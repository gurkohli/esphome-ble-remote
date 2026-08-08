#include "../ble_client_hid.h"
#include "bluetooth_e1.h"

#if defined(USE_ESP32) && defined(USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING)

#include "esphome/core/log.h"
#include <esp_random.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace esphome {
namespace ble_client_hid {

namespace {

static const char *const TAG = "ble_client_hid.transaction";

const char *step_name(ForensicStepKind kind) {
  switch (kind) {
    case ForensicStepKind::WRITE: return "write";
    case ForensicStepKind::EXCHANGE: return "exchange";
    case ForensicStepKind::WAIT_NOTIFICATION: return "wait_notification";
    case ForensicStepKind::REQUIRE_NOTIFICATION: return "require_notification";
    case ForensicStepKind::RANDOM_BYTES: return "random_bytes";
    case ForensicStepKind::TRANSFORM_BT_E1: return "transform_bt_e1";
    case ForensicStepKind::ASSERT_EQUAL: return "assert_equal";
    case ForensicStepKind::DELAY: return "delay";
  }
  return "unknown";
}

}  // namespace

size_t BLEClientHID::forensic_transaction_payload_limit_() const {
  const size_t mtu_payload = this->negotiated_mtu_available_ && this->negotiated_mtu_ > 3
                                 ? static_cast<size_t>(this->negotiated_mtu_ - 3)
                                 : 20;
  return std::min(mtu_payload, MAX_FORENSIC_TRANSACTION_WRITE_BYTES);
}

void BLEClientHID::fail_forensic_transaction_(const std::string &stage, const std::string &message,
                                              const char *status_domain, int status) {
  if (this->forensic_transaction_active_ != nullptr)
    this->forensic_transaction_result_variables_ = this->forensic_transaction_active_->recipe.variables;
  this->forensic_transaction_active_.reset();
  this->forensic_transaction_pending_.reset();
  this->forensic_transaction_status_.stage = stage;
  this->forensic_transaction_status_.message = message;
  this->forensic_transaction_status_.status_domain = status_domain;
  this->forensic_transaction_status_.status = status;
  this->forensic_transaction_status_.finished_ms = millis();
  this->forensic_transaction_status_.complete = true;
  this->forensic_transaction_status_.succeeded = false;
  this->forensic_transaction_status_.abortable = false;
  this->forensic_transaction_status_.write_blocked = this->forensic_gatt_write_active_ != nullptr;
  this->forensic_transaction_status_.reconnect_required = this->forensic_transaction_reconnect_required_;
  this->record_forensic_operation_locked_("transaction", stage.c_str(), 0, 0, status_domain, status, true, false);
  ESP_LOGW(TAG, "TRANSACTION sequence=%u stage=%s message=%s",
           static_cast<unsigned>(this->forensic_transaction_status_.sequence),
           stage.c_str(), message.c_str());
}

void BLEClientHID::complete_forensic_transaction_() {
  if (this->forensic_transaction_active_ != nullptr)
    this->forensic_transaction_result_variables_ = this->forensic_transaction_active_->recipe.variables;
  this->forensic_transaction_active_.reset();
  this->forensic_transaction_status_.stage = "succeeded";
  this->forensic_transaction_status_.message = "All transaction steps completed.";
  this->forensic_transaction_status_.status_domain = "local";
  this->forensic_transaction_status_.status = 0;
  this->forensic_transaction_status_.current_step = this->forensic_transaction_status_.total_steps;
  this->forensic_transaction_status_.finished_ms = millis();
  this->forensic_transaction_status_.complete = true;
  this->forensic_transaction_status_.succeeded = true;
  this->forensic_transaction_status_.abortable = false;
  this->forensic_transaction_status_.write_blocked = false;
  this->forensic_transaction_status_.reconnect_required = false;
  this->record_forensic_operation_locked_("transaction", "succeeded", 0, 0, "local", 0, true, true);
  ESP_LOGI(TAG, "TRANSACTION sequence=%u stage=succeeded steps=%u",
           static_cast<unsigned>(this->forensic_transaction_status_.sequence),
           static_cast<unsigned>(this->forensic_transaction_status_.total_steps));
}

void BLEClientHID::advance_forensic_transaction_() {
  if (this->forensic_transaction_active_ == nullptr) return;
  auto &runtime = *this->forensic_transaction_active_;
  if (runtime.step_index < runtime.recipe.steps.size()) {
    const auto &step = runtime.recipe.steps[runtime.step_index];
    uint16_t handle = 0;
    const auto target = runtime.recipe.targets.find(step.target);
    if (target != runtime.recipe.targets.end()) handle = target->second.attribute_handle;
    this->record_forensic_operation_locked_("transaction_step", step_name(step.kind), handle, 0, "local", 0, true,
                                            true);
  }
  runtime.step_index++;
  runtime.step_started = false;
  runtime.step_started_ms = 0;
  runtime.write_complete = false;
  runtime.notification_received = false;
  runtime.notification_value.clear();
  this->forensic_transaction_status_.current_step = runtime.step_index + 1;
  if (runtime.step_index >= runtime.recipe.steps.size()) this->complete_forensic_transaction_();
}

bool BLEClientHID::abort_forensic_transaction_() {
  if (this->forensic_transaction_pending_ == nullptr && this->forensic_transaction_active_ == nullptr) return false;
  if (this->forensic_transaction_active_ != nullptr) {
    const auto &runtime = *this->forensic_transaction_active_;
    if (runtime.step_index < runtime.recipe.steps.size()) {
      const auto kind = runtime.recipe.steps[runtime.step_index].kind;
      if (runtime.step_started &&
          (kind == ForensicStepKind::EXCHANGE || kind == ForensicStepKind::WAIT_NOTIFICATION))
        this->forensic_transaction_reconnect_required_ = true;
    }
    this->forensic_transaction_result_variables_ = this->forensic_transaction_active_->recipe.variables;
  }
  this->forensic_transaction_pending_.reset();
  this->forensic_transaction_active_.reset();
  if (this->forensic_gatt_write_active_ != nullptr) this->forensic_gatt_write_active_->timed_out = true;
  this->forensic_transaction_status_.stage = "aborted";
  this->forensic_transaction_status_.message = this->forensic_gatt_write_active_ == nullptr
                                                   ? "Transaction aborted."
                                                   : "Transaction aborted; a GATT write callback is still pending.";
  this->forensic_transaction_status_.status_domain = "local";
  this->forensic_transaction_status_.status = -1;
  this->forensic_transaction_status_.finished_ms = millis();
  this->forensic_transaction_status_.complete = true;
  this->forensic_transaction_status_.succeeded = false;
  this->forensic_transaction_status_.abortable = false;
  this->forensic_transaction_status_.write_blocked = this->forensic_gatt_write_active_ != nullptr;
  this->forensic_transaction_status_.reconnect_required = this->forensic_transaction_reconnect_required_;
  this->record_forensic_operation_locked_("transaction", "aborted", 0, 0, "local", -1, true, false);
  return true;
}

void BLEClientHID::process_forensic_transaction_() {
  LockGuard forensic_guard(this->forensic_export_mutex_);
  const uint32_t now = millis();

  if (this->forensic_transaction_active_ == nullptr && this->forensic_transaction_pending_ != nullptr) {
    if (this->forensic_gatt_write_active_ != nullptr) return;
    if (!this->forensic_snapshot_available_ ||
        this->forensic_transaction_pending_->profile_hash != this->gatt_profile_hash_) {
      this->forensic_transaction_status_.available = true;
      this->forensic_transaction_status_.sequence = this->forensic_transaction_pending_->sequence;
      this->fail_forensic_transaction_("profile_changed",
                                       "The connected GATT profile no longer matches the validated recipe.");
      return;
    }
    auto runtime = std::make_unique<ForensicTransactionRuntime>();
    runtime->recipe = std::move(*this->forensic_transaction_pending_);
    this->forensic_transaction_pending_.reset();
    runtime->started_ms = now;
    this->forensic_transaction_status_.available = true;
    this->forensic_transaction_status_.sequence = runtime->recipe.sequence;
    this->forensic_transaction_status_.name = runtime->recipe.name;
    this->forensic_transaction_status_.stage = "running";
    this->forensic_transaction_status_.message = "Transaction started.";
    this->forensic_transaction_status_.status_domain = "local";
    this->forensic_transaction_status_.status = 0;
    this->forensic_transaction_status_.current_step = 1;
    this->forensic_transaction_status_.total_steps = runtime->recipe.steps.size();
    this->forensic_transaction_status_.started_ms = now;
    this->forensic_transaction_status_.finished_ms = 0;
    this->forensic_transaction_status_.complete = false;
    this->forensic_transaction_status_.succeeded = false;
    this->forensic_transaction_status_.abortable = true;
    this->forensic_transaction_status_.write_blocked = false;
    this->forensic_transaction_result_variables_.clear();
    this->forensic_transaction_responses_.reset(now);
    this->forensic_transaction_active_ = std::move(runtime);
    this->record_forensic_operation_locked_("transaction", "started", 0, 0, "local", 0, false, false);
  }

  for (size_t immediate_steps = 0; immediate_steps < FORENSIC_TRANSACTION_MAX_STEPS; immediate_steps++) {
    if (this->forensic_transaction_active_ == nullptr) return;
    auto &runtime = *this->forensic_transaction_active_;
    if (static_cast<uint32_t>(now - runtime.started_ms) >= FORENSIC_TRANSACTION_MAX_RUNTIME_MS) {
      if (runtime.step_index < runtime.recipe.steps.size()) {
        const auto kind = runtime.recipe.steps[runtime.step_index].kind;
        if (kind == ForensicStepKind::EXCHANGE || kind == ForensicStepKind::WAIT_NOTIFICATION)
          this->forensic_transaction_reconnect_required_ = true;
      }
      if (this->forensic_gatt_write_active_ != nullptr) this->forensic_gatt_write_active_->timed_out = true;
      this->fail_forensic_transaction_("runtime_timeout", "Transaction exceeded its maximum total runtime.");
      return;
    }
    if (runtime.step_index >= runtime.recipe.steps.size()) {
      this->complete_forensic_transaction_();
      return;
    }
    const auto &step = runtime.recipe.steps[runtime.step_index];
    this->forensic_transaction_status_.current_step = runtime.step_index + 1;
    if (runtime.step_started && step.timeout_ms != 0 &&
        static_cast<uint32_t>(now - runtime.step_started_ms) >= step.timeout_ms) {
      if (step.kind == ForensicStepKind::EXCHANGE || step.kind == ForensicStepKind::WAIT_NOTIFICATION)
        this->forensic_transaction_reconnect_required_ = true;
      if (this->forensic_gatt_write_active_ != nullptr) this->forensic_gatt_write_active_->timed_out = true;
      this->fail_forensic_transaction_("step_timeout", "The active transaction step timed out.");
      return;
    }

    if (step.kind == ForensicStepKind::DELAY) {
      if (!runtime.step_started) {
        runtime.step_started = true;
        runtime.step_started_ms = now;
        this->forensic_transaction_status_.stage = "delaying";
        this->forensic_transaction_status_.message = "Waiting for the configured delay.";
      }
      if (static_cast<uint32_t>(now - runtime.step_started_ms) < step.delay_ms) return;
      this->advance_forensic_transaction_();
      continue;
    }

    if (step.kind == ForensicStepKind::REQUIRE_NOTIFICATION) {
      const auto target = runtime.recipe.targets.find(step.target);
      if (target == runtime.recipe.targets.end() || !target->second.notification_enabled) {
        this->fail_forensic_transaction_("subscription_unavailable",
                                         "The required notification target is not subscribed.");
        return;
      }
      this->advance_forensic_transaction_();
      continue;
    }

    if (step.kind == ForensicStepKind::RANDOM_BYTES) {
      ForensicTransactionVariable output;
      output.value.resize(step.output_length);
      esp_fill_random(output.value.data(), output.value.size());
      output.secret = step.output_secret;
      runtime.recipe.variables[step.output_variable] = std::move(output);
      this->advance_forensic_transaction_();
      continue;
    }

    if (step.kind == ForensicStepKind::TRANSFORM_BT_E1) {
      const auto key = runtime.recipe.variables.find(step.key_variable);
      const auto random = runtime.recipe.variables.find(step.random_variable);
      const auto address = runtime.recipe.variables.find(step.address_variable);
      if (key == runtime.recipe.variables.end() || random == runtime.recipe.variables.end() ||
          address == runtime.recipe.variables.end() || key->second.value.size() != 16 ||
          random->second.value.size() != 16 || address->second.value.size() != 6) {
        this->fail_forensic_transaction_("transform_input_invalid", "Bluetooth E1 inputs have invalid lengths.");
        return;
      }
      std::array<uint8_t, 16> key_bytes{};
      std::array<uint8_t, 16> random_bytes{};
      std::array<uint8_t, 6> address_bytes{};
      std::copy(key->second.value.begin(), key->second.value.end(), key_bytes.begin());
      std::copy(random->second.value.begin(), random->second.value.end(), random_bytes.begin());
      std::copy(address->second.value.begin(), address->second.value.end(), address_bytes.begin());
      ForensicTransactionVariable output;
      const auto transformed = bluetooth_e1(key_bytes, random_bytes, address_bytes);
      output.value.assign(transformed.begin(), transformed.end());
      output.secret = key->second.secret || random->second.secret || address->second.secret;
      runtime.recipe.variables[step.output_variable] = std::move(output);
      this->advance_forensic_transaction_();
      continue;
    }

    if (step.kind == ForensicStepKind::ASSERT_EQUAL) {
      const auto left = runtime.recipe.variables.find(step.left_variable);
      const auto right = runtime.recipe.variables.find(step.right_variable);
      if (left == runtime.recipe.variables.end() || right == runtime.recipe.variables.end()) {
        this->fail_forensic_transaction_("assert_input_missing", "An assertion variable is unavailable.");
        return;
      }
      size_t difference = left->second.value.size() ^ right->second.value.size();
      const size_t compared = std::min(left->second.value.size(), right->second.value.size());
      for (size_t index = 0; index < compared; index++) difference |= left->second.value[index] ^ right->second.value[index];
      if (difference != 0) {
        this->fail_forensic_transaction_("assertion_failed", "Transaction byte assertion failed.");
        return;
      }
      this->advance_forensic_transaction_();
      continue;
    }

    if (step.kind == ForensicStepKind::WAIT_NOTIFICATION) {
      if (!runtime.step_started) {
        runtime.step_started = true;
        runtime.step_started_ms = now;
        this->forensic_transaction_status_.stage = "waiting_for_notification";
        this->forensic_transaction_status_.message = "Waiting for a matching notification.";
      }
      if (!runtime.notification_received) return;
      std::string error;
      if (!apply_forensic_captures(step.matcher, runtime.notification_value.data(), runtime.notification_value.size(),
                                   runtime.recipe.variables, error)) {
        this->fail_forensic_transaction_("capture_failed", error);
        return;
      }
      this->advance_forensic_transaction_();
      continue;
    }

    if (step.kind != ForensicStepKind::WRITE && step.kind != ForensicStepKind::EXCHANGE) {
      this->fail_forensic_transaction_("invalid_step", "Unsupported compiled transaction step.");
      return;
    }
    const auto target = runtime.recipe.targets.find(step.target);
    if (target == runtime.recipe.targets.end()) {
      this->fail_forensic_transaction_("target_missing", "A compiled write target is unavailable.");
      return;
    }
    if (!runtime.step_started) {
      std::vector<uint8_t> payload;
      std::string error;
      if (!compose_forensic_value(step.value, runtime.recipe.variables, this->forensic_transaction_payload_limit_(),
                                  payload, error)) {
        this->fail_forensic_transaction_("compose_failed", error);
        return;
      }
      runtime.step_started = true;
      runtime.step_started_ms = now;
      runtime.write_complete = false;
      runtime.notification_received = false;
      const auto &write_target = target->second;
      const bool with_response = write_target.write_mode == ForensicWriteMode::WITH_RESPONSE;
      bool payload_secret = false;
      for (const auto &part : step.value)
        if (part.kind == ForensicValuePartKind::VARIABLE) {
          const auto variable = runtime.recipe.variables.find(part.variable);
          if (variable != runtime.recipe.variables.end() && variable->second.secret) payload_secret = true;
        }
      if (with_response) {
        auto active_write = std::make_unique<ForensicGattWrite>();
        active_write->sequence = runtime.recipe.sequence;
        active_write->step_index = runtime.step_index;
        active_write->started_ms = now;
        active_write->descriptor = write_target.kind == ForensicTargetKind::DESCRIPTOR;
        active_write->characteristic_handle = write_target.characteristic_handle;
        active_write->attribute_handle = write_target.attribute_handle;
        active_write->with_response = true;
        active_write->value_secret = payload_secret;
        active_write->value = payload;
        this->forensic_gatt_write_active_ = std::move(active_write);
      }
      esp_err_t result;
      if (write_target.kind == ForensicTargetKind::DESCRIPTOR) {
        result = esp_ble_gattc_write_char_descr(
            this->parent()->get_gattc_if(), this->parent()->get_conn_id(), write_target.attribute_handle,
            static_cast<uint16_t>(payload.size()), payload.data(), ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
      } else {
        const esp_gatt_write_type_t write_type = with_response ? ESP_GATT_WRITE_TYPE_RSP : ESP_GATT_WRITE_TYPE_NO_RSP;
        result = esp_ble_gattc_write_char(
            this->parent()->get_gattc_if(), this->parent()->get_conn_id(), write_target.attribute_handle,
            static_cast<uint16_t>(payload.size()), payload.data(), write_type, ESP_GATT_AUTH_REQ_NONE);
      }
      this->record_forensic_operation_locked_(
          write_target.kind == ForensicTargetKind::DESCRIPTOR ? "transaction_descriptor_write"
                                                               : "transaction_characteristic_write",
          result == ESP_OK ? "scheduled" : "schedule_failed", write_target.attribute_handle,
          write_target.kind == ForensicTargetKind::DESCRIPTOR ? write_target.characteristic_handle : 0, "esp_err",
          result, result != ESP_OK || !with_response, result == ESP_OK && !with_response, payload.data(),
          payload.size(), payload_secret);
      if (result != ESP_OK) {
        this->forensic_gatt_write_active_.reset();
        this->fail_forensic_transaction_("write_schedule_failed", "ESP-IDF rejected the GATT write.", "esp_err",
                                         result);
        return;
      }
      if (!with_response) runtime.write_complete = true;
      this->forensic_transaction_status_.stage = step.kind == ForensicStepKind::EXCHANGE
                                                     ? "waiting_for_exchange"
                                                     : (with_response ? "waiting_for_write_response" : "running");
      this->forensic_transaction_status_.message = step.kind == ForensicStepKind::EXCHANGE
                                                       ? "Write scheduled; waiting for its matching notification."
                                                       : "GATT write scheduled.";
    }
    if (!runtime.write_complete) return;
    if (step.kind == ForensicStepKind::EXCHANGE) {
      if (!runtime.notification_received) return;
      std::string error;
      if (!apply_forensic_captures(step.matcher, runtime.notification_value.data(), runtime.notification_value.size(),
                                   runtime.recipe.variables, error)) {
        this->fail_forensic_transaction_("capture_failed", error);
        return;
      }
    }
    this->advance_forensic_transaction_();
  }
}

bool BLEClientHID::finish_forensic_transaction_write_(bool descriptor, uint16_t handle, esp_gatt_status_t status) {
  LockGuard forensic_guard(this->forensic_export_mutex_);
  if (this->forensic_gatt_write_active_ == nullptr || this->forensic_gatt_write_active_->descriptor != descriptor ||
      this->forensic_gatt_write_active_->attribute_handle != handle)
    return false;
  auto completed = std::move(this->forensic_gatt_write_active_);
  this->record_forensic_operation_locked_(descriptor ? "transaction_descriptor_write"
                                                      : "transaction_characteristic_write",
                                          completed->timed_out ? "late_callback" : "callback", handle,
                                          descriptor ? completed->characteristic_handle : 0, "gatt", status, true,
                                          status == ESP_GATT_OK, completed->value.data(), completed->value.size(),
                                          completed->value_secret);
  this->forensic_transaction_status_.write_blocked = false;
  if (this->forensic_transaction_active_ == nullptr || completed->timed_out ||
      this->forensic_transaction_active_->recipe.sequence != completed->sequence ||
      this->forensic_transaction_active_->step_index != completed->step_index)
    return true;
  if (status != ESP_GATT_OK) {
    this->fail_forensic_transaction_("write_response_failed", "The peripheral rejected the GATT write.", "gatt",
                                     status);
    return true;
  }
  this->forensic_transaction_active_->write_complete = true;
  return true;
}

void BLEClientHID::process_forensic_transaction_notification_(uint16_t handle, bool is_notify, const uint8_t *value,
                                                              size_t length) {
  LockGuard forensic_guard(this->forensic_export_mutex_);
  if (this->forensic_transaction_active_ == nullptr) return;
  auto &runtime = *this->forensic_transaction_active_;
  if (runtime.step_index >= runtime.recipe.steps.size()) return;

  bool response_handle = false;
  for (const auto &candidate : runtime.recipe.steps) {
    if ((candidate.kind == ForensicStepKind::WAIT_NOTIFICATION || candidate.kind == ForensicStepKind::EXCHANGE) &&
        candidate.matcher.handle == handle) {
      response_handle = true;
      break;
    }
  }

  const auto &step = runtime.recipe.steps[runtime.step_index];
  const bool matched = !runtime.notification_received && runtime.step_started &&
                       (step.kind == ForensicStepKind::WAIT_NOTIFICATION || step.kind == ForensicStepKind::EXCHANGE) &&
                       forensic_notification_matches(step.matcher, handle, is_notify, value, length);
  if (response_handle &&
      !this->forensic_transaction_responses_.append(millis(), runtime.step_index + 1, handle, is_notify, matched,
                                                    value, length)) {
    this->fail_forensic_transaction_("response_capture_incomplete",
                                     "A complete transaction response could not be retained in memory.");
    return;
  }
  if (!matched) return;
  runtime.notification_received = true;
  if (value != nullptr && length != 0) runtime.notification_value.assign(value, value + length);
  this->record_forensic_operation_locked_("transaction_match", is_notify ? "notification" : "indication", handle,
                                          0, "gatt", ESP_GATT_OK, true, true, value, length);
}

}  // namespace ble_client_hid
}  // namespace esphome

#endif
