#include "ble_client_hid.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>
#include <utility>

#include "esphome/core/helpers.h"
#include "mbedtls/sha256.h"
#include "usages.h"

#ifdef USE_ESP32

namespace esphome {
namespace ble_client_hid {

static const char *const TAG = "ble_client_hid";

namespace {

constexpr uint16_t UUID_GAP_SERVICE = 0x1800;
constexpr uint16_t UUID_GATT_SERVICE = 0x1801;
constexpr uint16_t UUID_HID_SERVICE = 0x1812;
constexpr uint16_t UUID_BATTERY_SERVICE = 0x180F;
constexpr uint16_t UUID_DEVICE_INFORMATION_SERVICE = 0x180A;

constexpr uint16_t UUID_DEVICE_NAME = 0x2A00;
constexpr uint16_t UUID_APPEARANCE = 0x2A01;
constexpr uint16_t UUID_PREFERRED_CONNECTION_PARAMETERS = 0x2A04;
constexpr uint16_t UUID_SERVICE_CHANGED = 0x2A05;
constexpr uint16_t UUID_SYSTEM_ID = 0x2A23;
constexpr uint16_t UUID_MODEL_NUMBER = 0x2A24;
constexpr uint16_t UUID_SERIAL_NUMBER = 0x2A25;
constexpr uint16_t UUID_FIRMWARE_REVISION = 0x2A26;
constexpr uint16_t UUID_HARDWARE_REVISION = 0x2A27;
constexpr uint16_t UUID_SOFTWARE_REVISION = 0x2A28;
constexpr uint16_t UUID_MANUFACTURER_NAME = 0x2A29;
constexpr uint16_t UUID_IEEE_CERTIFICATION = 0x2A2A;
constexpr uint16_t UUID_BATTERY_LEVEL = 0x2A19;
constexpr uint16_t UUID_PNP_ID = 0x2A50;
constexpr uint16_t UUID_HID_INFORMATION = 0x2A4A;
constexpr uint16_t UUID_HID_REPORT_MAP = 0x2A4B;
constexpr uint16_t UUID_HID_REPORT = 0x2A4D;
constexpr uint16_t UUID_HID_PROTOCOL_MODE = 0x2A4E;
constexpr uint16_t UUID_BOOT_KEYBOARD_INPUT = 0x2A22;
constexpr uint16_t UUID_BOOT_KEYBOARD_OUTPUT = 0x2A32;
constexpr uint16_t UUID_BOOT_MOUSE_INPUT = 0x2A33;
constexpr uint16_t UUID_DATABASE_HASH = 0x2B2A;
constexpr uint16_t UUID_CLIENT_SUPPORTED_FEATURES = 0x2B29;
constexpr uint16_t UUID_SERVER_SUPPORTED_FEATURES = 0x2B3A;

constexpr uint16_t UUID_CHARACTERISTIC_USER_DESCRIPTION = 0x2901;
constexpr uint16_t UUID_CCCD = 0x2902;
constexpr uint16_t UUID_CHARACTERISTIC_PRESENTATION_FORMAT = 0x2904;
constexpr uint16_t UUID_CHARACTERISTIC_AGGREGATE_FORMAT = 0x2905;
constexpr uint16_t UUID_EXTERNAL_REPORT_REFERENCE = 0x2907;
constexpr uint16_t UUID_REPORT_REFERENCE = 0x2908;

bool elapsed(uint32_t now, uint32_t start, uint32_t interval) {
  return static_cast<uint32_t>(now - start) >= interval;
}

const char *phase_name(SetupPhase phase) {
  switch (phase) {
    case SetupPhase::DISCONNECTED: return "disconnected";
    case SetupPhase::WAITING_FOR_DISCOVERY: return "waiting_for_discovery";
    case SetupPhase::INVENTORY: return "inventory";
    case SetupPhase::READING: return "reading";
    case SetupPhase::BUILDING_PROFILE: return "building_profile";
    case SetupPhase::WRITING_PROTOCOL_MODE: return "writing_protocol_mode";
    case SetupPhase::REGISTERING: return "registering";
    case SetupPhase::WAITING_FOR_CCCD: return "waiting_for_cccd";
    case SetupPhase::READY: return "ready";
    case SetupPhase::DEGRADED: return "degraded";
    case SetupPhase::NO_HID: return "no_hid";
  }
  return "unknown";
}

bool is_dis_characteristic(uint16_t uuid) {
  switch (uuid) {
    case UUID_SYSTEM_ID:
    case UUID_MODEL_NUMBER:
    case UUID_SERIAL_NUMBER:
    case UUID_FIRMWARE_REVISION:
    case UUID_HARDWARE_REVISION:
    case UUID_SOFTWARE_REVISION:
    case UUID_MANUFACTURER_NAME:
    case UUID_IEEE_CERTIFICATION:
    case UUID_PNP_ID:
      return true;
    default:
      return false;
  }
}

[[maybe_unused]] const char *ad_type_name(uint8_t type) {
  switch (type) {
    case 0x01: return "flags";
    case 0x02: return "incomplete_uuid16_list";
    case 0x03: return "complete_uuid16_list";
    case 0x04: return "incomplete_uuid32_list";
    case 0x05: return "complete_uuid32_list";
    case 0x06: return "incomplete_uuid128_list";
    case 0x07: return "complete_uuid128_list";
    case 0x08: return "short_name";
    case 0x09: return "complete_name";
    case 0x0A: return "tx_power";
    case 0x16: return "service_data_uuid16";
    case 0x19: return "appearance";
    case 0x20: return "service_data_uuid32";
    case 0x21: return "service_data_uuid128";
    case 0xFF: return "manufacturer_data";
    default: return "unknown";
  }
}

std::string printable_text(const uint8_t *data, size_t length) {
  std::string result;
  result.reserve(length);
  for (size_t i = 0; i < length; i++)
    result.push_back(std::isprint(data[i]) != 0 ? static_cast<char>(data[i]) : '.');
  return result;
}

std::string digest_string(const std::array<unsigned char, 32> &digest) {
  static constexpr char HEX[] = "0123456789abcdef";
  std::string result(64, '0');
  for (size_t i = 0; i < digest.size(); i++) {
    result[i * 2] = HEX[digest[i] >> 4U];
    result[i * 2 + 1] = HEX[digest[i] & 0x0FU];
  }
  return result;
}

class SHA256Accumulator {
 public:
  SHA256Accumulator() {
    mbedtls_sha256_init(&this->context_);
    this->valid_ = mbedtls_sha256_starts(&this->context_, 0) == 0;
  }
  ~SHA256Accumulator() { mbedtls_sha256_free(&this->context_); }

  void update(const std::string &value) {
    if (this->valid_ && mbedtls_sha256_update(&this->context_,
          reinterpret_cast<const unsigned char *>(value.data()), value.size()) != 0)
      this->valid_ = false;
  }

  std::string finish() {
    std::array<unsigned char, 32> digest{};
    if (!this->valid_ || mbedtls_sha256_finish(&this->context_, digest.data()) != 0)
      return "unavailable";
    return digest_string(digest);
  }

 private:
  mbedtls_sha256_context context_{};
  bool valid_{false};
};

}  // namespace

void BLEClientHID::transition_(SetupPhase phase) {
  if (this->setup_phase_ != phase) {
    ESP_LOGV(TAG, "HID_SETUP from=%s to=%s", phase_name(this->setup_phase_), phase_name(phase));
  }
  this->setup_phase_ = phase;
  this->phase_started_ms_ = millis();
}

void BLEClientHID::mark_degraded_(const std::string &reason) {
  this->degraded_ = true;
  this->operations_failed_++;
  this->status_set_warning(reason.c_str());
  ESP_LOGW(TAG, "HID_SETUP_WARNING phase=%s reason=%s", phase_name(this->setup_phase_), reason.c_str());
}

void BLEClientHID::reset_connection_state_() {
  this->services_.clear();
  this->hid_services_.clear();
  this->read_queue_.clear();
  this->active_read_.reset();
  this->subscription_queue_.clear();
  this->active_subscription_.reset();
  this->subscription_state_.reset();
  this->handle_report_source_.clear();
  this->hid_report_handles_.clear();
  this->battery_handles_.clear();
  this->service_changed_handles_.clear();
  this->planned_read_handles_.clear();
  this->pending_reports_.clear();
  this->pending_report_bytes_ = 0;
  this->boot_decoder_.reset();
  this->sampled_events_.clear();
  this->sampling_window_active_ = false;
  this->preferred_conn_params_valid_ = false;
  this->preferred_conn_params_ = {};
  this->protocol_write_handles_.clear();
  this->congested_ = false;
  this->rediscovery_requested_ = false;
  this->operations_succeeded_ = 0;
  this->operations_failed_ = 0;
  this->degraded_ = false;
  this->gatt_profile_hash_.clear();
}

void BLEClientHID::loop() {
  this->process_pending_advertisement_();

  if (this->rediscovery_requested_) {
    this->rediscovery_requested_ = false;
    ESP_LOGW(TAG, "HID_PROFILE_INVALIDATED action=reconnect");
    this->parent()->disconnect();
  }

  switch (this->setup_phase_) {
    case SetupPhase::INVENTORY:
      if (!this->inventory_gatt_database_()) {
        this->mark_degraded_("GATT inventory failed");
        this->finalize_setup_();
      } else if (this->hid_services_.empty()) {
        ESP_LOGW(TAG, "HID_READY status=NO_HID services=%u", static_cast<unsigned>(this->services_.size()));
        this->status_set_warning("No HID service");
        this->transition_(SetupPhase::NO_HID);
        this->node_state = espbt::ClientState::ESTABLISHED;
      } else {
        this->plan_reads_();
        this->transition_(SetupPhase::READING);
      }
      break;
    case SetupPhase::READING:
      this->start_next_read_();
      break;
    case SetupPhase::BUILDING_PROFILE:
      this->build_hid_profiles_();
      this->start_protocol_mode_write_();
      break;
    case SetupPhase::WRITING_PROTOCOL_MODE:
      this->start_protocol_mode_write_();
      break;
    case SetupPhase::REGISTERING:
      this->start_next_subscription_();
      break;
    case SetupPhase::WAITING_FOR_CCCD:
      if (this->active_subscription_ != nullptr && this->subscription_state_.fallback_due(millis()))
        this->write_current_cccd_();
      break;
    default:
      break;
  }

  this->handle_phase_timeout_();
  this->update_sampling_window_();
  const uint32_t processing_started = micros();
  size_t processed = 0;
  while (!this->pending_reports_.empty() && processed < MAX_REPORTS_PER_LOOP &&
         static_cast<uint32_t>(micros() - processing_started) < MAX_PROCESSING_TIME_US) {
    PendingHIDReport report = std::move(this->pending_reports_.front());
    this->pending_reports_.pop_front();
    this->pending_report_bytes_ -= report.payload.size();
    const std::string raw = format_value_(report.payload.data(), report.payload.size());
    this->process_input_report_(std::move(report), raw);
    processed++;
  }
  this->update_sampling_window_();
}

void BLEClientHID::handle_phase_timeout_() {
  if (this->setup_phase_ == SetupPhase::DISCONNECTED || this->setup_phase_ == SetupPhase::WAITING_FOR_DISCOVERY ||
      this->setup_phase_ == SetupPhase::READY || this->setup_phase_ == SetupPhase::DEGRADED ||
      this->setup_phase_ == SetupPhase::NO_HID || !elapsed(millis(), this->phase_started_ms_, PHASE_TIMEOUT_MS))
    return;
  const std::string reason = std::string("timeout in ") + phase_name(this->setup_phase_);
  this->mark_degraded_(reason);
  if (this->setup_phase_ == SetupPhase::READING) {
    this->active_read_.reset();
    this->read_queue_.clear();
    this->transition_(SetupPhase::BUILDING_PROFILE);
  } else if (this->setup_phase_ == SetupPhase::REGISTERING || this->setup_phase_ == SetupPhase::WAITING_FOR_CCCD) {
    this->active_subscription_.reset();
    this->subscription_state_.reset();
    this->subscription_queue_.clear();
    this->finalize_setup_();
  } else {
    this->finalize_setup_();
  }
}

void BLEClientHID::dump_config() {
  ESP_LOGCONFIG(TAG, "BLE Client HID:");
  ESP_LOGCONFIG(TAG, "  MAC address: %s", this->parent()->address_str());
  ESP_LOGCONFIG(TAG, "  Discovery mode: %s", this->discovery_mode_ == DiscoveryMode::FORENSIC ? "forensic" : "standard");
  const char *protocol = this->protocol_mode_policy_ == ProtocolModePolicy::REPORT ? "report" :
                         this->protocol_mode_policy_ == ProtocolModePolicy::BOOT ? "boot" : "unchanged";
  ESP_LOGCONFIG(TAG, "  Protocol mode: %s", protocol);
  if (this->event_sampling_interval_us_ == 0)
    ESP_LOGCONFIG(TAG, "  Event coalescing: disabled");
  else
    ESP_LOGCONFIG(TAG, "  Event coalescing: %u us", static_cast<unsigned>(this->event_sampling_interval_us_));
  ESP_LOGCONFIG(TAG, "  HID Usage Tables: %s", HID_USAGE_TABLE_VERSION);
}

bool BLEClientHID::uuid16_(const espbt::ESPBTUUID &uuid, uint16_t expected) {
  const esp_bt_uuid_t raw = uuid.get_uuid();
  return raw.len == ESP_UUID_LEN_16 && raw.uuid.uuid16 == expected;
}

std::string BLEClientHID::uuid_string_(const espbt::ESPBTUUID &uuid) {
  char buffer[espbt::UUID_STR_LEN];
  return uuid.as_128bit().to_str(buffer);
}

std::string BLEClientHID::format_value_(const uint8_t *data, size_t length) {
  if (data == nullptr && length != 0) return "<null>";
  if (length == 0) return "<empty>";
  return format_hex_pretty(data, length);
}

std::string BLEClientHID::sha256_(const uint8_t *data, size_t length) {
  std::array<unsigned char, 32> digest{};
  if (mbedtls_sha256(data, length, digest.data(), 0) != 0)
    return "unavailable";
  return digest_string(digest);
}

const GattCharacteristicInfo *BLEClientHID::find_characteristic_(uint16_t handle) const {
  for (const auto &service : this->services_)
    for (const auto &characteristic : service.characteristics)
      if (characteristic.handle == handle) return &characteristic;
  return nullptr;
}

const GattDescriptorInfo *BLEClientHID::find_descriptor_(const GattCharacteristicInfo &characteristic,
                                                         uint16_t uuid) const {
  for (const auto &descriptor : characteristic.descriptors)
    if (uuid16_(descriptor.uuid, uuid)) return &descriptor;
  return nullptr;
}

HIDServiceContext *BLEClientHID::find_hid_context_(uint16_t service_instance) {
  for (auto &context : this->hid_services_)
    if (context.service_instance == service_instance) return &context;
  return nullptr;
}

const HIDServiceContext *BLEClientHID::find_hid_context_(uint16_t service_instance) const {
  for (const auto &context : this->hid_services_)
    if (context.service_instance == service_instance) return &context;
  return nullptr;
}

bool BLEClientHID::inventory_gatt_database_() {
  this->services_.clear();
  this->hid_services_.clear();
  size_t characteristic_total = 0;
  size_t descriptor_total = 0;
  size_t included_service_total = 0;
  SHA256Accumulator normalized;

  for (uint16_t service_offset = 0; service_offset < MAX_SERVICES; service_offset++) {
    esp_gattc_service_elem_t result{};
    uint16_t count = 1;
    const esp_gatt_status_t status = esp_ble_gattc_get_service(
        this->parent()->get_gattc_if(), this->parent()->get_conn_id(), nullptr, &result, &count, service_offset);
    if (status == ESP_GATT_INVALID_OFFSET || status == ESP_GATT_NOT_FOUND) break;
    if (status != ESP_GATT_OK || count == 0) {
      ESP_LOGW(TAG, "GATT_INVENTORY_ERROR object=service offset=%u status=%d", service_offset, status);
      return false;
    }
    GattServiceInfo service;
    service.uuid = espbt::ESPBTUUID::from_uuid(result.uuid);
    service.instance = service_offset;
    service.start_handle = result.start_handle;
    service.end_handle = result.end_handle;
    service.primary = result.is_primary;
    normalized.update("S:" + uuid_string_(service.uuid) + (service.primary ? ":P;" : ":S;"));
    ESP_LOGV(TAG, "GATT_SERVICE instance=%u uuid=%s primary=%s start=%u end=%u", service.instance,
             uuid_string_(service.uuid).c_str(), service.primary ? "true" : "false", service.start_handle,
             service.end_handle);

    uint16_t include_count = 0;
    if (esp_ble_gattc_get_attr_count(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                     ESP_GATT_DB_INCLUDED_SERVICE, service.start_handle, service.end_handle, 0,
                                     &include_count) == ESP_GATT_OK && include_count != 0) {
      const size_t remaining = MAX_INCLUDED_SERVICES - included_service_total;
      if (include_count > remaining) {
        this->mark_degraded_("included service inventory limit exceeded");
        include_count = static_cast<uint16_t>(remaining);
      }
      std::vector<esp_gattc_incl_svc_elem_t> includes(include_count);
      uint16_t requested = include_count;
      esp_gatt_status_t include_status = requested == 0 ? ESP_GATT_OK : esp_ble_gattc_get_include_service(
          this->parent()->get_gattc_if(), this->parent()->get_conn_id(), service.start_handle, service.end_handle,
          nullptr, includes.data(), &requested);
      if (include_status == ESP_GATT_OK) {
        for (uint16_t i = 0; i < requested; i++) {
          GattIncludedServiceInfo include;
          include.uuid = espbt::ESPBTUUID::from_uuid(includes[i].uuid);
          include.declaration_handle = includes[i].handle;
          include.start_handle = includes[i].incl_srvc_s_handle;
          include.end_handle = includes[i].incl_srvc_e_handle;
          normalized.update("I:" + uuid_string_(include.uuid) + ";");
          ESP_LOGV(TAG, "GATT_INCLUDE service_instance=%u uuid=%s handle=%u start=%u end=%u", service.instance,
                   uuid_string_(include.uuid).c_str(), include.declaration_handle, include.start_handle,
                   include.end_handle);
          service.included_services.push_back(std::move(include));
          included_service_total++;
        }
      } else {
        this->mark_degraded_("included service inventory failed");
      }
    }

    for (uint16_t char_offset = 0; characteristic_total < MAX_CHARACTERISTICS; char_offset++) {
      esp_gattc_char_elem_t char_result{};
      uint16_t char_count = 1;
      const esp_gatt_status_t char_status = esp_ble_gattc_get_all_char(
          this->parent()->get_gattc_if(), this->parent()->get_conn_id(), service.start_handle, service.end_handle,
          &char_result, &char_count, char_offset);
      if (char_status == ESP_GATT_INVALID_OFFSET || char_status == ESP_GATT_NOT_FOUND) break;
      if (char_status != ESP_GATT_OK || char_count == 0) {
        this->mark_degraded_("characteristic inventory failed");
        break;
      }
      GattCharacteristicInfo characteristic;
      characteristic.uuid = espbt::ESPBTUUID::from_uuid(char_result.uuid);
      characteristic.handle = char_result.char_handle;
      characteristic.properties = char_result.properties;
      characteristic.service_instance = service.instance;
      normalized.update("C:" + uuid_string_(characteristic.uuid) + ":" +
                        std::to_string(characteristic.properties) + ";");
      ESP_LOGV(TAG, "GATT_CHARACTERISTIC service_instance=%u uuid=%s handle=%u properties=0x%02X",
               service.instance, uuid_string_(characteristic.uuid).c_str(), characteristic.handle,
               characteristic.properties);
      characteristic_total++;

      for (uint16_t descriptor_offset = 0; descriptor_total < MAX_DESCRIPTORS; descriptor_offset++) {
        esp_gattc_descr_elem_t descriptor_result{};
        uint16_t descriptor_count = 1;
        const esp_gatt_status_t descriptor_status = esp_ble_gattc_get_all_descr(
            this->parent()->get_gattc_if(), this->parent()->get_conn_id(), characteristic.handle,
            &descriptor_result, &descriptor_count, descriptor_offset);
        if (descriptor_status == ESP_GATT_INVALID_OFFSET || descriptor_status == ESP_GATT_NOT_FOUND) break;
        if (descriptor_status != ESP_GATT_OK || descriptor_count == 0) {
          this->mark_degraded_("descriptor inventory failed");
          break;
        }
        GattDescriptorInfo descriptor;
        descriptor.uuid = espbt::ESPBTUUID::from_uuid(descriptor_result.uuid);
        descriptor.handle = descriptor_result.handle;
        normalized.update("D:" + uuid_string_(descriptor.uuid) + ";");
        ESP_LOGV(TAG, "GATT_DESCRIPTOR service_instance=%u characteristic_handle=%u uuid=%s handle=%u",
                 service.instance, characteristic.handle, uuid_string_(descriptor.uuid).c_str(), descriptor.handle);
        characteristic.descriptors.push_back(std::move(descriptor));
        descriptor_total++;
      }
      if (descriptor_total >= MAX_DESCRIPTORS)
        this->mark_degraded_("descriptor inventory limit exceeded");
      service.characteristics.push_back(std::move(characteristic));
    }
    if (characteristic_total >= MAX_CHARACTERISTICS)
      this->mark_degraded_("characteristic inventory limit exceeded");

    if (uuid16_(service.uuid, UUID_HID_SERVICE)) {
      HIDServiceContext context;
      context.service_instance = service.instance;
      this->hid_services_.push_back(std::move(context));
    }
    this->services_.push_back(std::move(service));
  }
  if (this->services_.size() >= MAX_SERVICES)
    this->mark_degraded_("service inventory limit exceeded");
  this->gatt_profile_hash_ = normalized.finish();
  ESP_LOGD(TAG, "GATT_PROFILE services=%u included_services=%u characteristics=%u descriptors=%u sha256=%s",
           static_cast<unsigned>(this->services_.size()), static_cast<unsigned>(included_service_total),
           static_cast<unsigned>(characteristic_total), static_cast<unsigned>(descriptor_total),
           this->gatt_profile_hash_.c_str());
  return !this->services_.empty();
}

bool BLEClientHID::add_read_(const GattServiceInfo &service, const GattCharacteristicInfo &characteristic,
                             const GattDescriptorInfo *descriptor, ReadPurpose purpose, bool required) {
  const uint16_t handle = descriptor == nullptr ? characteristic.handle : descriptor->handle;
  if (this->planned_read_handles_.count(handle) != 0) return true;
  if (this->read_queue_.size() >= MAX_READ_OPERATIONS) {
    this->mark_degraded_("read operation limit exceeded");
    return false;
  }
  GattReadOperation operation;
  operation.handle = handle;
  operation.characteristic_handle = characteristic.handle;
  operation.service_instance = service.instance;
  operation.purpose = purpose;
  operation.descriptor = descriptor != nullptr;
  operation.required = required;
  operation.service_uuid = service.uuid;
  operation.characteristic_uuid = characteristic.uuid;
  operation.attribute_uuid = descriptor == nullptr ? characteristic.uuid : descriptor->uuid;
  this->read_queue_.push_back(std::move(operation));
  this->planned_read_handles_.insert(handle);
  return true;
}

void BLEClientHID::plan_reads_() {
  this->read_queue_.clear();
  this->planned_read_handles_.clear();
  for (const auto &service : this->services_) {
    for (const auto &characteristic : service.characteristics) {
      const esp_bt_uuid_t raw_uuid = characteristic.uuid.get_uuid();
      const uint16_t uuid = raw_uuid.len == ESP_UUID_LEN_16 ? raw_uuid.uuid.uuid16 : 0;
      ReadPurpose purpose = ReadPurpose::GENERIC_STANDARD;
      bool standard = false;
      bool required = false;
      if (uuid16_(service.uuid, UUID_GAP_SERVICE)) {
        if (uuid == UUID_DEVICE_NAME) purpose = ReadPurpose::DEVICE_NAME;
        else if (uuid == UUID_APPEARANCE) purpose = ReadPurpose::APPEARANCE;
        else if (uuid == UUID_PREFERRED_CONNECTION_PARAMETERS) purpose = ReadPurpose::PREFERRED_CONNECTION_PARAMETERS;
        standard = uuid == UUID_DEVICE_NAME || uuid == UUID_APPEARANCE || uuid == UUID_PREFERRED_CONNECTION_PARAMETERS;
      } else if (uuid16_(service.uuid, UUID_GATT_SERVICE)) {
        standard = uuid == UUID_SERVICE_CHANGED || uuid == UUID_DATABASE_HASH ||
                   uuid == UUID_CLIENT_SUPPORTED_FEATURES || uuid == UUID_SERVER_SUPPORTED_FEATURES;
      } else if (uuid16_(service.uuid, UUID_DEVICE_INFORMATION_SERVICE) && is_dis_characteristic(uuid)) {
        standard = true;
        if (uuid == UUID_PNP_ID) purpose = ReadPurpose::PNP_ID;
        else if (uuid == UUID_MANUFACTURER_NAME) purpose = ReadPurpose::MANUFACTURER;
        else if (uuid == UUID_SERIAL_NUMBER) purpose = ReadPurpose::SERIAL_NUMBER;
      } else if (uuid16_(service.uuid, UUID_BATTERY_SERVICE) && uuid == UUID_BATTERY_LEVEL) {
        standard = true;
        purpose = ReadPurpose::BATTERY_LEVEL;
      } else if (uuid16_(service.uuid, UUID_HID_SERVICE)) {
        standard = uuid == UUID_HID_INFORMATION || uuid == UUID_HID_REPORT_MAP || uuid == UUID_HID_PROTOCOL_MODE ||
                   uuid == UUID_HID_REPORT || uuid == UUID_BOOT_KEYBOARD_INPUT || uuid == UUID_BOOT_KEYBOARD_OUTPUT ||
                   uuid == UUID_BOOT_MOUSE_INPUT;
        if (uuid == UUID_HID_INFORMATION) purpose = ReadPurpose::HID_INFORMATION;
        else if (uuid == UUID_HID_REPORT_MAP) { purpose = ReadPurpose::HID_REPORT_MAP; required = true; }
        else if (uuid == UUID_HID_PROTOCOL_MODE) purpose = ReadPurpose::HID_PROTOCOL_MODE;
        else purpose = ReadPurpose::HID_REPORT_VALUE;
      }
      if ((characteristic.properties & ESP_GATT_CHAR_PROP_BIT_READ) != 0 &&
          (standard || this->discovery_mode_ == DiscoveryMode::FORENSIC))
        this->add_read_(service, characteristic, nullptr,
                        standard ? purpose : ReadPurpose::GENERIC_FORENSIC, required);

      for (const auto &descriptor : characteristic.descriptors) {
        ReadPurpose descriptor_purpose = ReadPurpose::GENERIC_STANDARD;
        bool standard_descriptor = false;
        if (uuid16_(descriptor.uuid, UUID_REPORT_REFERENCE)) {
          standard_descriptor = true;
          descriptor_purpose = ReadPurpose::HID_REPORT_REFERENCE;
        } else if (uuid16_(descriptor.uuid, UUID_EXTERNAL_REPORT_REFERENCE)) {
          standard_descriptor = true;
          descriptor_purpose = ReadPurpose::HID_EXTERNAL_REPORT_REFERENCE;
        } else if (uuid16_(descriptor.uuid, UUID_CHARACTERISTIC_USER_DESCRIPTION) ||
                   uuid16_(descriptor.uuid, UUID_CHARACTERISTIC_PRESENTATION_FORMAT) ||
                   uuid16_(descriptor.uuid, UUID_CHARACTERISTIC_AGGREGATE_FORMAT)) {
          standard_descriptor = true;
        }
        if (standard_descriptor || this->discovery_mode_ == DiscoveryMode::FORENSIC)
          this->add_read_(service, characteristic, &descriptor,
                          standard_descriptor ? descriptor_purpose : ReadPurpose::GENERIC_FORENSIC, false);
      }
    }
  }
  ESP_LOGD(TAG, "GATT_READ_PLAN operations=%u mode=%s", static_cast<unsigned>(this->read_queue_.size()),
           this->discovery_mode_ == DiscoveryMode::FORENSIC ? "forensic" : "standard");
}

void BLEClientHID::start_next_read_() {
  if (this->active_read_ != nullptr || this->congested_) return;
  if (this->read_queue_.empty()) {
    this->transition_(SetupPhase::BUILDING_PROFILE);
    return;
  }
  this->active_read_ = std::make_unique<GattReadOperation>(std::move(this->read_queue_.front()));
  this->read_queue_.pop_front();
  esp_err_t status = this->active_read_->descriptor
      ? esp_ble_gattc_read_char_descr(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                      this->active_read_->handle, ESP_GATT_AUTH_REQ_NO_MITM)
      : esp_ble_gattc_read_char(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                               this->active_read_->handle, ESP_GATT_AUTH_REQ_NO_MITM);
  if (status != ESP_OK) {
    const bool required = this->active_read_->required;
    ESP_LOGW(TAG, "GATT_READ handle=%u status=schedule_failed code=%d", this->active_read_->handle, status);
    this->active_read_.reset();
    if (required) this->mark_degraded_("required GATT read could not be scheduled");
    else this->operations_failed_++;
  }
}

void BLEClientHID::finish_active_read_(esp_gatt_status_t status, const uint8_t *value, size_t length) {
  if (this->active_read_ == nullptr) {
    ESP_LOGV(TAG, "GATT_READ status=unexpected_callback");
    return;
  }
  GattReadOperation operation = std::move(*this->active_read_);
  this->active_read_.reset();
  if (status != ESP_GATT_OK) {
    ESP_LOGW(TAG, "GATT_READ handle=%u uuid=%s status=failed code=%d", operation.handle,
             uuid_string_(operation.attribute_uuid).c_str(), status);
    if (operation.required) this->mark_degraded_("required GATT read failed");
    else this->operations_failed_++;
    return;
  }
  if (length > MAX_ATTRIBUTE_VALUE_BYTES) {
    ESP_LOGW(TAG, "GATT_READ handle=%u status=value_too_large length=%u limit=%u", operation.handle,
             static_cast<unsigned>(length), static_cast<unsigned>(MAX_ATTRIBUTE_VALUE_BYTES));
    if (operation.required) this->mark_degraded_("required GATT value exceeded limit");
    else this->operations_failed_++;
    return;
  }
  this->operations_succeeded_++;
  this->process_read_value_(operation, value, length);
}

void BLEClientHID::process_read_value_(const GattReadOperation &operation, const uint8_t *value, size_t length) {
  const std::string raw = format_value_(value, length);
  ESP_LOGV(TAG, "GATT_VALUE service_instance=%u characteristic_handle=%u handle=%u uuid=%s len=%u data=%s",
           operation.service_instance, operation.characteristic_handle, operation.handle,
           uuid_string_(operation.attribute_uuid).c_str(), static_cast<unsigned>(length), raw.c_str());
  if (value == nullptr && length != 0) {
    if (operation.required) this->mark_degraded_("required GATT read returned null data");
    return;
  }
  switch (operation.purpose) {
    case ReadPurpose::DEVICE_NAME:
      ESP_LOGD(TAG, "HID_DEVICE field=device_name len=%u value=%s", static_cast<unsigned>(length),
               printable_text(value, length).c_str());
      break;
    case ReadPurpose::MANUFACTURER:
      ESP_LOGD(TAG, "HID_DEVICE field=manufacturer len=%u value=%s", static_cast<unsigned>(length),
               printable_text(value, length).c_str());
      break;
    case ReadPurpose::SERIAL_NUMBER:
      ESP_LOGD(TAG, "HID_DEVICE field=serial_number len=%u value=%s privacy=sensitive",
               static_cast<unsigned>(length), printable_text(value, length).c_str());
      break;
    case ReadPurpose::APPEARANCE:
      if (length == 2)
        ESP_LOGD(TAG, "HID_DEVICE field=appearance value=%u", value[0] | (static_cast<uint16_t>(value[1]) << 8U));
      else
        this->mark_degraded_("Appearance has invalid length");
      break;
    case ReadPurpose::PREFERRED_CONNECTION_PARAMETERS:
      if (length == 8) {
        this->preferred_conn_params_.min_int = value[0] | (static_cast<uint16_t>(value[1]) << 8U);
        this->preferred_conn_params_.max_int = value[2] | (static_cast<uint16_t>(value[3]) << 8U);
        this->preferred_conn_params_.latency = value[4] | (static_cast<uint16_t>(value[5]) << 8U);
        this->preferred_conn_params_.timeout = value[6] | (static_cast<uint16_t>(value[7]) << 8U);
        memcpy(this->preferred_conn_params_.bda, this->parent()->get_remote_bda(), sizeof(esp_bd_addr_t));
        this->preferred_conn_params_valid_ = true;
      } else {
        this->mark_degraded_("Preferred Connection Parameters have invalid length");
      }
      break;
    case ReadPurpose::BATTERY_LEVEL:
      this->battery_handles_.insert(operation.characteristic_handle);
      if (length >= 1) {
        ESP_LOGD(TAG, "HID_BATTERY source=read value=%u", value[0]);
        if (this->battery_sensor_ != nullptr) this->battery_sensor_->publish_state(value[0]);
      } else {
        this->mark_degraded_("Battery Level is empty");
      }
      break;
    case ReadPurpose::PNP_ID:
      if (length >= 7) {
        const uint16_t vendor_id = value[1] | (static_cast<uint16_t>(value[2]) << 8U);
        const uint16_t product_id = value[3] | (static_cast<uint16_t>(value[4]) << 8U);
        const uint16_t version = value[5] | (static_cast<uint16_t>(value[6]) << 8U);
        ESP_LOGD(TAG, "HID_DEVICE field=pnp_id source=%u vendor_id=%u product_id=%u version=%u", value[0],
                 vendor_id, product_id, version);
      } else {
        this->mark_degraded_("PnP ID has invalid length");
      }
      break;
    case ReadPurpose::HID_INFORMATION: {
      HIDServiceContext *context = this->find_hid_context_(operation.service_instance);
      if (context != nullptr && length == 4) {
        ESP_LOGD(TAG, "HID_INFO service_instance=%u bcd_hid=0x%02X%02X country=%u flags=0x%02X",
                 operation.service_instance, value[1], value[0], value[2], value[3]);
      } else {
        this->mark_degraded_("HID Information has invalid length");
      }
      break;
    }
    case ReadPurpose::HID_PROTOCOL_MODE: {
      HIDServiceContext *context = this->find_hid_context_(operation.service_instance);
      if (context != nullptr && length == 1) {
        context->protocol_mode = value[0];
        context->protocol_mode_handle = operation.characteristic_handle;
        ESP_LOGD(TAG, "HID_PROTOCOL service_instance=%u mode=%s raw=%u", operation.service_instance,
                 value[0] == 0 ? "boot" : value[0] == 1 ? "report" : "unknown", value[0]);
      } else {
        this->mark_degraded_("Protocol Mode has invalid length");
      }
      break;
    }
    case ReadPurpose::HID_REPORT_MAP: {
      HIDServiceContext *context = this->find_hid_context_(operation.service_instance);
      if (context == nullptr || length == 0) {
        this->mark_degraded_("HID Report Map is empty");
        break;
      }
      context->report_map_hash = sha256_(value, length);
      context->report_map.reset(HIDReportMap::parse_report_map_data(value, length));
      ESP_LOGI(TAG, "HID_REPORT_MAP service_instance=%u len=%u sha256=%s data=%s", operation.service_instance,
               static_cast<unsigned>(length), context->report_map_hash.c_str(), raw.c_str());
      HIDReportMap::esp_logd_report_map(value, length);
      if (context->report_map == nullptr)
        this->mark_degraded_("HID Report Map could not be parsed");
      break;
    }
    case ReadPurpose::HID_REPORT_REFERENCE: {
      HIDReportSource &source = this->handle_report_source_[operation.characteristic_handle];
      source.service_instance = operation.service_instance;
      source.characteristic_handle = operation.characteristic_handle;
      source.characteristic_uuid = UUID_HID_REPORT;
      if (length == 2) {
        source.report_id = value[0];
        source.has_report_id = true;
        source.report_type = value[1];
        source.has_report_type = true;
        ESP_LOGD(TAG, "HID_REPORT_REFERENCE service_instance=%u handle=%u report_id=%u report_type=%u",
                 operation.service_instance, operation.characteristic_handle, value[0], value[1]);
        if (value[1] < 1 || value[1] > 3)
          this->mark_degraded_("Report Reference has unknown Report Type");
      } else {
        this->mark_degraded_("Report Reference has invalid length");
      }
      break;
    }
    case ReadPurpose::HID_EXTERNAL_REPORT_REFERENCE:
      if (length == 2)
        ESP_LOGD(TAG, "HID_EXTERNAL_REPORT_REFERENCE service_instance=%u uuid=0x%04X",
                 operation.service_instance, value[0] | (static_cast<uint16_t>(value[1]) << 8U));
      else
        this->mark_degraded_("External Report Reference has unsupported length");
      break;
    default:
      break;
  }
}

void BLEClientHID::log_hid_schema_(const HIDServiceContext &context) const {
  if (context.report_map == nullptr) return;
  for (const auto &diagnostic : context.report_map->diagnostics()) {
    if (diagnostic.error) {
      ESP_LOGW(TAG, "HID_SCHEMA_WARNING service_instance=%u offset=%u message=%s", context.service_instance,
               static_cast<unsigned>(diagnostic.offset), diagnostic.message.c_str());
    } else {
      ESP_LOGV(TAG, "HID_SCHEMA_DIAGNOSTIC service_instance=%u offset=%u message=%s", context.service_instance,
               static_cast<unsigned>(diagnostic.offset), diagnostic.message.c_str());
    }
  }
  for (const auto &collection : context.report_map->collections()) {
    const char *usage_name = lookup_usage_name(collection.usage.page, collection.usage.usage);
    ESP_LOGV(TAG, "HID_COLLECTION service_instance=%u collection_id=%u parent=%s type=%u usage_page=%u usage_id=%u usage=%s aliases=%u",
             context.service_instance, collection.id,
             collection.parent == HIDCollectionSchema::NO_PARENT ? "-" : std::to_string(collection.parent).c_str(),
             collection.type, collection.usage.page, collection.usage.usage,
             usage_name == nullptr ? "unknown" : usage_name, static_cast<unsigned>(collection.aliases.size()));
  }
  for (const auto &report : context.report_map->reports())
    ESP_LOGV(TAG, "HID_REPORT_SCHEMA service_instance=%u kind=%s report_id=%u bits=%u bytes=%u fields=%u",
             context.service_instance, hid_report_kind_name(report.kind), report.report_id, report.bit_size,
             static_cast<unsigned>(report.byte_size()), static_cast<unsigned>(report.field_ids.size()));
  for (const auto &field : context.report_map->fields()) {
    HIDUsage first_usage = field.usage_at(0, false);
    const char *usage_name = lookup_usage_name(first_usage.page, first_usage.usage);
    const char *usage_kinds = lookup_usage_kinds(first_usage.page, first_usage.usage);
    ESP_LOGV(TAG, "HID_FIELD service_instance=%u field_id=%u kind=%s report_id=%u collection_id=%s offset=%u size=%u count=%u flags=0x%03X logical_min=%lld logical_max=%lld physical_min=%lld physical_max=%lld unit=0x%08X unit_exp=%d usage_page=%u usage_id=%u usage=%s usage_kinds=%s aliases=%u strings=%u designators=%u",
             context.service_instance, field.id, hid_report_kind_name(field.kind), field.report_id,
             field.collection_id == HIDCollectionSchema::NO_PARENT ? "-" : std::to_string(field.collection_id).c_str(),
             field.bit_offset, field.report_size, field.report_count, field.flags,
             static_cast<long long>(field.logical.minimum), static_cast<long long>(field.logical.maximum),
             static_cast<long long>(field.physical.minimum), static_cast<long long>(field.physical.maximum), field.unit,
             field.unit_exponent, first_usage.page, first_usage.usage, usage_name == nullptr ? "unknown" : usage_name,
             usage_kinds == nullptr ? "-" : usage_kinds, static_cast<unsigned>(field.alternative_usages.size()),
             static_cast<unsigned>(field.string_indices.size()), static_cast<unsigned>(field.designator_indices.size()));
  }
}

void BLEClientHID::build_hid_profiles_() {
  for (const auto &service : this->services_) {
    if (!uuid16_(service.uuid, UUID_HID_SERVICE)) continue;
    HIDServiceContext *context = this->find_hid_context_(service.instance);
    for (const auto &characteristic : service.characteristics) {
      const esp_bt_uuid_t raw_uuid = characteristic.uuid.get_uuid();
      if (raw_uuid.len != ESP_UUID_LEN_16) continue;
      const uint16_t uuid = raw_uuid.uuid.uuid16;
      if (uuid == UUID_HID_REPORT || uuid == UUID_BOOT_KEYBOARD_INPUT || uuid == UUID_BOOT_MOUSE_INPUT) {
        this->hid_report_handles_.insert(characteristic.handle);
        HIDReportSource &source = this->handle_report_source_[characteristic.handle];
        source.service_instance = service.instance;
        source.characteristic_handle = characteristic.handle;
        source.characteristic_uuid = uuid;
        if (uuid == UUID_BOOT_KEYBOARD_INPUT || uuid == UUID_BOOT_MOUSE_INPUT) {
          source.report_type = static_cast<uint8_t>(HIDReportKind::INPUT);
          source.has_report_type = true;
        } else if (!source.has_report_id) {
          ESP_LOGW(TAG, "HID_SCHEMA_WARNING service_instance=%u handle=%u reason=missing_report_reference",
                   service.instance, characteristic.handle);
          this->degraded_ = true;
        }
      }
      if (uuid == UUID_HID_PROTOCOL_MODE && context != nullptr)
        context->protocol_mode_handle = characteristic.handle;
    }
    if (context == nullptr || context->report_map == nullptr) continue;
    this->log_hid_schema_(*context);
    for (const auto &entry : this->handle_report_source_) {
      const HIDReportSource &source = entry.second;
      if (source.service_instance != service.instance || !source.has_report_id || !source.has_report_type) continue;
      const auto kind = source.report_type == 1 ? HIDReportKind::INPUT :
                        source.report_type == 2 ? HIDReportKind::OUTPUT : HIDReportKind::FEATURE;
      if (source.report_type >= 1 && source.report_type <= 3 &&
          context->report_map->find_report(kind, source.report_id) == nullptr) {
        ESP_LOGW(TAG, "HID_SCHEMA_WARNING service_instance=%u handle=%u report_id=%u report_type=%u reason=reference_not_defined",
                 service.instance, source.characteristic_handle, source.report_id, source.report_type);
        this->degraded_ = true;
      }
    }
    ESP_LOGD(TAG, "HID_PROFILE service_instance=%u report_map_sha256=%s reports=%u fields=%u collections=%u protocol=%s",
             context->service_instance, context->report_map_hash.c_str(),
             static_cast<unsigned>(context->report_map->reports().size()),
             static_cast<unsigned>(context->report_map->fields().size()),
             static_cast<unsigned>(context->report_map->collections().size()),
             context->protocol_mode == 0 ? "boot" : context->protocol_mode == 1 ? "report" : "unknown");
  }
}

void BLEClientHID::start_protocol_mode_write_() {
  if (this->setup_phase_ == SetupPhase::BUILDING_PROFILE) {
    this->protocol_write_handles_.clear();
    if (this->protocol_mode_policy_ != ProtocolModePolicy::UNCHANGED)
      for (const auto &context : this->hid_services_)
        if (context.protocol_mode_handle != 0) this->protocol_write_handles_.push_back(context.protocol_mode_handle);
    this->transition_(SetupPhase::WRITING_PROTOCOL_MODE);
  }
  if (this->protocol_write_handles_.empty()) {
    this->plan_subscriptions_();
    this->transition_(SetupPhase::REGISTERING);
    return;
  }
  const uint16_t handle = this->protocol_write_handles_.front();
  this->protocol_write_handles_.pop_front();
  uint8_t value = this->protocol_mode_policy_ == ProtocolModePolicy::BOOT ? 0 : 1;
  const esp_err_t status = esp_ble_gattc_write_char(this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
                                                     handle, 1, &value, ESP_GATT_WRITE_TYPE_NO_RSP,
                                                     ESP_GATT_AUTH_REQ_NONE);
  if (status == ESP_OK) {
    this->operations_succeeded_++;
    ESP_LOGD(TAG, "HID_PROTOCOL_WRITE handle=%u requested_mode=%s status=scheduled", handle,
             value == 0 ? "boot" : "report");
  } else {
    this->mark_degraded_("Protocol Mode write failed");
  }
}

void BLEClientHID::plan_subscriptions_() {
  this->subscription_queue_.clear();
  for (const auto &service : this->services_) {
    for (const auto &characteristic : service.characteristics) {
      if ((characteristic.properties & (ESP_GATT_CHAR_PROP_BIT_NOTIFY | ESP_GATT_CHAR_PROP_BIT_INDICATE)) == 0)
        continue;
      const esp_bt_uuid_t raw_uuid = characteristic.uuid.get_uuid();
      const uint16_t uuid = raw_uuid.len == ESP_UUID_LEN_16 ? raw_uuid.uuid.uuid16 : 0;
      const bool battery = uuid16_(service.uuid, UUID_BATTERY_SERVICE) && uuid == UUID_BATTERY_LEVEL;
      const bool service_changed = uuid16_(service.uuid, UUID_GATT_SERVICE) && uuid == UUID_SERVICE_CHANGED;
      const bool hid = uuid16_(service.uuid, UUID_HID_SERVICE) &&
                       (uuid == UUID_HID_REPORT || uuid == UUID_BOOT_KEYBOARD_INPUT || uuid == UUID_BOOT_MOUSE_INPUT);
      if (!battery && !service_changed && !hid && this->discovery_mode_ != DiscoveryMode::FORENSIC) continue;
      if (this->subscription_queue_.size() >= MAX_SUBSCRIPTIONS) {
        this->mark_degraded_("subscription limit exceeded");
        break;
      }
      SubscriptionInfo subscription;
      subscription.characteristic_handle = characteristic.handle;
      subscription.service_instance = service.instance;
      subscription.properties = characteristic.properties;
      subscription.required = hid;
      const GattDescriptorInfo *cccd = this->find_descriptor_(characteristic, UUID_CCCD);
      if (cccd != nullptr) subscription.cccd_handle = cccd->handle;
      this->subscription_queue_.push_back(subscription);
      if (battery) this->battery_handles_.insert(characteristic.handle);
      if (service_changed) this->service_changed_handles_.insert(characteristic.handle);
    }
  }
  ESP_LOGD(TAG, "HID_SUBSCRIPTION_PLAN count=%u mode=%s", static_cast<unsigned>(this->subscription_queue_.size()),
           this->discovery_mode_ == DiscoveryMode::FORENSIC ? "forensic" : "standard");
}

void BLEClientHID::start_next_subscription_() {
  if (this->active_subscription_ != nullptr || this->congested_) return;
  if (this->subscription_queue_.empty()) {
    this->finalize_setup_();
    return;
  }
  this->active_subscription_ =
      std::make_unique<SubscriptionInfo>(std::move(this->subscription_queue_.front()));
  this->subscription_queue_.pop_front();
  this->subscription_state_.begin(this->active_subscription_->characteristic_handle,
                                  this->active_subscription_->cccd_handle);
  if (this->active_subscription_->cccd_handle == 0) {
    ESP_LOGW(TAG, "HID_SUBSCRIPTION handle=%u status=failed reason=missing_cccd",
             this->active_subscription_->characteristic_handle);
    if (this->active_subscription_->required) this->mark_degraded_("required notification has no CCCD");
    else this->operations_failed_++;
    this->active_subscription_.reset();
    this->subscription_state_.reset();
    return;
  }
  const esp_err_t status = esp_ble_gattc_register_for_notify(
      this->parent()->get_gattc_if(), this->parent()->get_remote_bda(),
      this->active_subscription_->characteristic_handle);
  if (status != ESP_OK) {
    ESP_LOGW(TAG, "HID_SUBSCRIPTION handle=%u status=registration_schedule_failed code=%d",
             this->active_subscription_->characteristic_handle, status);
    if (this->active_subscription_->required) this->mark_degraded_("required notification registration failed");
    else this->operations_failed_++;
    this->active_subscription_.reset();
    this->subscription_state_.reset();
  }
}

void BLEClientHID::handle_registration_result_(uint16_t handle, esp_gatt_status_t status) {
  const SubscriptionDecision decision =
      this->subscription_state_.registration_result(handle, status == ESP_GATT_OK, millis(), CCCD_FALLBACK_DELAY_MS);
  if (this->active_subscription_ == nullptr || decision == SubscriptionDecision::UNMATCHED) {
    ESP_LOGV(TAG, "HID_SUBSCRIPTION handle=%u status=unexpected_registration_callback", handle);
    return;
  }
  if (decision == SubscriptionDecision::FAILED) {
    ESP_LOGW(TAG, "HID_SUBSCRIPTION handle=%u status=registration_failed code=%d", handle, status);
    if (this->active_subscription_->required) this->mark_degraded_("required notification registration failed");
    else this->operations_failed_++;
    this->active_subscription_.reset();
    this->subscription_state_.reset();
    this->transition_(SetupPhase::REGISTERING);
    return;
  }
  ESP_LOGV(TAG, "HID_SUBSCRIPTION handle=%u status=registered cccd_handle=%u", handle,
           this->active_subscription_->cccd_handle);
  this->transition_(SetupPhase::WAITING_FOR_CCCD);
}

void BLEClientHID::write_current_cccd_() {
  if (this->active_subscription_ == nullptr) return;
  this->subscription_state_.own_cccd_write_attempted();
  uint16_t value = (this->active_subscription_->properties & ESP_GATT_CHAR_PROP_BIT_NOTIFY) != 0 ? 1 : 2;
  const esp_err_t status = esp_ble_gattc_write_char_descr(
      this->parent()->get_gattc_if(), this->parent()->get_conn_id(), this->active_subscription_->cccd_handle,
      sizeof(value), reinterpret_cast<uint8_t *>(&value), ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
  if (status != ESP_OK) {
    ESP_LOGW(TAG, "HID_SUBSCRIPTION handle=%u cccd_handle=%u status=cccd_schedule_failed code=%d",
             this->active_subscription_->characteristic_handle, this->active_subscription_->cccd_handle, status);
    if (this->active_subscription_->required) this->mark_degraded_("required CCCD write failed");
    else this->operations_failed_++;
    this->active_subscription_.reset();
    this->subscription_state_.reset();
    this->transition_(SetupPhase::REGISTERING);
  }
}

void BLEClientHID::handle_cccd_result_(uint16_t handle, esp_gatt_status_t status) {
  const SubscriptionDecision decision = this->subscription_state_.cccd_result(handle, status == ESP_GATT_OK);
  if (this->active_subscription_ == nullptr || decision == SubscriptionDecision::UNMATCHED) {
    ESP_LOGV(TAG, "HID_SUBSCRIPTION cccd_handle=%u status=unmatched_write_callback code=%d", handle, status);
    return;
  }
  if (decision == SubscriptionDecision::COMPLETE) {
    ESP_LOGD(TAG, "HID_SUBSCRIPTION handle=%u cccd_handle=%u status=enabled",
             this->active_subscription_->characteristic_handle, handle);
    this->operations_succeeded_++;
    this->active_subscription_.reset();
    this->subscription_state_.reset();
    this->transition_(SetupPhase::REGISTERING);
    return;
  }
  if (decision == SubscriptionDecision::RETRY_CCCD) {
    ESP_LOGW(TAG, "HID_SUBSCRIPTION handle=%u cccd_handle=%u status=framework_write_failed code=%d action=retry",
             this->active_subscription_->characteristic_handle, handle, status);
    this->write_current_cccd_();
    return;
  }
  ESP_LOGW(TAG, "HID_SUBSCRIPTION handle=%u cccd_handle=%u status=failed code=%d",
           this->active_subscription_->characteristic_handle, handle, status);
  if (this->active_subscription_->required) this->mark_degraded_("required CCCD write failed");
  else this->operations_failed_++;
  this->active_subscription_.reset();
  this->subscription_state_.reset();
  this->transition_(SetupPhase::REGISTERING);
}

void BLEClientHID::finalize_setup_() {
  if (this->preferred_conn_params_valid_ && esp_ble_gap_update_conn_params(&this->preferred_conn_params_) != ESP_OK)
    ESP_LOGW(TAG, "HID_CONNECTION_PARAMETERS status=request_failed");
  if (this->degraded_) {
    this->transition_(SetupPhase::DEGRADED);
  } else {
    this->status_clear_warning();
    this->transition_(SetupPhase::READY);
  }
  ESP_LOGI(TAG, "HID_READY status=%s services=%u hid_services=%u operations_succeeded=%u operations_failed=%u gatt_profile=%s",
           this->degraded_ ? "DEGRADED" : "OK", static_cast<unsigned>(this->services_.size()),
           static_cast<unsigned>(this->hid_services_.size()), static_cast<unsigned>(this->operations_succeeded_),
           static_cast<unsigned>(this->operations_failed_), this->gatt_profile_hash_.c_str());
  this->node_state = espbt::ClientState::ESTABLISHED;
}

void BLEClientHID::gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                                       esp_ble_gattc_cb_param_t *param) {
  if (param == nullptr || (gattc_if != ESP_GATT_IF_NONE && gattc_if != this->parent()->get_gattc_if())) return;
  switch (event) {
    case ESP_GATTC_CONNECT_EVT:
      if (memcmp(param->connect.remote_bda, this->parent()->get_remote_bda(), sizeof(esp_bd_addr_t)) != 0) break;
      this->reset_connection_state_();
      this->transition_(SetupPhase::WAITING_FOR_DISCOVERY);
      if (esp_ble_set_encryption(param->connect.remote_bda, ESP_BLE_SEC_ENCRYPT) != ESP_OK)
        ESP_LOGW(TAG, "HID_CONNECTION security=request_failed");
      break;
    case ESP_GATTC_DISCONNECT_EVT:
      if (memcmp(param->disconnect.remote_bda, this->parent()->get_remote_bda(), sizeof(esp_bd_addr_t)) != 0) break;
      ESP_LOGW(TAG, "HID_CONNECTION status=disconnected reason=%d", param->disconnect.reason);
      this->status_set_warning("Disconnected");
      this->reset_connection_state_();
      this->transition_(SetupPhase::DISCONNECTED);
      break;
    case ESP_GATTC_SEARCH_CMPL_EVT:
      if (param->search_cmpl.conn_id != this->parent()->get_conn_id()) break;
      if (param->search_cmpl.status != ESP_GATT_OK) {
        this->mark_degraded_("GATT service discovery failed");
        this->finalize_setup_();
      } else {
        this->transition_(SetupPhase::INVENTORY);
      }
      break;
    case ESP_GATTC_READ_CHAR_EVT:
    case ESP_GATTC_READ_DESCR_EVT:
      if (param->read.conn_id != this->parent()->get_conn_id()) break;
      if (this->active_read_ == nullptr || this->active_read_->handle != param->read.handle) {
        ESP_LOGV(TAG, "GATT_READ handle=%u status=unmatched_callback", param->read.handle);
        break;
      }
      this->finish_active_read_(param->read.status, param->read.value, param->read.value_len);
      break;
    case ESP_GATTC_REG_FOR_NOTIFY_EVT:
      this->handle_registration_result_(param->reg_for_notify.handle, param->reg_for_notify.status);
      break;
    case ESP_GATTC_WRITE_DESCR_EVT:
      if (param->write.conn_id == this->parent()->get_conn_id())
        this->handle_cccd_result_(param->write.handle, param->write.status);
      break;
    case ESP_GATTC_NOTIFY_EVT: {
      if (param->notify.conn_id != this->parent()->get_conn_id() ||
          memcmp(param->notify.remote_bda, this->parent()->get_remote_bda(), sizeof(esp_bd_addr_t)) != 0)
        break;
      const uint64_t seq_id = this->log_raw_notification_(param->notify);
      if (this->service_changed_handles_.count(param->notify.handle) != 0) {
        ESP_LOGW(TAG, "HID_SERVICE_CHANGED seq_id=%llu action=invalidate_profile",
                 static_cast<unsigned long long>(seq_id));
        this->request_rediscovery_();
      } else if (this->battery_handles_.count(param->notify.handle) != 0) {
        if (param->notify.value == nullptr || param->notify.value_len < 1) {
          ESP_LOGW(TAG, "HID_IGNORE seq_id=%llu reason=invalid_battery_payload",
                   static_cast<unsigned long long>(seq_id));
        } else {
          ESP_LOGD(TAG, "HID_BATTERY seq_id=%llu source=notification value=%u",
                   static_cast<unsigned long long>(seq_id), param->notify.value[0]);
          if (this->battery_sensor_ != nullptr) this->battery_sensor_->publish_state(param->notify.value[0]);
        }
      } else if (this->hid_report_handles_.count(param->notify.handle) != 0) {
        this->enqueue_input_report_(param->notify, seq_id);
      } else {
        ESP_LOGD(TAG, "HID_RAW_HANDLING seq_id=%llu result=raw_only reason=no_decoder",
                 static_cast<unsigned long long>(seq_id));
      }
      break;
    }
    case ESP_GATTC_SRVC_CHG_EVT:
      if (memcmp(param->srvc_chg.remote_bda, this->parent()->get_remote_bda(), sizeof(esp_bd_addr_t)) == 0)
        this->request_rediscovery_();
      break;
    case ESP_GATTC_CONGEST_EVT:
      if (param->congest.conn_id == this->parent()->get_conn_id()) {
        this->congested_ = param->congest.congested;
        ESP_LOGW(TAG, "GATT_CONGESTION congested=%s", this->congested_ ? "true" : "false");
      }
      break;
    case ESP_GATTC_QUEUE_FULL_EVT:
      if (param->queue_full.conn_id == this->parent()->get_conn_id()) {
        this->congested_ = param->queue_full.is_full;
        ESP_LOGW(TAG, "GATT_QUEUE_FULL full=%s status=%d", param->queue_full.is_full ? "true" : "false",
                 param->queue_full.status);
      }
      break;
    case ESP_GATTC_DIS_SRVC_CMPL_EVT:
      if (param->dis_srvc_cmpl.conn_id == this->parent()->get_conn_id()) {
        ESP_LOGV(TAG, "GATT_DISCOVERY_COMPLETE status=%d", param->dis_srvc_cmpl.status);
      }
      break;
    default:
      break;
  }
}

void BLEClientHID::gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  if (param == nullptr || event != ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT ||
      memcmp(param->update_conn_params.bda, this->parent()->get_remote_bda(), sizeof(esp_bd_addr_t)) != 0)
    return;
  ESP_LOGI(TAG, "HID_CONNECTION_PARAMETERS status=%d interval_ms=%.2f latency=%u timeout_ms=%.1f",
           param->update_conn_params.status, param->update_conn_params.conn_int * 1.25f,
           param->update_conn_params.latency, param->update_conn_params.timeout * 10.0f);
}

uint64_t BLEClientHID::log_raw_notification_(
    const esp_ble_gattc_cb_param_t::gattc_notify_evt_param &notification) {
  const uint64_t seq_id = this->next_seq_id_++;
  const uint16_t handle = notification.handle;
  const char *classification = this->battery_handles_.count(handle) != 0 ? "BATTERY" :
                               this->service_changed_handles_.count(handle) != 0 ? "SERVICE_CHANGED" :
                               this->hid_report_handles_.count(handle) != 0 ? "HID" : "UNKNOWN";
  HIDReportSource source;
  auto known = this->handle_report_source_.find(handle);
  if (known != this->handle_report_source_.end()) source = known->second;
  const GattCharacteristicInfo *characteristic = this->find_characteristic_(handle);
  const std::string uuid = characteristic == nullptr ? "unknown" : uuid_string_(characteristic->uuid);
  const uint16_t service_instance = characteristic == nullptr ? source.service_instance
                                                               : characteristic->service_instance;
  const std::string report_id = source.has_report_id ? std::to_string(source.report_id) : "-";
  const char *report_type = source.has_report_type && source.report_type >= 1 && source.report_type <= 3
                              ? hid_report_kind_name(static_cast<HIDReportKind>(source.report_type)) : "-";
  const std::string raw = format_value_(notification.value, notification.value_len);
  ESP_LOGD(TAG, "HID_RAW seq_id=%llu class=%s service_instance=%u handle=%u uuid=%s report_id=%s report_type=%s transport=%s len=%u data=%s",
           static_cast<unsigned long long>(seq_id), classification, service_instance, handle, uuid.c_str(),
           report_id.c_str(), report_type, notification.is_notify ? "notify" : "indicate",
           notification.value_len, raw.c_str());
  return seq_id;
}

void BLEClientHID::enqueue_input_report_(
    const esp_ble_gattc_cb_param_t::gattc_notify_evt_param &notification, uint64_t seq_id) {
  if (notification.value == nullptr && notification.value_len != 0) {
    ESP_LOGW(TAG, "HID_IGNORE seq_id=%llu reason=null_payload len=%u", static_cast<unsigned long long>(seq_id),
             notification.value_len);
    return;
  }
  if (notification.value_len > MAX_REPORT_PAYLOAD_BYTES) {
    ESP_LOGW(TAG, "HID_IGNORE seq_id=%llu reason=payload_limit len=%u",
             static_cast<unsigned long long>(seq_id), notification.value_len);
    return;
  }
  while (!this->pending_reports_.empty() &&
         (this->pending_reports_.size() >= MAX_PENDING_REPORTS ||
          this->pending_report_bytes_ + notification.value_len > MAX_PENDING_REPORT_BYTES)) {
    this->reports_dropped_++;
    const uint64_t dropped = this->pending_reports_.front().seq_id;
    this->pending_report_bytes_ -= this->pending_reports_.front().payload.size();
    this->pending_reports_.pop_front();
    const uint32_t now = millis();
    if (this->last_overflow_warning_ == 0 || elapsed(now, this->last_overflow_warning_, OVERFLOW_WARNING_INTERVAL_MS)) {
      ESP_LOGW(TAG, "HID_QUEUE status=full dropped_total=%u dropped_seq_id=%llu queued_bytes=%u policy=drop_oldest",
               static_cast<unsigned>(this->reports_dropped_), static_cast<unsigned long long>(dropped),
               static_cast<unsigned>(this->pending_report_bytes_));
      this->last_overflow_warning_ = now;
    }
  }
  PendingHIDReport report;
  auto source = this->handle_report_source_.find(notification.handle);
  if (source != this->handle_report_source_.end()) report.source = source->second;
  report.source.characteristic_handle = notification.handle;
  report.source.is_notification = notification.is_notify;
  report.source.has_transport = true;
  report.seq_id = seq_id;
  if (notification.value_len != 0)
    report.payload.assign(notification.value, notification.value + notification.value_len);
  this->pending_report_bytes_ += report.payload.size();
  this->pending_reports_.push_back(std::move(report));
}

void BLEClientHID::process_input_report_(PendingHIDReport report, const std::string &raw) {
  HIDDecodeStatus status = HIDDecodeStatus::SCHEMA_MISSING;
  bool recognized = false;
  std::vector<HIDReportItemValue> values;
  if (report.source.characteristic_uuid == UUID_BOOT_KEYBOARD_INPUT ||
      report.source.characteristic_uuid == UUID_BOOT_MOUSE_INPUT) {
    values = this->boot_decoder_.decode(report.source, report.payload.data(), report.payload.size(), &status);
    recognized = status == HIDDecodeStatus::EXACT || status == HIDDecodeStatus::LONG;
  } else {
    HIDServiceContext *context = this->find_hid_context_(report.source.service_instance);
    if (context != nullptr && context->report_map != nullptr)
      values = context->report_map->parse(report.source, report.payload.data(), report.payload.size(), &recognized,
                                          &status);
  }
  this->process_decoded_values_(report, raw, values, status);
  if (values.empty() && recognized) {
    ESP_LOGD(TAG, "HID_NO_EVENT seq_id=%llu reason=unchanged decode_status=%s",
             static_cast<unsigned long long>(report.seq_id), hid_decode_status_name(status));
  } else if (values.empty() && !recognized) {
    HIDEvent barrier = this->make_hid_event_(report, raw, nullptr, status);
    for (HIDEvent &event : this->sampled_events_.drain_before(std::move(barrier)))
      this->emit_hid_event_(std::move(event));
    this->sampling_window_active_ = false;
  }
}

void BLEClientHID::process_decoded_values_(const PendingHIDReport &report, const std::string &raw,
                                           const std::vector<HIDReportItemValue> &values, HIDDecodeStatus status) {
  this->update_sampling_window_();
  size_t index = 0;
  while (index < values.size()) {
    const HIDReportItemValue &value = values[index];
    if (this->event_sampling_interval_us_ == 0 || value.aggregation == HIDReportItemValue::Aggregation::PASSTHROUGH) {
      if (this->event_sampling_interval_us_ != 0) {
        HIDEvent barrier = this->make_hid_event_(report, raw, &value, status);
        for (HIDEvent &event : this->sampled_events_.drain_before(std::move(barrier)))
          this->emit_hid_event_(std::move(event));
        this->sampling_window_active_ = false;
      } else {
        this->emit_hid_event_(this->make_hid_event_(report, raw, &value, status));
      }
      index++;
      continue;
    }
    size_t run_end = index + 1;
    while (run_end < values.size() && values[run_end].aggregation != HIDReportItemValue::Aggregation::PASSTHROUGH)
      run_end++;
    if (!this->sampling_window_active_) {
      for (size_t current = index; current < run_end; current++)
        this->emit_hid_event_(this->make_hid_event_(report, raw, &values[current], status));
      this->sampling_window_active_ = true;
      this->sampling_window_started_us_ = micros();
    } else {
      for (size_t current = index; current < run_end; current++)
        this->accumulate_event_(report, raw, values[current], status);
    }
    index = run_end;
  }
}

void BLEClientHID::accumulate_event_(const PendingHIDReport &report, const std::string &raw,
                                     const HIDReportItemValue &value, HIDDecodeStatus status) {
  const SampledEventKey key{report.source.service_instance, value.field_id,
                            static_cast<uint8_t>(report.source.has_report_id ? report.source.report_id : 0),
                            static_cast<uint8_t>(HIDReportKind::INPUT)};
  HIDEvent event = this->make_hid_event_(report, raw, &value, status);
  if (this->sampled_events_.accumulate(key, value.aggregation, value.value, value.raw_value, std::move(event))) return;
  this->flush_sampled_events_("pressure");
  HIDEvent retry = this->make_hid_event_(report, raw, &value, status);
  if (!this->sampled_events_.accumulate(key, value.aggregation, value.value, value.raw_value, std::move(retry)))
    ESP_LOGW(TAG, "HID_COALESCING status=failed service_instance=%u field_id=%u", key.service_instance,
             static_cast<unsigned>(key.field_id));
  this->sampling_window_started_us_ = micros();
}

void BLEClientHID::update_sampling_window_() {
  if (!this->sampling_window_active_ || this->event_sampling_interval_us_ == 0) return;
  const uint32_t now = micros();
  if (!elapsed(now, this->sampling_window_started_us_, this->event_sampling_interval_us_)) return;
  if (this->sampled_events_.empty()) {
    this->sampling_window_active_ = false;
    return;
  }
  this->flush_sampled_events_("timer");
  this->sampling_window_started_us_ = now;
}

void BLEClientHID::flush_sampled_events_(const char *reason) {
  if (this->sampled_events_.empty()) return;
  ESP_LOGV(TAG, "HID_COALESCING action=flush pending=%u reason=%s",
           static_cast<unsigned>(this->sampled_events_.size()), reason);
  for (HIDEvent &event : this->sampled_events_.drain()) this->emit_hid_event_(std::move(event));
}

HIDEvent BLEClientHID::make_hid_event_(const PendingHIDReport &report, const std::string &raw,
                                       const HIDReportItemValue *value, HIDDecodeStatus status) {
  const HIDReportSource &source = report.source;
  const GattCharacteristicInfo *characteristic = this->find_characteristic_(source.characteristic_handle);
  HIDEvent event;
  event.data = {{"device", this->parent()->address_str()},
                {"hid_service", std::to_string(source.service_instance)},
                {"handle", std::to_string(source.characteristic_handle)},
                {"characteristic_uuid", characteristic == nullptr ? "unknown" : uuid_string_(characteristic->uuid)},
                {"report_id", source.has_report_id ? std::to_string(source.report_id) : "unknown"},
                {"hid_report_type", source.has_report_type && source.report_type >= 1 && source.report_type <= 3
                                          ? hid_report_kind_name(static_cast<HIDReportKind>(source.report_type)) : "unknown"},
                {"transport", source.has_transport ? (source.is_notification ? "notification" : "indication") : "unknown"},
                {"length", std::to_string(report.payload.size())},
                {"raw_data", raw},
                {"decode_status", hid_decode_status_name(status)},
                {"seq_id_from", std::to_string(report.seq_id)},
                {"seq_id_to", std::to_string(report.seq_id)}};
  const HIDServiceContext *context = this->find_hid_context_(source.service_instance);
  if (context != nullptr && !context->report_map_hash.empty())
    event.data.emplace("profile_id", context->report_map_hash.substr(0, 16));
  if (value == nullptr) return event;
  const char *usage_name = lookup_usage_name(value->usage.page, value->usage.usage);
  const std::string usage = usage_name == nullptr
      ? std::to_string(value->usage.page) + "_" + std::to_string(value->usage.usage) : usage_name;
  event.data.emplace("usage", usage);
  event.data.emplace("usage_page", std::to_string(value->usage.page));
  event.data.emplace("usage_id", std::to_string(value->usage.usage));
  event.data.emplace("field_id", std::to_string(value->field_id));
  event.data.emplace("collection_id", value->collection_id == HIDCollectionSchema::NO_PARENT
                                            ? "unknown" : std::to_string(value->collection_id));
  event.data.emplace("application_usage_page", std::to_string(value->application_usage.page));
  event.data.emplace("application_usage_id", std::to_string(value->application_usage.usage));
  const char *application_name = lookup_usage_name(value->application_usage.page, value->application_usage.usage);
  if (application_name != nullptr) event.data.emplace("application_usage", application_name);
  event.data.emplace("value", std::to_string(value->value));
  event.data.emplace("raw_value", std::to_string(value->raw_value));
  event.data.emplace("relative", value->is_relative ? "true" : "false");
  return event;
}

void BLEClientHID::emit_hid_event_(HIDEvent event) {
#ifdef USE_API
  this->fire_homeassistant_event("esphome.hid_events", event.data);
#endif
  auto usage = event.data.find("usage");
  if (usage != event.data.end()) {
    if (this->last_event_usage_text_sensor_ != nullptr)
      this->last_event_usage_text_sensor_->publish_state(usage->second);
    if (this->last_event_code_text_sensor_ != nullptr)
      this->last_event_code_text_sensor_->publish_state(event.data.at("usage_page") + "_" + event.data.at("usage_id"));
    if (this->last_event_value_sensor_ != nullptr)
      this->last_event_value_sensor_->publish_state(strtoll(event.data.at("value").c_str(), nullptr, 10));
  }
  ESP_LOGD(TAG, "HID_EVENT seq_id_from=%s seq_id_to=%s service_instance=%s report_id=%s field_id=%s usage=%s value=%s decode_status=%s",
           event.data.at("seq_id_from").c_str(), event.data.at("seq_id_to").c_str(),
           event.data.at("hid_service").c_str(), event.data.at("report_id").c_str(),
           event.data.count("field_id") != 0 ? event.data.at("field_id").c_str() : "unknown",
           usage != event.data.end() ? usage->second.c_str() : "unknown",
           event.data.count("value") != 0 ? event.data.at("value").c_str() : "unknown",
           event.data.at("decode_status").c_str());
}

void BLEClientHID::request_rediscovery_() { this->rediscovery_requested_ = true; }

#ifdef USE_ESP32_BLE_DEVICE
bool BLEClientHID::parse_device(const espbt::ESPBTDevice &device) {
  if (device.address_uint64() != this->parent()->get_address()) return false;
  const auto &scan = device.get_scan_result();
  const size_t total = static_cast<size_t>(scan.adv_data_len) + scan.scan_rsp_len;
  if (total > this->pending_advertisement_.bytes.size()) return false;
  const bool same = total == this->last_advertisement_length_ &&
                    std::equal(scan.ble_adv, scan.ble_adv + total, this->last_advertisement_.begin());
  if (same) return false;
  std::copy(scan.ble_adv, scan.ble_adv + total, this->last_advertisement_.begin());
  this->last_advertisement_length_ = static_cast<uint8_t>(total);
  std::copy(scan.ble_adv, scan.ble_adv + total, this->pending_advertisement_.bytes.begin());
  this->pending_advertisement_.advertisement_length = scan.adv_data_len;
  this->pending_advertisement_.scan_response_length = scan.scan_rsp_len;
  this->pending_advertisement_.address_type = scan.ble_addr_type;
  this->pending_advertisement_.rssi = scan.rssi;
  this->pending_advertisement_.available = true;
  return false;
}
#endif

void BLEClientHID::process_pending_advertisement_() {
  if (!this->pending_advertisement_.available) return;
  PendingAdvertisement advertisement = this->pending_advertisement_;
  this->pending_advertisement_.available = false;
  ESP_LOGD(TAG, "BLE_ADV address=%s address_type=%u rssi=%d adv_len=%u scan_rsp_len=%u adv_data=%s scan_rsp_data=%s",
           this->parent()->address_str(), advertisement.address_type, advertisement.rssi,
           advertisement.advertisement_length, advertisement.scan_response_length,
           format_value_(advertisement.bytes.data(), advertisement.advertisement_length).c_str(),
           format_value_(advertisement.bytes.data() + advertisement.advertisement_length,
                         advertisement.scan_response_length).c_str());
  this->log_advertisement_elements_(advertisement.bytes.data(), advertisement.advertisement_length, "advertisement");
  this->log_advertisement_elements_(advertisement.bytes.data() + advertisement.advertisement_length,
                                    advertisement.scan_response_length, "scan_response");
}

void BLEClientHID::log_advertisement_elements_(const uint8_t *data, size_t length, const char *source) const {
  size_t offset = 0;
  while (offset < length) {
    const uint8_t field_length = data[offset++];
    if (field_length == 0) break;
    if (field_length > length - offset) {
      ESP_LOGW(TAG, "BLE_ADV_FIELD source=%s offset=%u status=truncated declared_len=%u remaining=%u", source,
               static_cast<unsigned>(offset - 1), field_length, static_cast<unsigned>(length - offset));
      return;
    }
    const uint8_t type = data[offset++];
    const size_t value_length = field_length - 1U;
    const std::string raw = format_value_(data + offset, value_length);
    if (type == 0x08 || type == 0x09) {
      ESP_LOGV(TAG, "BLE_ADV_FIELD source=%s type=0x%02X name=%s len=%u data=%s text=%s", source, type,
               ad_type_name(type), static_cast<unsigned>(value_length), raw.c_str(),
               printable_text(data + offset, value_length).c_str());
    } else {
      ESP_LOGV(TAG, "BLE_ADV_FIELD source=%s type=0x%02X name=%s len=%u data=%s", source, type,
               ad_type_name(type), static_cast<unsigned>(value_length), raw.c_str());
    }
    offset += value_length;
  }
}

void BLEClientHID::register_last_event_value_sensor(sensor::Sensor *sensor) {
  this->last_event_value_sensor_ = sensor;
}
void BLEClientHID::register_battery_sensor(sensor::Sensor *sensor) { this->battery_sensor_ = sensor; }
void BLEClientHID::register_last_event_usage_text_sensor(text_sensor::TextSensor *sensor) {
  this->last_event_usage_text_sensor_ = sensor;
}
void BLEClientHID::register_last_event_code_text_sensor(text_sensor::TextSensor *sensor) {
  this->last_event_code_text_sensor_ = sensor;
}

}  // namespace ble_client_hid
}  // namespace esphome
#endif
