#include "../ble_client_hid.h"
#include "forensic_transaction.h"

#if defined(USE_ESP32) && defined(USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING)

#include "esphome/components/web_server_base/web_server_base.h"
#include "esphome/components/web_server_idf/web_server_idf.h"
#include "esphome/components/json/json_util.h"
#include <algorithm>
#include <cstring>
#include <limits>

namespace esphome {
namespace ble_client_hid {

namespace {

constexpr const char *TREE_SUFFIX = "/gatt-tree.txt";
constexpr const char *JSON_SUFFIX = "/gatt-profile.json";
constexpr const char *RECORDER_SUFFIX = "/recorder";
constexpr const char *RECORDER_START_SUFFIX = "/recorder/start";
constexpr const char *RECORDER_STOP_SUFFIX = "/recorder/stop";
constexpr const char *RECORDER_CLEAR_SUFFIX = "/recorder/clear";
constexpr const char *RECORDER_JSON_SUFFIX = "/recorder/events.json";
constexpr const char *TRANSACTION_VALIDATE_SUFFIX = "/transaction/validate";
constexpr const char *TRANSACTION_RUN_SUFFIX = "/transaction/run";
constexpr const char *TRANSACTION_ABORT_SUFFIX = "/transaction/abort";
constexpr const char *TRANSACTION_STATUS_SUFFIX = "/transaction/status.json";

bool request_url_is(AsyncWebServerRequest *request, const std::string &expected) {
  char url_buffer[AsyncWebServerRequest::URL_BUF_SIZE];
  return request->url_to(url_buffer) == expected;
}

void add_download_headers(AsyncWebServerResponse *response, const char *filename, const std::string &profile_hash) {
  response->addHeader("Content-Disposition", filename);
  response->addHeader("Cache-Control", "no-store");
  if (!profile_hash.empty()) {
    response->addHeader("X-GATT-Profile", profile_hash.c_str());
  }
}

void add_profile_headers(AsyncWebServerResponse *response, const std::string &profile_hash) {
  response->addHeader("Cache-Control", "no-store");
  if (!profile_hash.empty()) {
    response->addHeader("X-GATT-Profile", profile_hash.c_str());
  }
}

}  // namespace

void ForensicResponseWriter::print(const char *value) {
  if (value != nullptr) this->append_(value, std::strlen(value));
}

void ForensicResponseWriter::write(uint8_t value) {
  const char byte = static_cast<char>(value);
  this->append_(&byte, 1);
}

void ForensicResponseWriter::append_(const char *data, size_t length) {
  while (!this->failed_ && length != 0) {
    const size_t available = this->buffer_.size() - this->buffer_length_;
    const size_t copied = std::min(available, length);
    std::memcpy(this->buffer_.data() + this->buffer_length_, data, copied);
    this->buffer_length_ += copied;
    data += copied;
    length -= copied;
    if (this->buffer_length_ == this->buffer_.size()) this->flush_();
  }
}

bool ForensicResponseWriter::flush_() {
  if (this->failed_ || this->buffer_length_ == 0) return !this->failed_;
  if (httpd_resp_send_chunk(*this->request_, this->buffer_.data(), this->buffer_length_) != ESP_OK) {
    this->failed_ = true;
    return false;
  }
  this->buffer_length_ = 0;
  return true;
}

bool ForensicResponseWriter::finish() {
  if (!this->flush_()) return false;
  if (httpd_resp_send_chunk(*this->request_, nullptr, 0) != ESP_OK) {
    this->failed_ = true;
    return false;
  }
  return true;
}

class ForensicWebHandler final : public AsyncWebHandler {
 public:
  ForensicWebHandler(BLEClientHID *client, const std::string &base_path)
      : client_(client),
        base_path_(base_path),
        tree_path_(base_path + TREE_SUFFIX),
        json_path_(base_path + JSON_SUFFIX),
        recorder_path_(base_path + RECORDER_SUFFIX),
        recorder_start_path_(base_path + RECORDER_START_SUFFIX),
        recorder_stop_path_(base_path + RECORDER_STOP_SUFFIX),
        recorder_clear_path_(base_path + RECORDER_CLEAR_SUFFIX),
        recorder_json_path_(base_path + RECORDER_JSON_SUFFIX),
        transaction_validate_path_(base_path + TRANSACTION_VALIDATE_SUFFIX),
        transaction_run_path_(base_path + TRANSACTION_RUN_SUFFIX),
        transaction_abort_path_(base_path + TRANSACTION_ABORT_SUFFIX),
        transaction_status_path_(base_path + TRANSACTION_STATUS_SUFFIX) {}

  bool canHandle(AsyncWebServerRequest *request) const override {
    if (request->method() == HTTP_GET)
      return request_url_is(request, this->base_path_) || request_url_is(request, this->tree_path_) ||
             request_url_is(request, this->json_path_) || request_url_is(request, this->recorder_path_) ||
             request_url_is(request, this->recorder_json_path_) ||
             request_url_is(request, this->transaction_status_path_);
    if (request->method() == HTTP_POST)
      return request_url_is(request, this->recorder_start_path_) ||
             request_url_is(request, this->recorder_stop_path_) ||
             request_url_is(request, this->recorder_clear_path_) ||
             request_url_is(request, this->transaction_validate_path_) ||
             request_url_is(request, this->transaction_run_path_) ||
             request_url_is(request, this->transaction_abort_path_);
    return false;
  }

  void handleBody(AsyncWebServerRequest *request, uint8_t *data, size_t length, size_t index, size_t total) override {
    if (request_url_is(request, this->transaction_validate_path_) ||
        request_url_is(request, this->transaction_run_path_))
      this->transaction_recipe_body_.append(data, length, index, total);
  }

  void handleRequest(AsyncWebServerRequest *request) override {
    LockGuard forensic_guard(this->client_->forensic_export_mutex_);
    if (request_url_is(request, this->base_path_)) {
      request->redirect(this->recorder_path_.c_str());
      return;
    }

    if (request_url_is(request, this->recorder_path_)) {
      const bool profile_ready = this->client_->forensic_snapshot_available_;
      const char *snapshot = profile_ready ? "ready" : "not ready";
      const char *disabled = profile_ready ? "" : " disabled";
      const char *recording = this->client_->forensic_recording_active_ ? "recording" : "stopped";
      std::string transaction_panel;
      if (this->client_->forensic_web_logging_enabled_()) {
        std::string options;
        for (const auto &service : this->client_->services_) {
          const std::string service_uuid = BLEClientHID::uuid_string_(service.uuid);
          bool group_open = false;
          for (const auto &characteristic : service.characteristics) {
            const bool write_rsp =
                (characteristic.properties & ESP_GATT_CHAR_PROP_BIT_WRITE) != 0;
            const bool write_no_rsp =
                (characteristic.properties & ESP_GATT_CHAR_PROP_BIT_WRITE_NR) != 0;
            if (write_rsp || write_no_rsp) {
              if (!group_open) {
                options += str_sprintf("<optgroup label=\"Service %s, instance %u\">", service_uuid.c_str(),
                                       service.instance);
                group_open = true;
              }
              const std::string characteristic_uuid = BLEClientHID::uuid_string_(characteristic.uuid);
              options += str_sprintf(
                  "<option value=\"c:%u:%u:%u:%u\">Characteristic %s, handle 0x%04X (%s%s%s)</option>",
                  service.start_handle, service.instance, characteristic.handle, characteristic.handle,
                  characteristic_uuid.c_str(), characteristic.handle, write_rsp ? "write response" : "",
                  write_rsp && write_no_rsp ? ", " : "", write_no_rsp ? "write no response" : "");
            }
            for (const auto &descriptor : characteristic.descriptors) {
              if (!group_open) {
                options += str_sprintf("<optgroup label=\"Service %s, instance %u\">", service_uuid.c_str(),
                                       service.instance);
                group_open = true;
              }
              const std::string descriptor_uuid = BLEClientHID::uuid_string_(descriptor.uuid);
              options += str_sprintf(
                  "<option value=\"d:%u:%u:%u:%u\">Descriptor %s, handle 0x%04X; characteristic 0x%04X</option>",
                  service.start_handle, service.instance, characteristic.handle, descriptor.handle,
                  descriptor_uuid.c_str(), descriptor.handle, characteristic.handle);
            }
          }
          if (group_open) options += "</optgroup>";
        }
        const size_t limit = this->client_->forensic_transaction_payload_limit_();
        const std::string starter = str_sprintf(
            "{\n  \"version\": 1,\n  \"name\": \"forensic transaction\",\n  \"profile_hash\": \"%s\","
            "\n  \"targets\": {},\n  \"variables\": {},\n  \"steps\": []\n}",
            this->client_->gatt_profile_hash_.c_str());
        transaction_panel = str_sprintf(
            "<hr><h2>Raw GATT write</h2>"
            "<p class=warn>Writes can reconfigure, reset, or permanently alter a peripheral. The selected service "
            "and attribute hierarchy is validated against this connection's profile.</p>"
            "<label>Attribute<br><select id=target>%s</select></label>"
            "<label>Write mode<br><select id=mode><option value=auto>Automatic from properties</option>"
            "<option value=response>With response</option><option value=no_response>Without response</option>"
            "</select></label>"
            "<label>Hex payload (maximum %u bytes for the current MTU)<br>"
            "<textarea id=payload rows=3 placeholder=\"01 02 03\"></textarea></label>"
            "<p><button data-profile-action onclick=\"runRawWrite()\"%s>Run as one-step transaction</button></p>"
            "<hr><h2>Transaction recipe</h2>"
            "<p>Recipes are validated completely before execution. Atomic exchanges arm their notification matcher "
            "before writing, then wait for both the write result and matching notification. Every response on a "
            "recipe notification handle is captured automatically in the standalone transaction response; the "
            "manual recorder is not required.</p>"
            "<label>JSON recipe<br><textarea id=recipe rows=22 spellcheck=false>%s</textarea></label>"
            "<label class=confirm><input id=confirm type=checkbox> I understand this recipe can send multiple raw "
            "writes to the peripheral.</label>"
            "<p><button data-profile-action onclick=\"validateRecipe()\"%s>Validate</button>"
            "<button data-profile-action onclick=\"runRecipe()\"%s>Run</button>"
            "<button data-profile-action onclick=\"abortRecipe()\"%s>Abort</button></p>"
            "<pre id=transactionStatus>No transaction submitted.</pre>"
            "<p><a id=transactionDownload href=\"%s?download=yes\" download=\"ble-hid-transaction-response.json\" "
            "hidden>Download standalone transaction response JSON</a></p>",
            options.c_str(), static_cast<unsigned>(limit), disabled, starter.c_str(), disabled, disabled, disabled,
            this->transaction_status_path_.c_str());
      } else {
        transaction_panel =
            "<hr><h2>Forensic transactions</h2><p>Transactions are unavailable outside forensic web mode.</p>";
      }
      const std::string body = str_sprintf(
          "<!doctype html><meta name=viewport content=\"width=device-width,initial-scale=1\">"
          "<title>BLE forensic recorder</title><style>body{font:16px system-ui;max-width:900px;margin:40px auto;"
          "padding:0 18px}button,a{margin:4px;padding:9px 13px}code,pre{background:#eee;padding:4px 7px}"
          "label{display:block;margin:12px 0}select,textarea{box-sizing:border-box;width:100%%;padding:8px}"
          "pre{white-space:pre-wrap;overflow-wrap:anywhere}"
          ".confirm{display:flex;gap:8px}.confirm input{width:auto}.warn{color:#8b1a1a}"
          "button:disabled{cursor:not-allowed;opacity:.45}</style>"
          "<h1>BLE forensic recorder</h1><p>Profile: <strong id=profileState>%s</strong> &middot; "
          "Recorder: <strong>%s</strong>"
          " &middot; Events: <strong>%u</strong> &middot; Dropped: <strong>%u</strong></p>"
          "<p><a href=\"%s\">Profile JSON</a><a href=\"%s\">Readable tree</a>"
          "<a href=\"%s\">Recorded events JSON</a></p>"
          "<p><button data-profile-action onclick=\"go('%s')\"%s>Start / restart recording</button>"
          "<button data-profile-action onclick=\"go('%s')\"%s>Stop recording</button>"
          "<button data-profile-action onclick=\"go('%s')\"%s>Clear events</button></p>"
          "<p>Start recording, press controls on the device, stop, then download the event file.</p>%s"
          "<script>async function go(p){persistRecipe();let r=await fetch(p,{method:'POST'});if(!r.ok)alert(await r.text());"
          "else location.reload()}const profile='%s';let profileReady=%s;let pollTimer;let transactionPolling=true;"
          "let statusRenderKey='';"
          "const statusBox=()=>document.getElementById('transactionStatus');"
          "const recipeBox=()=>document.getElementById('recipe');"
          "const downloadLink=()=>document.getElementById('transactionDownload');"
          "const recipeStorageKey='ble-hid-forensic-recipe:'+profile;"
          "function persistRecipe(){let b=recipeBox();if(!b)return;try{localStorage.setItem(recipeStorageKey,b.value)}"
          "catch(e){}}function restoreRecipe(){let b=recipeBox();if(!b)return;try{let saved=localStorage.getItem("
          "recipeStorageKey);if(saved!==null)b.value=saved}catch(e){}b.addEventListener('input',persistRecipe)}"
          "function setDownloadAvailable(available){let a=downloadLink();if(a)a.hidden=!available}"
          "function setProfileReady(ready){profileReady=ready;document.getElementById('profileState').textContent="
          "ready?'ready':'not ready';document.querySelectorAll('[data-profile-action]').forEach(b=>b.disabled=!ready)}"
          "function stopPolling(){transactionPolling=false;clearTimeout(pollTimer)}"
          "function schedulePoll(ms){clearTimeout(pollTimer);if(transactionPolling)pollTimer=setTimeout(pollTransaction,ms)}"
          "function startPolling(ms){transactionPolling=true;schedulePoll(ms)}"
          "function renderStatus(j){let key=JSON.stringify(j,(k,v)=>k=='elapsed_ms'?0:v);if(key==statusRenderKey)return;"
          "statusRenderKey=key;statusBox().textContent=JSON.stringify(j,null,2);"
          "setDownloadAvailable(j.available===true&&j.complete===true)}"
          "function rawRecipe(){let t=document.getElementById('target').value.split(':');return {version:1,"
          "name:'raw GATT write',profile_hash:profile,targets:{write_target:{kind:t[0]=='d'?'descriptor':"
          "'characteristic',service_start_handle:+t[1],service_instance:+t[2],characteristic_handle:+t[3],"
          "attribute_handle:+t[4],mode:document.getElementById('mode').value}},variables:{},steps:[{op:'write',"
          "target:'write_target',value:document.getElementById('payload').value}]}}"
          "async function postRecipe(path,recipe,confirm){if(confirm)path+='?confirm=yes';let r=await fetch(path,"
          "{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(recipe)});"
          "let text=await r.text();statusBox().textContent=text;"
          "if(r.ok&&confirm){setDownloadAvailable(false);startPolling(100)}}"
          "function confirmed(){if(document.getElementById('confirm').checked)return true;statusBox().textContent="
          "'Confirm the warning before running a transaction.';return false}"
          "async function runRawWrite(){if(confirmed())await postRecipe('%s',rawRecipe(),true)}"
          "function parsedRecipe(){try{return JSON.parse(document.getElementById('recipe').value)}catch(e){"
          "statusBox().textContent='Invalid JSON: '+e.message;return null}}"
          "async function validateRecipe(){let r=parsedRecipe();if(r)await postRecipe('%s',r,false)}"
          "async function runRecipe(){let r=parsedRecipe();if(r&&confirmed())await postRecipe('%s',r,true)}"
          "async function abortRecipe(){stopPolling();let r=await fetch('%s',{method:'POST'});stopPolling();"
          "statusBox().textContent=await r.text()}async function pollTransaction(){if(!transactionPolling)return;"
          "let r=await fetch('%s',{cache:'no-store'});if(!transactionPolling)return;"
          "if(!r.ok){setProfileReady(false);statusBox().textContent=await r.text();schedulePoll(1000);return}"
          "if(!profileReady){location.reload();return}setProfileReady(true);let j=await r.json();"
          "renderStatus(j);if(j.complete)stopPolling();else schedulePoll(200)}"
          "restoreRecipe();pollTransaction()</script>", snapshot, recording,
          static_cast<unsigned>(this->client_->forensic_recording_events_.size()),
          static_cast<unsigned>(this->client_->forensic_recording_events_dropped_), this->json_path_.c_str(),
          this->tree_path_.c_str(), this->recorder_json_path_.c_str(), this->recorder_start_path_.c_str(), disabled,
          this->recorder_stop_path_.c_str(), disabled, this->recorder_clear_path_.c_str(), disabled,
          transaction_panel.c_str(),
          this->client_->gatt_profile_hash_.c_str(), profile_ready ? "true" : "false",
          this->transaction_run_path_.c_str(),
          this->transaction_validate_path_.c_str(), this->transaction_run_path_.c_str(),
          this->transaction_abort_path_.c_str(), this->transaction_status_path_.c_str());
      request->send(200, "text/html; charset=utf-8", body.c_str());
      return;
    }

    if (request->method() == HTTP_POST) {
      if (!this->client_->forensic_snapshot_available_) {
        request->send(409, "text/plain; charset=utf-8", "Wait for HID_READY before using the recorder.\n");
        return;
      }
      if (request_url_is(request, this->transaction_validate_path_)) {
        this->handle_transaction_recipe_request_(request, false);
        return;
      }
      if (request_url_is(request, this->transaction_run_path_)) {
        this->handle_transaction_recipe_request_(request, true);
        return;
      }
      if (request_url_is(request, this->transaction_abort_path_)) {
        if (!this->client_->abort_forensic_transaction_()) {
          request->send(409, "text/plain; charset=utf-8", "No queued or running transaction can be aborted.\n");
        } else {
          this->send_transaction_status_(request);
        }
        return;
      }
      if (request_url_is(request, this->recorder_start_path_)) {
        this->client_->forensic_recording_events_.clear();
        this->client_->forensic_recording_events_dropped_ = 0;
        this->client_->forensic_next_recording_sequence_ = 1;
        this->client_->forensic_recording_started_ms_ = millis();
        this->client_->forensic_recording_active_ = true;
      } else if (request_url_is(request, this->recorder_stop_path_)) {
        this->client_->forensic_recording_active_ = false;
      } else {
        this->client_->forensic_recording_active_ = false;
        this->client_->forensic_recording_events_.clear();
        this->client_->forensic_recording_events_dropped_ = 0;
        this->client_->forensic_next_recording_sequence_ = 1;
      }
      request->send(204);
      return;
    }

    if (!this->client_->forensic_snapshot_available_) {
      request->send(409, "text/plain; charset=utf-8",
                    "No completed forensic snapshot is available. Connect and discover the BLE device first.\n");
      return;
    }

    if (request_url_is(request, this->tree_path_)) {
      auto *response = request->beginResponse(200, "text/plain; charset=utf-8");
      add_download_headers(response, "attachment; filename=ble-hid-gatt-tree.txt", this->client_->gatt_profile_hash_);
      ForensicResponseWriter writer(request);
      this->client_->render_gatt_tree_(writer);
      if (!writer.finish()) ESP_LOGW("ble_client_hid", "GATT tree download ended before completion");
      return;
    }

    if (request_url_is(request, this->transaction_status_path_)) {
      this->send_transaction_status_(request);
      return;
    }

    if (request_url_is(request, this->recorder_json_path_)) {
      if (this->client_->forensic_recording_active_) {
        request->send(409, "text/plain; charset=utf-8", "Stop the recorder before downloading events.\n");
        return;
      }
      auto *response = request->beginResponse(200, "application/json");
      add_download_headers(response, "attachment; filename=ble-hid-recorded-events.json",
                           this->client_->gatt_profile_hash_);
      ForensicResponseWriter writer(request);
      this->client_->render_recorder_json_(writer);
      if (!writer.finish()) ESP_LOGW("ble_client_hid", "Recorder download ended before completion");
      return;
    }

    auto *response = request->beginResponse(200, "application/json");
    add_profile_headers(response, this->client_->gatt_profile_hash_);
    ForensicResponseWriter writer(request);
    this->client_->render_gatt_json_(writer);
    if (!writer.finish()) ESP_LOGW("ble_client_hid", "GATT profile download ended before completion");
  }

 protected:
  BLEClientHID *client_;
  std::string base_path_;
  std::string tree_path_;
  std::string json_path_;
  std::string recorder_path_;
  std::string recorder_start_path_;
  std::string recorder_stop_path_;
  std::string recorder_clear_path_;
  std::string recorder_json_path_;
  std::string transaction_validate_path_;
  std::string transaction_run_path_;
  std::string transaction_abort_path_;
  std::string transaction_status_path_;
  ForensicRecipeBodyBuffer transaction_recipe_body_;

  static bool bounded_integer_(JsonObjectConst object, const char *key, size_t maximum, size_t &output,
                               std::string &error, bool required = true) {
    const JsonVariantConst value = object[key];
    if (value.isNull()) {
      if (!required) return false;
      error = std::string("Missing integer field: ") + key;
      return false;
    }
    if (!value.is<uint32_t>() || value.as<uint32_t>() > maximum) {
      error = std::string("Invalid integer field: ") + key;
      return false;
    }
    output = value.as<uint32_t>();
    return true;
  }

  static bool boolean_(JsonObjectConst object, const char *key, bool default_value, bool &output,
                       std::string &error) {
    const JsonVariantConst value = object[key];
    if (value.isNull()) {
      output = default_value;
      return true;
    }
    if (!value.is<bool>()) {
      error = std::string("Invalid boolean field: ") + key;
      return false;
    }
    output = value.as<bool>();
    return true;
  }

  static bool string_(JsonObjectConst object, const char *key, std::string &output, std::string &error,
                      bool required = true) {
    const JsonVariantConst value = object[key];
    if (value.isNull()) {
      if (!required) {
        output.clear();
        return true;
      }
      error = std::string("Missing string field: ") + key;
      return false;
    }
    if (!value.is<const char *>()) {
      error = std::string("Invalid string field: ") + key;
      return false;
    }
    output = value.as<const char *>();
    return true;
  }

  bool compile_target_(const std::string &name, JsonObjectConst object, ForensicTransactionTarget &target,
                       std::string &error) const {
    std::string kind;
    if (!string_(object, "kind", kind, error)) return false;
    size_t service_start = 0;
    size_t service_instance = 0;
    size_t characteristic_handle = 0;
    size_t attribute_handle = 0;
    if (!bounded_integer_(object, "service_start_handle", std::numeric_limits<uint16_t>::max(), service_start,
                          error) ||
        !bounded_integer_(object, "service_instance", std::numeric_limits<uint16_t>::max(), service_instance,
                          error) ||
        !bounded_integer_(object, "characteristic_handle", std::numeric_limits<uint16_t>::max(),
                          characteristic_handle, error))
      return false;
    const GattServiceInfo *selected_service = nullptr;
    for (const auto &service : this->client_->services_)
      if (service.start_handle == service_start && service.instance == service_instance) {
        selected_service = &service;
        break;
      }
    const GattCharacteristicInfo *selected_characteristic = nullptr;
    if (selected_service != nullptr)
      for (const auto &characteristic : selected_service->characteristics)
        if (characteristic.handle == characteristic_handle) {
          selected_characteristic = &characteristic;
          break;
        }
    if (selected_characteristic == nullptr) {
      error = "Target " + name + " does not resolve to the selected service and characteristic hierarchy.";
      return false;
    }
    target.name = name;
    target.service_start_handle = static_cast<uint16_t>(service_start);
    target.service_instance = static_cast<uint16_t>(service_instance);
    target.characteristic_handle = static_cast<uint16_t>(characteristic_handle);
    if (kind == "notification") {
      if ((selected_characteristic->properties &
           (ESP_GATT_CHAR_PROP_BIT_NOTIFY | ESP_GATT_CHAR_PROP_BIT_INDICATE)) == 0) {
        error = "Notification target " + name + " does not advertise Notify or Indicate.";
        return false;
      }
      target.kind = ForensicTargetKind::NOTIFICATION;
      target.attribute_handle = selected_characteristic->handle;
      target.notification_enabled = selected_characteristic->subscription_enabled;
      return true;
    }
    if (!bounded_integer_(object, "attribute_handle", std::numeric_limits<uint16_t>::max(), attribute_handle,
                          error))
      return false;
    target.attribute_handle = static_cast<uint16_t>(attribute_handle);
    std::string mode = "auto";
    if (!object["mode"].isNull() && !string_(object, "mode", mode, error)) return false;
    if (kind == "descriptor") {
      bool found = false;
      for (const auto &descriptor : selected_characteristic->descriptors)
        if (descriptor.handle == attribute_handle) found = true;
      if (!found) {
        error = "Descriptor target " + name + " is not nested below the selected characteristic.";
        return false;
      }
      if (mode != "auto" && mode != "response") {
        error = "Descriptor target " + name + " requires response mode.";
        return false;
      }
      target.kind = ForensicTargetKind::DESCRIPTOR;
      target.write_mode = ForensicWriteMode::WITH_RESPONSE;
      return true;
    }
    if (kind != "characteristic" || attribute_handle != characteristic_handle) {
      error = "Target " + name + " has an invalid kind or mismatched characteristic handles.";
      return false;
    }
    const bool supports_response = (selected_characteristic->properties & ESP_GATT_CHAR_PROP_BIT_WRITE) != 0;
    const bool supports_no_response = (selected_characteristic->properties & ESP_GATT_CHAR_PROP_BIT_WRITE_NR) != 0;
    if (mode == "auto") {
      if (supports_response) target.write_mode = ForensicWriteMode::WITH_RESPONSE;
      else if (supports_no_response) target.write_mode = ForensicWriteMode::WITHOUT_RESPONSE;
      else {
        error = "Characteristic target " + name + " does not advertise a write property.";
        return false;
      }
    } else if (mode == "response" && supports_response) {
      target.write_mode = ForensicWriteMode::WITH_RESPONSE;
    } else if (mode == "no_response" && supports_no_response) {
      target.write_mode = ForensicWriteMode::WITHOUT_RESPONSE;
    } else {
      error = "Write mode is unsupported by characteristic target " + name + ".";
      return false;
    }
    target.kind = ForensicTargetKind::CHARACTERISTIC;
    return true;
  }

  bool compile_value_(JsonVariantConst source, const std::map<std::string, size_t> &known_lengths,
                      std::vector<ForensicValuePart> &parts, std::string &error) const {
    parts.clear();
    if (source.is<const char *>()) {
      ForensicValuePart part;
      if (!parse_forensic_hex(source.as<const char *>(), this->client_->forensic_transaction_payload_limit_(),
                              part.literal, error))
        return false;
      parts.push_back(std::move(part));
      return true;
    }
    if (!source.is<JsonArrayConst>()) {
      error = "Step value must be a hex string or an array of value parts.";
      return false;
    }
    size_t total_length = 0;
    for (JsonVariantConst item : source.as<JsonArrayConst>()) {
      if (!item.is<JsonObjectConst>()) {
        error = "Each value part must be an object.";
        return false;
      }
      const JsonObjectConst object = item.as<JsonObjectConst>();
      ForensicValuePart part;
      if (object["hex"].is<const char *>()) {
        if (!object["var"].isNull() ||
            !parse_forensic_hex(object["hex"].as<const char *>(), FORENSIC_TRANSACTION_MAX_VALUE_BYTES,
                                part.literal, error, true))
          return false;
        total_length += part.literal.size();
      } else {
        if (!string_(object, "var", part.variable, error)) return false;
        const auto known = known_lengths.find(part.variable);
        if (known == known_lengths.end()) {
          error = "Value references a variable that is not available yet: " + part.variable;
          return false;
        }
        part.kind = ForensicValuePartKind::VARIABLE;
        size_t offset = 0;
        if (!object["offset"].isNull() &&
            !bounded_integer_(object, "offset", FORENSIC_TRANSACTION_MAX_VALUE_BYTES, offset, error))
          return false;
        part.offset = offset;
        if (part.offset > known->second) {
          error = "Variable value offset is outside: " + part.variable;
          return false;
        }
        if (object["length"].isNull()) {
          part.to_end = true;
          part.length = known->second - part.offset;
        } else {
          size_t length = 0;
          if (!bounded_integer_(object, "length", FORENSIC_TRANSACTION_MAX_VALUE_BYTES, length, error) ||
              length > known->second - part.offset) {
            error = "Variable value length is outside: " + part.variable;
            return false;
          }
          part.length = length;
        }
        total_length += part.length;
      }
      if (total_length > this->client_->forensic_transaction_payload_limit_()) {
        error = "Composed value exceeds the current ATT write limit.";
        return false;
      }
      parts.push_back(std::move(part));
    }
    if (parts.empty() || total_length == 0) {
      error = "Step value must compose at least one byte.";
      return false;
    }
    return true;
  }

  bool compile_matcher_(JsonObjectConst step_object, ForensicTransactionRecipe &recipe,
                        std::map<std::string, size_t> &known_lengths,
                        std::map<std::string, bool> &known_secrets, ForensicNotificationMatcher &matcher,
                        std::string &error) const {
    std::string target_name;
    if (!string_(step_object, "notification", target_name, error)) return false;
    const auto target = recipe.targets.find(target_name);
    if (target == recipe.targets.end() || target->second.kind != ForensicTargetKind::NOTIFICATION) {
      error = "Notification matcher references an invalid notification target: " + target_name;
      return false;
    }
    if (!target->second.notification_enabled) {
      error = "Notification target is not subscribed on this connection: " + target_name;
      return false;
    }
    matcher.handle = target->second.attribute_handle;
    std::string transport = "any";
    if (!step_object["transport"].isNull() && !string_(step_object, "transport", transport, error)) return false;
    if (transport == "notify") matcher.accept_indicate = false;
    else if (transport == "indicate") matcher.accept_notify = false;
    else if (transport != "any") {
      error = "Notification transport must be any, notify, or indicate.";
      return false;
    }
    if (!step_object["match"].is<JsonObjectConst>()) {
      error = "Notification step requires a match object.";
      return false;
    }
    const JsonObjectConst match = step_object["match"].as<JsonObjectConst>();
    size_t offset = 0;
    if (!match["offset"].isNull() &&
        !bounded_integer_(match, "offset", FORENSIC_TRANSACTION_MAX_VALUE_BYTES, offset, error))
      return false;
    matcher.offset = offset;
    if (!match["value"].isNull()) {
      if (!match["value"].is<const char *>() ||
          !parse_forensic_hex(match["value"].as<const char *>(), FORENSIC_TRANSACTION_MAX_VALUE_BYTES,
                              matcher.value, error, true))
        return false;
    }
    if (!match["mask"].isNull()) {
      if (!match["mask"].is<const char *>() ||
          !parse_forensic_hex(match["mask"].as<const char *>(), FORENSIC_TRANSACTION_MAX_VALUE_BYTES,
                              matcher.mask, error, true) || matcher.mask.size() != matcher.value.size()) {
        error = "Notification match mask must have the same byte length as value.";
        return false;
      }
    }
    if (!boolean_(match, "allow_any", false, matcher.allow_any, error)) return false;
    if (matcher.value.empty() && !matcher.allow_any) {
      error = "Notification match requires value bytes or explicit allow_any.";
      return false;
    }
    if (!match["exact_length"].isNull()) {
      size_t exact_length = 0;
      if (!bounded_integer_(match, "exact_length", FORENSIC_TRANSACTION_MAX_VALUE_BYTES, exact_length, error))
        return false;
      matcher.has_exact_length = true;
      matcher.exact_length = exact_length;
      if (matcher.offset > exact_length || matcher.value.size() > exact_length - matcher.offset) {
        error = "Notification match range exceeds exact_length.";
        return false;
      }
    }
    if (!step_object["capture"].isNull()) {
      if (!step_object["capture"].is<JsonArrayConst>()) {
        error = "Notification capture must be an array.";
        return false;
      }
      for (JsonVariantConst item : step_object["capture"].as<JsonArrayConst>()) {
        if (!item.is<JsonObjectConst>()) {
          error = "Each notification capture must be an object.";
          return false;
        }
        const JsonObjectConst object = item.as<JsonObjectConst>();
        ForensicNotificationCapture capture;
        if (!string_(object, "variable", capture.variable, error) ||
            !forensic_variable_name_valid(capture.variable) || known_lengths.count(capture.variable) != 0) {
          error = "Capture variable is invalid or already defined.";
          return false;
        }
        size_t capture_offset = 0;
        size_t capture_length = 0;
        if (!bounded_integer_(object, "offset", FORENSIC_TRANSACTION_MAX_VALUE_BYTES, capture_offset, error) ||
            !bounded_integer_(object, "length", FORENSIC_TRANSACTION_MAX_VALUE_BYTES, capture_length, error) ||
            capture_length == 0 || (matcher.has_exact_length &&
                                    (capture_offset > matcher.exact_length ||
                                     capture_length > matcher.exact_length - capture_offset))) {
          error = "Notification capture range is invalid.";
          return false;
        }
        capture.offset = capture_offset;
        capture.length = capture_length;
        if (!boolean_(object, "secret", false, capture.secret, error)) return false;
        if (known_lengths.size() >= FORENSIC_TRANSACTION_MAX_VARIABLES) {
          error = "Recipe exceeds the variable limit.";
          return false;
        }
        matcher.captures.push_back(capture);
        known_lengths[capture.variable] = capture.length;
        known_secrets[capture.variable] = capture.secret;
        ForensicTransactionVariable placeholder;
        placeholder.secret = capture.secret;
        recipe.variables[capture.variable] = std::move(placeholder);
      }
    }
    return true;
  }

  bool compile_recipe_(const std::string &source, ForensicTransactionRecipe &recipe, std::string &error) const {
    if (source.empty() || source.size() > FORENSIC_TRANSACTION_MAX_RECIPE_BYTES) {
      error = "Recipe is empty or exceeds the 16384-byte limit.";
      return false;
    }
    JsonDocument document = json::parse_json(reinterpret_cast<const uint8_t *>(source.data()), source.size());
    if (document.isNull() || document.overflowed() || !document.is<JsonObject>()) {
      error = "Recipe is not a valid JSON object.";
      return false;
    }
    const JsonObjectConst root = document.as<JsonObjectConst>();
    size_t version = 0;
    if (!bounded_integer_(root, "version", 1, version, error) || version != 1) {
      error = "Recipe version must be 1.";
      return false;
    }
    if (!string_(root, "name", recipe.name, error, false) || recipe.name.size() > 64) {
      error = "Recipe name must not exceed 64 characters.";
      return false;
    }
    if (recipe.name.empty()) recipe.name = "forensic transaction";
    if (!string_(root, "profile_hash", recipe.profile_hash, error) ||
        recipe.profile_hash != this->client_->gatt_profile_hash_) {
      error = "Recipe profile_hash does not match the connected GATT profile.";
      return false;
    }
    if (!root["targets"].is<JsonObjectConst>()) {
      error = "Recipe targets must be an object.";
      return false;
    }
    const JsonObjectConst targets = root["targets"].as<JsonObjectConst>();
    if (targets.size() == 0 || targets.size() > FORENSIC_TRANSACTION_MAX_TARGETS) {
      error = "Recipe must define between 1 and 24 targets.";
      return false;
    }
    for (JsonPairConst entry : targets) {
      const std::string name = entry.key().c_str();
      if (!forensic_variable_name_valid(name) || !entry.value().is<JsonObjectConst>()) {
        error = "Target names must be valid identifiers and target values must be objects.";
        return false;
      }
      ForensicTransactionTarget target;
      if (!compile_target_(name, entry.value().as<JsonObjectConst>(), target, error)) return false;
      recipe.targets[name] = std::move(target);
    }
    std::map<std::string, size_t> known_lengths;
    std::map<std::string, bool> known_secrets;
    if (!root["variables"].isNull()) {
      if (!root["variables"].is<JsonObjectConst>()) {
        error = "Recipe variables must be an object.";
        return false;
      }
      const JsonObjectConst variables = root["variables"].as<JsonObjectConst>();
      if (variables.size() > FORENSIC_TRANSACTION_MAX_VARIABLES) {
        error = "Recipe exceeds the variable limit.";
        return false;
      }
      for (JsonPairConst entry : variables) {
        const std::string name = entry.key().c_str();
        if (!forensic_variable_name_valid(name)) {
          error = "Variable name is invalid: " + name;
          return false;
        }
        std::string hex;
        bool secret = false;
        if (entry.value().is<const char *>()) {
          hex = entry.value().as<const char *>();
        } else if (entry.value().is<JsonObjectConst>()) {
          const JsonObjectConst object = entry.value().as<JsonObjectConst>();
          if (!string_(object, "hex", hex, error) || !boolean_(object, "secret", false, secret, error)) return false;
        } else {
          error = "Variable values must be hex strings or {hex, secret} objects.";
          return false;
        }
        ForensicTransactionVariable variable;
        if (!parse_forensic_hex(hex, FORENSIC_TRANSACTION_MAX_VALUE_BYTES, variable.value, error, true)) return false;
        variable.secret = secret;
        known_lengths[name] = variable.value.size();
        known_secrets[name] = secret;
        recipe.variables[name] = std::move(variable);
      }
    }
    if (!root["steps"].is<JsonArrayConst>()) {
      error = "Recipe steps must be an array.";
      return false;
    }
    const JsonArrayConst steps = root["steps"].as<JsonArrayConst>();
    if (steps.size() == 0 || steps.size() > FORENSIC_TRANSACTION_MAX_STEPS) {
      error = "Recipe must contain between 1 and 64 steps.";
      return false;
    }
    for (JsonVariantConst item : steps) {
      if (!item.is<JsonObjectConst>()) {
        error = "Each transaction step must be an object.";
        return false;
      }
      const JsonObjectConst object = item.as<JsonObjectConst>();
      std::string operation;
      if (!string_(object, "op", operation, error)) return false;
      ForensicTransactionStep step;
      if (operation == "write" || operation == "exchange") {
        step.kind = operation == "write" ? ForensicStepKind::WRITE : ForensicStepKind::EXCHANGE;
        if (!string_(object, "target", step.target, error)) return false;
        const auto target = recipe.targets.find(step.target);
        if (target == recipe.targets.end() || target->second.kind == ForensicTargetKind::NOTIFICATION) {
          error = "Write step references an invalid write target: " + step.target;
          return false;
        }
        if (!compile_value_(object["value"], known_lengths, step.value, error)) return false;
        if (operation == "exchange" &&
            !compile_matcher_(object, recipe, known_lengths, known_secrets, step.matcher, error))
          return false;
      } else if (operation == "wait_notification") {
        step.kind = ForensicStepKind::WAIT_NOTIFICATION;
        if (!compile_matcher_(object, recipe, known_lengths, known_secrets, step.matcher, error)) return false;
      } else if (operation == "require_notification") {
        step.kind = ForensicStepKind::REQUIRE_NOTIFICATION;
        if (!string_(object, "target", step.target, error)) return false;
        const auto target = recipe.targets.find(step.target);
        if (target == recipe.targets.end() || target->second.kind != ForensicTargetKind::NOTIFICATION) {
          error = "require_notification references an invalid notification target.";
          return false;
        }
        step.timeout_ms = 0;
      } else if (operation == "transform") {
        std::string algorithm;
        if (!string_(object, "algorithm", algorithm, error) || algorithm != "bt_e1") {
          error = "Registered transform algorithm must be bt_e1.";
          return false;
        }
        step.kind = ForensicStepKind::TRANSFORM_BT_E1;
        if (!string_(object, "key", step.key_variable, error) ||
            !string_(object, "random", step.random_variable, error) ||
            !string_(object, "address", step.address_variable, error) ||
            !string_(object, "output", step.output_variable, error) ||
            !forensic_variable_name_valid(step.output_variable) || known_lengths.count(step.output_variable) != 0 ||
            known_lengths[step.key_variable] != 16 || known_lengths[step.random_variable] != 16 ||
            known_lengths[step.address_variable] != 6) {
          error = "bt_e1 requires existing 16-byte key/random, 6-byte address, and a new output variable.";
          return false;
        }
        if (known_lengths.size() >= FORENSIC_TRANSACTION_MAX_VARIABLES) {
          error = "Recipe exceeds the variable limit.";
          return false;
        }
        known_lengths[step.output_variable] = 16;
        known_secrets[step.output_variable] = known_secrets[step.key_variable] || known_secrets[step.random_variable] ||
                                             known_secrets[step.address_variable];
        ForensicTransactionVariable placeholder;
        placeholder.secret = known_secrets[step.output_variable];
        recipe.variables[step.output_variable] = std::move(placeholder);
      } else if (operation == "random_bytes") {
        step.kind = ForensicStepKind::RANDOM_BYTES;
        size_t length = 0;
        if (!string_(object, "output", step.output_variable, error) ||
            !forensic_variable_name_valid(step.output_variable) || known_lengths.count(step.output_variable) != 0 ||
            !bounded_integer_(object, "length", FORENSIC_TRANSACTION_MAX_VALUE_BYTES, length, error) ||
            length == 0 || !boolean_(object, "secret", false, step.output_secret, error)) {
          error = "random_bytes requires a new output variable and a length between 1 and 512.";
          return false;
        }
        if (known_lengths.size() >= FORENSIC_TRANSACTION_MAX_VARIABLES) {
          error = "Recipe exceeds the variable limit.";
          return false;
        }
        step.output_length = length;
        known_lengths[step.output_variable] = length;
        known_secrets[step.output_variable] = step.output_secret;
        ForensicTransactionVariable placeholder;
        placeholder.secret = step.output_secret;
        recipe.variables[step.output_variable] = std::move(placeholder);
      } else if (operation == "assert_equal") {
        step.kind = ForensicStepKind::ASSERT_EQUAL;
        if (!string_(object, "left", step.left_variable, error) ||
            !string_(object, "right", step.right_variable, error) ||
            known_lengths.count(step.left_variable) == 0 || known_lengths.count(step.right_variable) == 0 ||
            known_lengths[step.left_variable] != known_lengths[step.right_variable]) {
          error = "assert_equal requires two available variables with equal lengths.";
          return false;
        }
      } else if (operation == "delay") {
        step.kind = ForensicStepKind::DELAY;
        size_t delay = 0;
        if (!bounded_integer_(object, "ms", FORENSIC_TRANSACTION_MAX_STEP_TIMEOUT_MS, delay, error) || delay == 0) {
          error = "Delay must be between 1 and 60000 ms.";
          return false;
        }
        step.delay_ms = delay;
        step.timeout_ms = 0;
      } else {
        error = "Unknown transaction operation: " + operation;
        return false;
      }
      if ((step.kind == ForensicStepKind::WRITE || step.kind == ForensicStepKind::EXCHANGE ||
           step.kind == ForensicStepKind::WAIT_NOTIFICATION) &&
          !object["timeout_ms"].isNull()) {
        size_t timeout = 0;
        if (!bounded_integer_(object, "timeout_ms", FORENSIC_TRANSACTION_MAX_STEP_TIMEOUT_MS, timeout, error) ||
            timeout == 0) {
          error = "Step timeout must be between 1 and 60000 ms.";
          return false;
        }
        step.timeout_ms = timeout;
      }
      recipe.steps.push_back(std::move(step));
    }
    return true;
  }

  static void append_json_string_(std::string &output, const std::string &value) {
    output.push_back('"');
    for (const unsigned char character : value) {
      switch (character) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
          if (character >= 0x20 && character < 0x7F) output.push_back(static_cast<char>(character));
          else output += str_sprintf("\\u%04x", character);
      }
    }
    output.push_back('"');
  }

  static std::string hex_(const std::vector<uint8_t> &value) {
    static constexpr char DIGITS[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(value.size() * 2);
    for (const uint8_t byte : value) {
      output.push_back(DIGITS[byte >> 4]);
      output.push_back(DIGITS[byte & 0x0F]);
    }
    return output;
  }

  void send_transaction_status_(AsyncWebServerRequest *request) const {
    const auto send_json = [this, request](const std::string &body) {
      auto *response = request->beginResponse(200, "application/json", body);
      if (request->arg("download") == "yes")
        add_download_headers(response, "attachment; filename=ble-hid-transaction-response.json",
                             this->client_->gatt_profile_hash_);
      else
        add_profile_headers(response, this->client_->gatt_profile_hash_);
      request->send(response);
    };
    const auto &status = this->client_->forensic_transaction_status_;
    if (!status.available) {
      send_json("{\"format\":\"ble-gatt-transaction-response\",\"available\":false,\"complete\":true}\n");
      return;
    }
    const uint32_t elapsed_ms = status.started_ms == 0
                                    ? 0
                                    : static_cast<uint32_t>((status.complete && status.finished_ms != 0
                                                                 ? status.finished_ms
                                                                 : millis()) -
                                                            status.started_ms);
    std::string body = "{\"format\":\"ble-gatt-transaction-response\",\"device_address\":";
    append_json_string_(body, this->client_->parent()->address_str());
    body += ",\"gatt_profile_sha256\":";
    append_json_string_(body, this->client_->gatt_profile_hash_);
    body += ",\"available\":true,\"sequence\":" + std::to_string(status.sequence) + ",\"name\":";
    append_json_string_(body, status.name);
    body += ",\"stage\":";
    append_json_string_(body, status.stage);
    body += ",\"message\":";
    append_json_string_(body, status.message);
    body += ",\"status_domain\":";
    append_json_string_(body, status.status_domain);
    body += ",\"status\":" + std::to_string(status.status) +
            ",\"current_step\":" + std::to_string(status.current_step) +
            ",\"total_steps\":" + std::to_string(status.total_steps) +
            ",\"elapsed_ms\":" + std::to_string(elapsed_ms) +
            ",\"complete\":" + (status.complete ? "true" : "false") +
            ",\"succeeded\":" + (status.succeeded ? "true" : "false") +
            ",\"abortable\":" + (status.abortable ? "true" : "false") +
            ",\"write_blocked\":" + (status.write_blocked ? "true" : "false") +
            ",\"reconnect_required\":" + (status.reconnect_required ? "true" : "false") +
            ",\"variables\":{";
    const std::map<std::string, ForensicTransactionVariable> *variables = nullptr;
    if (this->client_->forensic_transaction_active_ != nullptr)
      variables = &this->client_->forensic_transaction_active_->recipe.variables;
    else if (this->client_->forensic_transaction_pending_ != nullptr)
      variables = &this->client_->forensic_transaction_pending_->variables;
    else
      variables = &this->client_->forensic_transaction_result_variables_;
    bool first = true;
    for (const auto &entry : *variables) {
      if (!first) body.push_back(',');
      first = false;
      append_json_string_(body, entry.first);
      body += ":{\"secret\":" + std::string(entry.second.secret ? "true" : "false") +
              ",\"length\":" + std::to_string(entry.second.value.size()) + ",\"hex\":";
      if (entry.second.secret) body += "null";
      else append_json_string_(body, hex_(entry.second.value));
      body.push_back('}');
    }
    body += "},\"responses\":{\"state\":";
    append_json_string_(body, status.complete ? "stopped" : "capturing");
    const auto &responses = this->client_->forensic_transaction_responses_;
    body += ",\"capacity\":" + std::to_string(FORENSIC_TRANSACTION_MAX_RESPONSE_EVENTS) +
            ",\"retained\":" + std::to_string(responses.events().size()) +
            ",\"dropped\":" + std::to_string(responses.dropped()) +
            ",\"complete\":" + (status.complete && responses.complete() ? "true" : "false") +
            ",\"events\":[";
    for (size_t index = 0; index < responses.events().size(); index++) {
      if (index != 0) body.push_back(',');
      const auto &event = responses.events()[index];
      body += "{\"sequence\":" + std::to_string(event.sequence) +
              ",\"offset_ms\":" + std::to_string(event.offset_ms) +
              ",\"step\":" + std::to_string(event.step) + ",\"transport\":";
      append_json_string_(body, event.is_notify ? "notification" : "indication");
      body += ",\"handle\":" + std::to_string(event.handle) + ",\"handle_hex\":";
      append_json_string_(body, str_sprintf("0x%04X", event.handle));
      body += ",\"characteristic_uuid\":";
      const auto *characteristic = this->client_->find_characteristic_(event.handle);
      if (characteristic == nullptr) body += "null";
      else append_json_string_(body, BLEClientHID::uuid_string_(characteristic->uuid));
      body += ",\"matched\":" + std::string(event.matched ? "true" : "false") + ",\"value_hex\":";
      append_json_string_(body, hex_(event.value));
      body += ",\"length\":" + std::to_string(event.value.size()) + ",\"truncated\":false}";
    }
    body += "]}}\n";
    send_json(body);
  }

  void handle_transaction_recipe_request_(AsyncWebServerRequest *request, bool run) {
    std::string source;
    if (this->transaction_recipe_body_.started()) {
      if (this->transaction_recipe_body_.too_large()) {
        this->transaction_recipe_body_.reset();
        request->send(413, "text/plain; charset=utf-8", "Recipe exceeds the 16384-byte limit.\n");
        return;
      }
      if (!this->transaction_recipe_body_.complete()) {
        this->transaction_recipe_body_.reset();
        request->send(400, "text/plain; charset=utf-8", "Recipe request body is incomplete or malformed.\n");
        return;
      }
      source = this->transaction_recipe_body_.take();
    } else {
      source = request->arg("recipe");
    }
    this->handle_transaction_recipe_(request, run, source);
  }

  void handle_transaction_recipe_(AsyncWebServerRequest *request, bool run, const std::string &source) {
    if (run && request->arg("confirm") != "yes") {
      request->send(422, "text/plain; charset=utf-8", "Explicit confirmation is required.\n");
      return;
    }
    ForensicTransactionRecipe recipe;
    std::string error;
    if (!compile_recipe_(source, recipe, error)) {
      error.push_back('\n');
      request->send(422, "text/plain; charset=utf-8", error.c_str());
      return;
    }
    if (!run) {
      std::string response = "{\"valid\":true,\"name\":";
      append_json_string_(response, recipe.name);
      response += ",\"targets\":" + std::to_string(recipe.targets.size()) +
                  ",\"steps\":" + std::to_string(recipe.steps.size()) + "}\n";
      request->send(200, "application/json", response.c_str());
      return;
    }
    if (this->client_->forensic_transaction_pending_ != nullptr ||
        this->client_->forensic_transaction_active_ != nullptr ||
        this->client_->forensic_gatt_write_active_ != nullptr ||
        this->client_->forensic_transaction_reconnect_required_) {
      request->send(409, "text/plain; charset=utf-8",
                    this->client_->forensic_transaction_reconnect_required_
                        ? "Reconnect the BLE peripheral before starting another transaction.\n"
                        : "Another transaction or GATT response is still active.\n");
      return;
    }
    recipe.sequence = this->client_->forensic_next_transaction_sequence_++;
    ForensicTransactionStatus status;
    status.available = true;
    status.sequence = recipe.sequence;
    status.name = recipe.name;
    status.stage = "queued";
    status.message = "Recipe validated and queued.";
    status.status_domain = "local";
    status.status = 0;
    status.current_step = 1;
    status.total_steps = recipe.steps.size();
    status.abortable = true;
    this->client_->forensic_transaction_status_ = std::move(status);
    this->client_->forensic_transaction_result_variables_.clear();
    this->client_->forensic_transaction_responses_.reset();
    this->client_->forensic_transaction_pending_ = std::make_unique<ForensicTransactionRecipe>(std::move(recipe));
    this->send_transaction_status_(request);
  }
};

void BLEClientHID::publish_forensic_snapshot_() {
  if (!this->forensic_web_logging_enabled_() || this->discovery_mode_ != DiscoveryMode::FORENSIC) {
    return;
  }
  LockGuard forensic_guard(this->forensic_export_mutex_);
  this->forensic_capture_completed_ms_ = millis();
  this->forensic_snapshot_available_ = true;
}

void BLEClientHID::record_forensic_operation_(const char *type, const char *stage, uint16_t handle,
                                               uint16_t related_handle, const char *status_domain, int status,
                                               bool complete, bool succeeded, const uint8_t *value, size_t length,
                                               bool value_redacted) {
  if (!this->forensic_web_logging_enabled_() || this->discovery_mode_ != DiscoveryMode::FORENSIC) return;
  LockGuard forensic_guard(this->forensic_export_mutex_);
  this->record_forensic_operation_locked_(type, stage, handle, related_handle, status_domain, status, complete,
                                          succeeded, value, length, value_redacted);
}

void BLEClientHID::record_forensic_operation_locked_(const char *type, const char *stage, uint16_t handle,
                                                      uint16_t related_handle, const char *status_domain, int status,
                                                      bool complete, bool succeeded, const uint8_t *value,
                                                      size_t length, bool value_redacted) {
  const bool recorder_event = std::strcmp(type, "notification") == 0 || std::strcmp(type, "indication") == 0;
  if (recorder_event) {
    if (!this->forensic_recording_active_) return;
    if (this->forensic_recording_events_.size() >= MAX_FORENSIC_OPERATIONS) {
      this->forensic_recording_events_dropped_++;
      return;
    }
    ForensicOperation event;
    event.sequence = this->forensic_next_recording_sequence_++;
    event.offset_ms = millis() - this->forensic_recording_started_ms_;
    event.type = type;
    event.stage = stage;
    event.handle = handle;
    event.related_handle = related_handle;
    event.status_domain = status_domain;
    event.status = status;
    event.complete = complete;
    event.succeeded = succeeded;
    event.value_length = length;
    event.value_redacted = value_redacted;
    const size_t stored_length = std::min(length, MAX_FORENSIC_OPERATION_VALUE_BYTES);
    event.value_truncated = length > stored_length;
    if (!value_redacted && value != nullptr && stored_length != 0) event.value.assign(value, value + stored_length);
    this->forensic_recording_events_.push_back(std::move(event));
    return;
  }
  if (this->forensic_operations_.size() >= MAX_FORENSIC_OPERATIONS) {
    this->forensic_operations_dropped_++;
    return;
  }
  ForensicOperation operation;
  operation.sequence = this->forensic_next_operation_sequence_++;
  operation.offset_ms = millis() - this->forensic_capture_started_ms_;
  operation.type = type;
  operation.stage = stage;
  operation.handle = handle;
  operation.related_handle = related_handle;
  operation.status_domain = status_domain;
  operation.status = status;
  operation.complete = complete;
  operation.succeeded = succeeded;
  operation.value_length = length;
  operation.value_redacted = value_redacted;
  const size_t stored_length = std::min(length, MAX_FORENSIC_OPERATION_VALUE_BYTES);
  operation.value_truncated = length > stored_length;
  if (!value_redacted && value != nullptr && stored_length != 0) operation.value.assign(value, value + stored_length);
  this->forensic_operations_.push_back(std::move(operation));
}

void register_forensic_web_handler(BLEClientHID *client, const std::string &base_path) {
  if (web_server_base::global_web_server_base == nullptr) {
    return;
  }
  web_server_base::global_web_server_base->add_handler(new ForensicWebHandler(client, base_path));
}

}  // namespace ble_client_hid
}  // namespace esphome

#endif
