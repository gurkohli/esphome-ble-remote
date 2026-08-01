#include "ble_client_hid.h"

#include "usages.h"
#include "esphome/core/helpers.h"

#ifdef USE_ESP32

namespace esphome {
namespace ble_client_hid {

static const char *const TAG = "ble_client_hid";

void BLEClientHID::loop() {
  switch (this->hid_state) {
    case HIDState::BLE_CONNECTED:
      this->hid_state = HIDState::READING_CHARS;
      this->read_client_characteristics();  // not instant, finished when
                                            // hid_state = HIDState::READ_CHARS
      break;
    case HIDState::READ_CHARS:
      this->configure_hid_client();
      this->hid_state = this->handles_waiting_for_notify_registration.empty()
                            ? HIDState::NOTIFICATIONS_REGISTERED
                            : HIDState::NOTIFICATIONS_REGISTERING;
      break;
    case HIDState::NOTIFICATIONS_REGISTERED:
      if (this->preferred_conn_params_valid_ && esp_ble_gap_update_conn_params(&this->preferred_conn_params) != ESP_OK)
        ESP_LOGW(TAG, "Failed to request preferred connection parameters");
      // Connection parameter optimization is optional and its GAP callback can
      // be absent. Do not block HID readiness on it.
      this->hid_state = HIDState::CONFIGURATION_COMPLETE;
      this->node_state = espbt::ClientState::ESTABLISHED;
      break;
    default:
      break;
  }
}

void BLEClientHID::dump_config() {
  ESP_LOGCONFIG(TAG, "BLE Client HID:");
  ESP_LOGCONFIG(TAG, "  MAC address        : %s",
                this->parent()->address_str());
}

void BLEClientHID::gap_event_handler(esp_gap_ble_cb_event_t event,
  esp_ble_gap_cb_param_t *param) {
   switch (event)
   {
   case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT:
    if (memcmp(param->update_conn_params.bda, this->parent()->get_remote_bda(), 6) != 0)
      break;
    ESP_LOGI(TAG, "Updated conn params to interval=%.2f ms, latency=%u, timeout=%.1f ms", param->update_conn_params.conn_int * 1.25f, param->update_conn_params.latency, param->update_conn_params.timeout * 10.f);
    this->hid_state = HIDState::CONFIGURATION_COMPLETE;
    this->node_state = espbt::ClientState::ESTABLISHED;
    /* code */
     break;
   default:
     break;
   }
  }

void BLEClientHID::read_client_characteristics() {
  ESP_LOGD(TAG, "Reading client characteristics");
  using namespace ble_client;
  BLEService *battery_service =
      this->parent()->get_service(ESP_GATT_UUID_BATTERY_SERVICE_SVC);
  BLEService *device_info_service =
      this->parent()->get_service(ESP_GATT_UUID_DEVICE_INFO_SVC);

  BLEService *hid_service = this->parent()->get_service(ESP_GATT_UUID_HID_SVC);
  BLEService *generic_access_service = this->parent()->get_service(0x1800);

  if (generic_access_service != nullptr) {
    BLECharacteristic *device_name_char =
        generic_access_service->get_characteristic(
            ESP_GATT_UUID_GAP_DEVICE_NAME);
    BLECharacteristic *pref_conn_params_char = generic_access_service->get_characteristic(ESP_GATT_UUID_GAP_PREF_CONN_PARAM);
    this->schedule_read_char(pref_conn_params_char);
    this->schedule_read_char(device_name_char);
  }
  if (device_info_service != nullptr) {
    BLECharacteristic *pnp_id_char =
        device_info_service->get_characteristic(ESP_GATT_UUID_PNP_ID);
    this->schedule_read_char(pnp_id_char);
    BLECharacteristic *manufacturer_char =
        device_info_service->get_characteristic(ESP_GATT_UUID_MANU_NAME);
    this->schedule_read_char(manufacturer_char);
    BLECharacteristic *serial_number_char =
        device_info_service->get_characteristic(
            ESP_GATT_UUID_SERIAL_NUMBER_STR);
    this->schedule_read_char(serial_number_char);
  }
  if (hid_service != nullptr) {
    BLECharacteristic *hid_report_map_char =
        hid_service->get_characteristic(ESP_GATT_UUID_HID_REPORT_MAP);
    this->schedule_read_char(hid_report_map_char);
    ESP_LOGD(TAG, "Found %d characteristics",
             hid_service->characteristics.size());
    for (auto *chr : hid_service->characteristics) {
      if (chr->uuid.get_uuid().uuid.uuid16 != ESP_GATT_UUID_HID_REPORT) {
        continue;
      }

      BLEDescriptor *rpt_ref_desc =
          chr->get_descriptor(ESP_GATT_UUID_RPT_REF_DESCR);
      if (rpt_ref_desc != nullptr) {
        this->schedule_read_descriptor(rpt_ref_desc);
      }
    }
  }
  this->finish_pending_reads_();
}
void BLEClientHID::on_gatt_read_finished(GATTReadData *data) {
  std::map<uint16_t, GATTReadData *>::iterator itr;
  itr = this->handles_to_read.find(data->handle_);
  if (itr != this->handles_to_read.end()) {
    delete itr->second;
    itr->second = data;
  } else {
    delete data;
    return;
  }
  this->finish_pending_reads_();
}

void BLEClientHID::finish_pending_reads_() {
  // check if all handles have been read:
  for (auto const &element : this->handles_to_read) {
    if (element.second == nullptr) {
      return;
    }
  }
  this->hid_state = HIDState::READ_CHARS;
}

void BLEClientHID::gattc_event_handler(esp_gattc_cb_event_t event,
                                       esp_gatt_if_t gattc_if,
                                       esp_ble_gattc_cb_param_t *param) {
  if (param == nullptr || (gattc_if != ESP_GATT_IF_NONE && gattc_if != this->parent()->get_gattc_if()))
    return;
  esp_ble_gattc_cb_param_t *p_data = param;
  switch (event) {
    case ESP_GATTC_CONNECT_EVT: {
      auto ret = esp_ble_set_encryption(param->connect.remote_bda,
                                        ESP_BLE_SEC_ENCRYPT);
      if (ret) {
        ESP_LOGE(TAG, "[%d] [%s] esp_ble_set_encryption error, status=%d",
                 this->parent()->get_connection_index(),
                 this->parent()->address_str(), ret);
      }
      esp_gap_conn_params_t params;
      ret = esp_ble_get_current_conn_params(
          this->parent()->get_remote_bda(), &params);
      if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to get conn params");
      } else {
        ESP_LOGI(TAG, "conn params: interval=%u, latency=%u, timeout=%u",
                 params.interval, params.latency, params.timeout);
      }
      break;
    }
    case ESP_GATTC_DISCONNECT_EVT: {
      ESP_LOGW(TAG, "[%s] Disconnected!",
               this->parent()->address_str());
      this->status_set_warning("Diconnected");
      this->handles_waiting_for_notify_registration.clear();
      this->preferred_conn_params_valid_ = false;
      this->battery_handle = 0;
      this->handle_report_source.clear();
      this->hid_report_handles_.clear();
      for (auto &entry : this->handles_to_read)
        delete entry.second;
      this->handles_to_read.clear();
      delete this->hid_report_map;
      this->hid_report_map = nullptr;
      this->hid_state = HIDState::INIT;
      break;
    }
    case ESP_GATTC_SEARCH_RES_EVT: {
      if (p_data->search_res.srvc_id.uuid.len == ESP_UUID_LEN_16 && p_data->search_res.srvc_id.uuid.uuid.uuid16 ==
          ESP_GATT_UUID_HID_SVC) {
        this->hid_state = HIDState::HID_SERVICE_FOUND;
        ESP_LOGD(TAG, "GATT HID service found on device %s",
                 this->parent()->address_str());
      }
      break;
    }
    case ESP_GATTC_SEARCH_CMPL_EVT: {
      if (p_data->search_cmpl.status != ESP_GATT_OK || this->hid_state != HIDState::HID_SERVICE_FOUND) {
        // service not found
        ESP_LOGW(TAG, "No GATT HID service found on device %s",
                 this->parent()->address_str());
        this->hid_state = HIDState::NO_HID_SERVICE;
        this->status_set_warning("Invalid device config");
        break;
      }
      ESP_LOGD(TAG, "GATTC search finished with status code %d",
               p_data->search_cmpl.status);
      this->hid_state = HIDState::BLE_CONNECTED;
      esp_gap_conn_params_t params;
      esp_err_t ret = esp_ble_get_current_conn_params(
          this->parent()->get_remote_bda(), &params);
      if (ret != ESP_OK) {
        ESP_LOGW(TAG, "Failed to get conn params");
      } else {
        ESP_LOGI(TAG, "conn params: interval=%u, latency=%u, timeout=%u",
                 params.interval, params.latency, params.timeout);
      }
      break;
    }
    case ESP_GATTC_READ_CHAR_EVT:
    case ESP_GATTC_READ_DESCR_EVT: {
      if (param->read.conn_id != this->parent()->get_conn_id()) break;
      if (param->read.status != ESP_OK) {
        ESP_LOGW(TAG, "GATTC read failed for handle %u with status code %d",
                 param->read.handle, param->read.status);
        auto pending = this->handles_to_read.find(param->read.handle);
        if (pending != this->handles_to_read.end()) {
          delete pending->second;
          this->handles_to_read.erase(pending);
          this->finish_pending_reads_();
        }
        break;
      }
      GATTReadData *data = new GATTReadData(
          param->read.handle, param->read.value, param->read.value_len);
      this->on_gatt_read_finished(data);
      break;
    }
    case ESP_GATTC_NOTIFY_EVT: {
      if (param->notify.conn_id != this->parent()->get_conn_id()) break;
      if (p_data->notify.handle == this->battery_handle) {
        if (p_data->notify.value == nullptr || p_data->notify.value_len < 1) {
          ESP_LOGW(TAG, "Empty battery notification");
          break;
        }
        uint8_t battery_level = p_data->notify.value[0];
        if (this->battery_sensor == nullptr) {
          break;
        }
        this->battery_sensor->publish_state(battery_level);
      } else if (this->hid_report_handles_.count(p_data->notify.handle) != 0) {
        this->send_input_report_event(p_data);
      } else {
        ESP_LOGD(TAG, "Ignoring notification for unrelated handle %u", p_data->notify.handle);
      }
      break;
    }
    case ESP_GATTC_REG_FOR_NOTIFY_EVT: {
      if (param->reg_for_notify.status != ESP_GATT_OK) {
        ESP_LOGW(TAG, "Notification registration failed for handle %u, status=%d",
                 param->reg_for_notify.handle, param->reg_for_notify.status);
      }
      this->handles_waiting_for_notify_registration.erase(param->reg_for_notify.handle);
      if(this->handles_waiting_for_notify_registration.empty()){
        this->hid_state = HIDState::NOTIFICATIONS_REGISTERED;
      }
      break;
    }
    default: {
      break;
    }
  }
}

void BLEClientHID::send_input_report_event(esp_ble_gattc_cb_param_t *p_data) {
  const uint32_t timestamp = millis();
  HIDReportSource source;
  source.characteristic_handle = p_data->notify.handle;
  source.is_notification = p_data->notify.is_notify;
  source.has_transport = true;
  auto report_source = this->handle_report_source.find(p_data->notify.handle);
  if (report_source != this->handle_report_source.end()) {
    const bool is_notification = source.is_notification;
    source = report_source->second;
    source.is_notification = is_notification;
    source.has_transport = true;
  }
  const std::string raw =
      format_hex_pretty(p_data->notify.value, p_data->notify.value_len);
  if (source.has_report_id) {
    ESP_LOGD(TAG, "HID_RAW handle=%u report_id=%u report_type=%s transport=%s len=%u data=%s",
             source.characteristic_handle, source.report_id,
             source.has_report_type ? (source.report_type == 1 ? "input" : source.report_type == 2 ? "output" :
                                       source.report_type == 3 ? "feature" : "unknown") : "unknown",
             p_data->notify.is_notify ? "notification" : "indication",
             p_data->notify.value_len, raw.c_str());
  } else {
    ESP_LOGD(TAG, "HID_RAW handle=%u uuid=0x%04X report_id=unknown report_type=unknown transport=%s len=%u data=%s",
             source.characteristic_handle, source.characteristic_uuid,
             p_data->notify.is_notify ? "notification" : "indication", p_data->notify.value_len,
             raw.c_str());
  }
  std::vector<HIDReportItemValue> hid_report_values;
  if (this->hid_report_map != nullptr && p_data->notify.value != nullptr) {
    hid_report_values = this->hid_report_map->parse(source, p_data->notify.value,
                                                    p_data->notify.value_len);
  } else {
    ESP_LOGW(TAG, "Cannot parse HID notification: report map or payload unavailable");
  }
  std::vector<HIDEvent> events;
  for (HIDReportItemValue value : hid_report_values) {
    std::string usage;
    if (USAGE_PAGES.count(value.usage.page) > 0 &&
        USAGE_PAGES.at(value.usage.page).usages_.count(value.usage.usage) > 0) {
      usage = USAGE_PAGES.at(value.usage.page).usages_.at(value.usage.usage);
    } else {
      usage = std::to_string(value.usage.page) + "_" +
              std::to_string(value.usage.usage);
    }
    HIDEvent event;
    event.data = {{"device", this->parent()->address_str()},
                  {"handle", std::to_string(source.characteristic_handle)},
                  {"characteristic_uuid", std::to_string(source.characteristic_uuid)},
                  {"report_id", source.has_report_id ? std::to_string(source.report_id) : "unknown"},
                  {"hid_report_type", source.has_report_type ?
                       (source.report_type == 1 ? "input" : source.report_type == 2 ? "output" :
                        source.report_type == 3 ? "feature" : "unknown") : "unknown"},
                  {"transport", source.has_transport ? (source.is_notification ? "notification" : "indication") : "unknown"},
                  {"length", std::to_string(p_data->notify.value_len)},
                  {"raw_data", raw},
                  {"timestamp", std::to_string(timestamp)},
                  {"usage", usage},
                  {"usage_page", std::to_string(value.usage.page)},
                  {"usage_id", std::to_string(value.usage.usage)},
                  {"value", std::to_string(value.value)},
                  {"raw_value", std::to_string(value.raw_value)},
                  {"relative", value.is_relative ? "true" : "false"}};
    events.push_back(event);
    if(this->last_event_usage_text_sensor != nullptr){
      this->last_event_usage_text_sensor->publish_state(usage);
    }
    if(this->last_event_code_text_sensor != nullptr){
      std::string event_code = std::to_string(value.usage.page) + "_" +
                               std::to_string(value.usage.usage);
      this->last_event_code_text_sensor->publish_state(event_code);
    }
    if (this->last_event_value_sensor != nullptr) {
      this->last_event_value_sensor->publish_state(value.value);
    }
  }
  if (events.empty()) {
    HIDEvent event;
    event.data = {{"device", this->parent()->address_str()},
                  {"handle", std::to_string(source.characteristic_handle)},
                  {"characteristic_uuid", std::to_string(source.characteristic_uuid)},
                  {"report_id", source.has_report_id ? std::to_string(source.report_id) : "unknown"},
                  {"hid_report_type", source.has_report_type ?
                       (source.report_type == 1 ? "input" : source.report_type == 2 ? "output" :
                        source.report_type == 3 ? "feature" : "unknown") : "unknown"},
                  {"transport", source.has_transport ? (source.is_notification ? "notification" : "indication") : "unknown"},
                  {"length", std::to_string(p_data->notify.value_len)},
                  {"raw_data", raw},
                  {"timestamp", std::to_string(timestamp)}};
    events.push_back(event);
  }
  this->emit_hid_events(events);
}

void BLEClientHID::emit_hid_events(const std::vector<HIDEvent> &events) {
  for (const auto &event : events) {
#ifdef USE_API
    this->fire_homeassistant_event("esphome.hid_events", event.data);
#endif
    std::string summary;
    for (const auto &field : event.data) {
      if (!summary.empty())
        summary += " ";
      summary += field.first + "=" + field.second;
    }
    ESP_LOGI(TAG, "HID event: %s", summary.c_str());
  }
}

void BLEClientHID::register_last_event_value_sensor(
    sensor::Sensor *last_event_value_sensor) {
  this->last_event_value_sensor = last_event_value_sensor;
}

void BLEClientHID::register_battery_sensor(sensor::Sensor *battery_sensor) {
  this->battery_sensor = battery_sensor;
}

void BLEClientHID::register_last_event_usage_text_sensor(
    text_sensor::TextSensor *last_event_usage_text_sensor) {
  this->last_event_usage_text_sensor = last_event_usage_text_sensor;
}

void BLEClientHID::register_last_event_code_text_sensor(
    text_sensor::TextSensor *last_event_code_text_sensor) {
  this->last_event_code_text_sensor = last_event_code_text_sensor;
}

void BLEClientHID::schedule_read_char(
    ble_client::BLECharacteristic *characteristic) {
  if (characteristic == nullptr)
    return;
  if ((characteristic->properties & ESP_GATT_CHAR_PROP_BIT_READ) == 0) {
    ESP_LOGD(TAG, "Characteristic handle %u is not readable", characteristic->handle);
    return;
  }
  const esp_err_t status = esp_ble_gattc_read_char(
      this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
      characteristic->handle, ESP_GATT_AUTH_REQ_NO_MITM);
  if (status != ESP_OK) {
    ESP_LOGW(TAG, "Failed to schedule characteristic read for handle %u: %d",
             characteristic->handle, status);
    return;
  }
  this->handles_to_read.emplace(characteristic->handle, nullptr);
}

void BLEClientHID::schedule_read_descriptor(ble_client::BLEDescriptor *descriptor) {
  if (descriptor == nullptr)
    return;
  const esp_err_t status = esp_ble_gattc_read_char_descr(
      this->parent()->get_gattc_if(), this->parent()->get_conn_id(),
      descriptor->handle, ESP_GATT_AUTH_REQ_NO_MITM);
  if (status != ESP_OK) {
    ESP_LOGW(TAG, "Failed to schedule descriptor read for handle %u: %d", descriptor->handle, status);
    return;
  }
  this->handles_to_read.emplace(descriptor->handle, nullptr);
}

GATTReadData *BLEClientHID::get_characteristic_data(
    ble_client::BLEService *service, uint16_t uuid) {
  if (service == nullptr)
    return nullptr;
  using namespace ble_client;
  BLECharacteristic *characteristic = service->get_characteristic(uuid);
  if (characteristic == nullptr) {
    ESP_LOGD(TAG, "No characteristic with uuid %#X found on device", uuid);
    return nullptr;
  }
  auto read = this->handles_to_read.find(characteristic->handle);
  if (read != this->handles_to_read.end() && read->second != nullptr) {
    ESP_LOGD(TAG, "Characteristic parsed for uuid %#X, handle %#X, length %u",
             uuid, characteristic->handle, read->second->value_len_);
    return read->second;
  }
  ESP_LOGD(TAG,
           "Characteristic with uuid %#X and handle %#X not stored in "
           "handles_to_read",
           uuid, characteristic->handle);
  return nullptr;
}

bool BLEClientHID::register_for_notifications_(ble_client::BLECharacteristic *characteristic) {
  if (characteristic == nullptr)
    return false;
  if ((characteristic->properties & (ESP_GATT_CHAR_PROP_BIT_NOTIFY | ESP_GATT_CHAR_PROP_BIT_INDICATE)) == 0)
    return false;
  const esp_err_t status = esp_ble_gattc_register_for_notify(
      this->parent()->get_gattc_if(), this->parent()->get_remote_bda(), characteristic->handle);
  if (status != ESP_OK) {
    ESP_LOGW(TAG, "Register for notify failed for handle %u with status=%d", characteristic->handle, status);
    return false;
  }
  this->handles_waiting_for_notify_registration.insert(characteristic->handle);
  return true;
}

void BLEClientHID::configure_hid_client() {
  using namespace ble_client;
  BLEService *battery_service =
      this->parent()->get_service(ESP_GATT_UUID_BATTERY_SERVICE_SVC);
  BLEService *device_info_service =
      this->parent()->get_service(ESP_GATT_UUID_DEVICE_INFO_SVC);
  BLEService *hid_service = this->parent()->get_service(ESP_GATT_UUID_HID_SVC);
  BLEService *generic_access_service = this->parent()->get_service(0x1800);

  if (generic_access_service != nullptr) {
    GATTReadData *data = this->get_characteristic_data(
        generic_access_service, ESP_GATT_UUID_GAP_DEVICE_NAME);
    if (data != nullptr) {
      this->device_name.assign(reinterpret_cast<const char *>(data->value_), data->value_len_);
    } else {
      this->device_name = "Generic";
    }
  }
  if (battery_service != nullptr) {
    BLECharacteristic *battery_level_char =
        battery_service->get_characteristic(ESP_GATT_UUID_BATTERY_LEVEL);
    if (battery_level_char != nullptr &&
        ((battery_level_char->properties & ESP_GATT_CHAR_PROP_BIT_NOTIFY) !=
         0)) {
      this->battery_handle = battery_level_char->handle;
      this->register_for_notifications_(battery_level_char);
    }
  }
  if (device_info_service != nullptr) {
    GATTReadData *pnp = this->get_characteristic_data(device_info_service, ESP_GATT_UUID_PNP_ID);
    if (pnp != nullptr && pnp->value_len_ >= 7) {
      this->vendor_id = static_cast<uint16_t>(pnp->value_[1]) | (static_cast<uint16_t>(pnp->value_[2]) << 8);
      this->product_id = static_cast<uint16_t>(pnp->value_[3]) | (static_cast<uint16_t>(pnp->value_[4]) << 8);
      this->version = static_cast<uint16_t>(pnp->value_[5]) | (static_cast<uint16_t>(pnp->value_[6]) << 8);
    } else if (pnp != nullptr) {
      ESP_LOGW(TAG, "PnP ID has invalid length %u", pnp->value_len_);
    }

    GATTReadData *manufacturer = this->get_characteristic_data(
        device_info_service, ESP_GATT_UUID_MANU_NAME);
    if (manufacturer != nullptr) {
      this->manufacturer.assign(reinterpret_cast<const char *>(manufacturer->value_), manufacturer->value_len_);
    } else {
      this->manufacturer = "Generic";
    }

    GATTReadData *serial = this->get_characteristic_data(
        device_info_service, ESP_GATT_UUID_SERIAL_NUMBER_STR);
    if (serial != nullptr) {
      this->serial_number.assign(reinterpret_cast<const char *>(serial->value_), serial->value_len_);
    } else {
      this->serial_number = "000000";
    }
  }
  if (hid_service != nullptr) {
    GATTReadData *report_map = this->get_characteristic_data(hid_service, ESP_GATT_UUID_HID_REPORT_MAP);
    if (report_map != nullptr && report_map->value_len_ > 0) {
      ESP_LOGD(TAG, "Parse HID Report Map");
      const std::string raw_map = format_hex_pretty(report_map->value_, report_map->value_len_);
      ESP_LOGI(TAG, "HID_REPORT_MAP len=%u data=%s", report_map->value_len_, raw_map.c_str());
      HIDReportMap::esp_logd_report_map(report_map->value_, report_map->value_len_);
      delete this->hid_report_map;
      this->hid_report_map = HIDReportMap::parse_report_map_data(report_map->value_, report_map->value_len_);
      ESP_LOGD(TAG, "Parse HID Report Map Done");
    } else {
      ESP_LOGE(TAG, "Readable HID Report Map is missing or empty");
    }
    std::vector<BLECharacteristic *> chars = hid_service->characteristics;
    for (BLECharacteristic *hid_char : chars) {
      if (hid_char->uuid.get_uuid().len != ESP_UUID_LEN_16)
        continue;
      const uint16_t characteristic_uuid = hid_char->uuid.get_uuid().uuid.uuid16;
      ESP_LOGI(TAG, "HID characteristic uuid=0x%04X handle=%u properties=0x%02X",
               characteristic_uuid, hid_char->handle, hid_char->properties);
      if (characteristic_uuid == ESP_GATT_UUID_HID_REPORT) {
        this->hid_report_handles_.insert(hid_char->handle);
        BLEDescriptor *rpt_ref_desc =
            hid_char->get_descriptor(ESP_GATT_UUID_RPT_REF_DESCR);
        if (rpt_ref_desc != nullptr) {
          auto report_reference = this->handles_to_read.find(rpt_ref_desc->handle);
          if (report_reference == this->handles_to_read.end() || report_reference->second == nullptr ||
              report_reference->second->value_len_ != 2) {
            ESP_LOGW(TAG, "Invalid Report Reference descriptor for handle %d", hid_char->handle);
            continue;
          }
          HIDReportSource source;
          source.characteristic_handle = hid_char->handle;
          source.characteristic_uuid = characteristic_uuid;
          source.report_id = report_reference->second->value_[0];
          source.has_report_id = true;
          source.report_type = report_reference->second->value_[1];
          source.has_report_type = true;
          this->handle_report_source[hid_char->handle] = source;
          ESP_LOGD(TAG, "Report ID for handle %d is %d, type %d", hid_char->handle,
                   source.report_id, source.report_type);
        } else {
          ESP_LOGW(TAG, "HID Report characteristic handle %u has no Report Reference descriptor",
                   hid_char->handle);
        }
        // Subscribe to every notifiable Report characteristic, including an
        // unknown or nonconforming Report Type, so unexpected device traffic
        // remains visible in raw logging instead of being silently missed.
        this->register_for_notifications_(hid_char);
      } else if (characteristic_uuid == ESP_GATT_UUID_HID_BT_KB_INPUT ||
                 characteristic_uuid == ESP_GATT_UUID_HID_BT_MOUSE_INPUT) {
        HIDReportSource source;
        source.characteristic_handle = hid_char->handle;
        source.characteristic_uuid = characteristic_uuid;
        source.report_type = 1;
        source.has_report_type = true;
        this->handle_report_source[hid_char->handle] = source;
        this->hid_report_handles_.insert(hid_char->handle);
        ESP_LOGI(TAG, "HID Boot Input characteristic uuid=0x%04X handle=%u properties=0x%02X",
                 characteristic_uuid, hid_char->handle, hid_char->properties);
        this->register_for_notifications_(hid_char);
      }
    }
  }
  if(generic_access_service != nullptr){
    GATTReadData *conn = this->get_characteristic_data(generic_access_service, ESP_GATT_UUID_GAP_PREF_CONN_PARAM);
    if(conn != nullptr && conn->value_len_ >= 8){
      const uint8_t *value = conn->value_;
      this->preferred_conn_params.min_int = value[0] | (value[1] << 8);
      this->preferred_conn_params.max_int = value[2] | (value[3] << 8);
      this->preferred_conn_params.latency = value[4] | (value[5] << 8);
      this->preferred_conn_params.timeout = value[6] | (value[7] << 8);
      memcpy(this->preferred_conn_params.bda, this->parent()->get_remote_bda(), 6);
      this->preferred_conn_params_valid_ = true;
      ESP_LOGI(TAG, "Got preferred connection paramters: interval: %.2f - %.2f ms, latency: %u, timeout: %.1f ms", preferred_conn_params.min_int * 1.25f, preferred_conn_params.max_int * 1.25f, preferred_conn_params.latency, preferred_conn_params.timeout*10.f);
    } else if (conn != nullptr) {
      ESP_LOGW(TAG, "Preferred connection parameters have invalid length %u", conn->value_len_);
    }
  }
  // delete read data:
  for (auto &kv : this->handles_to_read) {
    delete kv.second;
  }
  this->handles_to_read.clear();
}

}  // namespace ble_client_hid
}  // namespace esphome
#endif
