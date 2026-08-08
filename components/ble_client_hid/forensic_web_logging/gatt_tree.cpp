#include <algorithm>
#include <cctype>
#include <set>
#include <string>

#include "../ble_client_hid.h"
#include "../usages.h"
#include "esphome/components/web_server_base/web_server_base.h"
#include "esphome/core/helpers.h"

#if defined(USE_ESP32) && defined(USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING)

namespace esphome {
namespace ble_client_hid {

namespace {

constexpr uint16_t UUID_GAP_SERVICE = 0x1800;
constexpr uint16_t UUID_GATT_SERVICE = 0x1801;
constexpr uint16_t UUID_DEVICE_INFORMATION_SERVICE = 0x180A;
constexpr uint16_t UUID_BATTERY_SERVICE = 0x180F;
constexpr uint16_t UUID_HID_SERVICE = 0x1812;

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

uint16_t uuid16_value(const espbt::ESPBTUUID &uuid) {
  const esp_bt_uuid_t raw = uuid.get_uuid();
  return raw.len == ESP_UUID_LEN_16 ? raw.uuid.uuid16 : 0;
}

const char *service_name(uint16_t uuid) {
  switch (uuid) {
    case UUID_GAP_SERVICE: return "Generic Access";
    case UUID_GATT_SERVICE: return "Generic Attribute";
    case UUID_DEVICE_INFORMATION_SERVICE: return "Device Information";
    case UUID_BATTERY_SERVICE: return "Battery";
    case UUID_HID_SERVICE: return "Human Interface Device";
    default: return "unknown";
  }
}

const char *characteristic_name(uint16_t uuid) {
  switch (uuid) {
    case UUID_DEVICE_NAME: return "Device Name";
    case UUID_APPEARANCE: return "Appearance";
    case UUID_PREFERRED_CONNECTION_PARAMETERS: return "Peripheral Preferred Connection Parameters";
    case UUID_SERVICE_CHANGED: return "Service Changed";
    case UUID_SYSTEM_ID: return "System ID";
    case UUID_MODEL_NUMBER: return "Model Number";
    case UUID_SERIAL_NUMBER: return "Serial Number";
    case UUID_FIRMWARE_REVISION: return "Firmware Revision";
    case UUID_HARDWARE_REVISION: return "Hardware Revision";
    case UUID_SOFTWARE_REVISION: return "Software Revision";
    case UUID_MANUFACTURER_NAME: return "Manufacturer Name";
    case UUID_IEEE_CERTIFICATION: return "IEEE Certification Data";
    case UUID_BATTERY_LEVEL: return "Battery Level";
    case UUID_PNP_ID: return "PnP ID";
    case UUID_HID_INFORMATION: return "HID Information";
    case UUID_HID_REPORT_MAP: return "Report Map";
    case UUID_HID_REPORT: return "Report";
    case UUID_HID_PROTOCOL_MODE: return "Protocol Mode";
    case UUID_BOOT_KEYBOARD_INPUT: return "Boot Keyboard Input Report";
    case UUID_BOOT_KEYBOARD_OUTPUT: return "Boot Keyboard Output Report";
    case UUID_BOOT_MOUSE_INPUT: return "Boot Mouse Input Report";
    case UUID_DATABASE_HASH: return "Database Hash";
    case UUID_CLIENT_SUPPORTED_FEATURES: return "Client Supported Features";
    case UUID_SERVER_SUPPORTED_FEATURES: return "Server Supported Features";
    default: return "unknown";
  }
}

const char *descriptor_name(uint16_t uuid) {
  switch (uuid) {
    case UUID_CHARACTERISTIC_USER_DESCRIPTION: return "Characteristic User Description";
    case UUID_CCCD: return "Client Characteristic Configuration";
    case UUID_CHARACTERISTIC_PRESENTATION_FORMAT: return "Characteristic Presentation Format";
    case UUID_CHARACTERISTIC_AGGREGATE_FORMAT: return "Characteristic Aggregate Format";
    case UUID_EXTERNAL_REPORT_REFERENCE: return "External Report Reference";
    case UUID_REPORT_REFERENCE: return "Report Reference";
    default: return "unknown";
  }
}

const char *collection_type_name(uint8_t type) {
  switch (type) {
    case 0: return "physical";
    case 1: return "application";
    case 2: return "logical";
    case 3: return "report";
    case 4: return "named_array";
    case 5: return "usage_switch";
    case 6: return "usage_modifier";
    default: return "unknown_or_vendor_defined";
  }
}

const char *ad_type_name(uint8_t type) {
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
  for (size_t i = 0; i < length; i++) result.push_back(std::isprint(data[i]) != 0 ? static_cast<char>(data[i]) : '.');
  return result;
}

std::string short_uuid(const espbt::ESPBTUUID &uuid) {
  const uint16_t value = uuid16_value(uuid);
  if (value != 0) return str_sprintf("0x%04X", value);
  char buffer[espbt::UUID_STR_LEN];
  return uuid.as_128bit().to_str(buffer);
}

std::string hex16(uint16_t value) { return str_sprintf("0x%04X", value); }

std::string property_names(uint8_t properties) {
  std::string result;
  const auto append = [&result](const char *name) {
    if (!result.empty()) result += "|";
    result += name;
  };
  if ((properties & ESP_GATT_CHAR_PROP_BIT_BROADCAST) != 0) append("broadcast");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_READ) != 0) append("read");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_WRITE_NR) != 0) append("write_without_response");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_WRITE) != 0) append("write");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_NOTIFY) != 0) append("notify");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_INDICATE) != 0) append("indicate");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_AUTH) != 0) append("authenticated_signed_write");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_EXT_PROP) != 0) append("extended");
  return result.empty() ? "none" : result;
}

}  // namespace

void BLEClientHID::render_gatt_tree_(ForensicResponseWriter &response) {
  if (this->discovery_mode_ != DiscoveryMode::FORENSIC) return;

  const auto append_line = [&response](const std::string &line) {
    response.print(line);
    response.write('\n');
  };
  const auto metadata = [this](const char *key) -> std::string {
    const auto found = this->device_metadata_.find(key);
    return found == this->device_metadata_.end() ? "<unavailable>" : found->second;
  };
  const auto read_value = [](bool planned, bool complete, bool succeeded, int status, size_t length, bool truncated,
                             const std::vector<uint8_t> &value, bool readable) -> std::string {
    if (!planned) return readable ? "<unavailable: not read>" : "<unavailable: not readable>";
    if (!complete) return "<unavailable: read incomplete>";
    if (!succeeded) return str_sprintf("<unavailable: read failed status=%d>", status);
    const std::string formatted = BLEClientHID::format_value_(value.data(), value.size());
    return str_sprintf("len=%u data=%s%s", static_cast<unsigned>(length), formatted.c_str(),
                       truncated ? " <truncated; complete value is in GATT_VALUE>" : "");
  };
  const auto usage_text = [](HIDUsage usage) -> std::string {
    const char *name = lookup_usage_name(usage.page, usage.usage);
    return str_sprintf("page=%u (0x%04X) id=%u (0x%04X) name=%s", usage.page, usage.page, usage.usage, usage.usage,
                       name == nullptr ? "unknown" : name);
  };
  const auto advertisement_fields = [&append_line](const uint8_t *data, size_t length, const std::string &prefix) {
    if (length == 0) {
      append_line(prefix + "`-- <none>");
      return;
    }
    size_t offset = 0;
    size_t index = 0;
    while (offset < length) {
      const size_t field_offset = offset;
      const uint8_t field_length = data[offset++];
      if (field_length == 0) {
        append_line(prefix + str_sprintf("`-- Field[%u] offset=%u terminator", static_cast<unsigned>(index),
                                         static_cast<unsigned>(field_offset)));
        return;
      }
      if (field_length > length - offset) {
        append_line(prefix +
                    str_sprintf("`-- Field[%u] offset=%u <unavailable: truncated declared_len=%u remaining=%u>",
                                static_cast<unsigned>(index), static_cast<unsigned>(field_offset), field_length,
                                static_cast<unsigned>(length - offset)));
        return;
      }
      const uint8_t type = data[offset++];
      const size_t value_length = field_length - 1U;
      const uint8_t *value = data + offset;
      std::string decoded = "unknown";
      if (type == 0x08 || type == 0x09) {
        decoded = "text=" + printable_text(value, value_length);
      } else if (type == 0x01 && value_length == 1) {
        decoded = str_sprintf("flags=0x%02X", value[0]);
      } else if (type == 0x0A && value_length == 1) {
        decoded = str_sprintf("tx_power=%d dBm", static_cast<int8_t>(value[0]));
      } else if (type == 0x19 && value_length == 2) {
        decoded = str_sprintf("appearance=%u (0x%04X)", value[0] | (static_cast<uint16_t>(value[1]) << 8U),
                              value[0] | (static_cast<uint16_t>(value[1]) << 8U));
      } else if (type == 0xFF && value_length >= 2) {
        decoded = str_sprintf("company_id=%u (0x%04X)", value[0] | (static_cast<uint16_t>(value[1]) << 8U),
                              value[0] | (static_cast<uint16_t>(value[1]) << 8U));
      } else if ((type == 0x02 || type == 0x03) && value_length >= 2) {
        decoded.clear();
        for (size_t uuid_offset = 0; uuid_offset + 1U < value_length; uuid_offset += 2U) {
          if (!decoded.empty()) decoded += ",";
          decoded += str_sprintf("0x%04X", value[uuid_offset] | (static_cast<uint16_t>(value[uuid_offset + 1U]) << 8U));
        }
        decoded = "uuid16_list=" + decoded;
      } else if (type == 0x16 && value_length >= 2) {
        decoded = str_sprintf("service_uuid=0x%04X", value[0] | (static_cast<uint16_t>(value[1]) << 8U));
      }
      append_line(prefix + str_sprintf("|-- Field[%u] offset=%u type=0x%02X name=%s len=%u data=%s decoded=%s",
                                       static_cast<unsigned>(index), static_cast<unsigned>(field_offset), type,
                                       ad_type_name(type), static_cast<unsigned>(value_length),
                                       BLEClientHID::format_value_(value, value_length).c_str(), decoded.c_str()));
      offset += value_length;
      index++;
    }
  };
  const auto unresolved_handles = [](const GattServiceInfo &service) -> std::string {
    std::set<uint16_t> known;
    known.insert(service.start_handle);
    for (const auto &include : service.included_services) known.insert(include.declaration_handle);
    for (const auto &characteristic : service.characteristics) {
      if (characteristic.handle > service.start_handle) known.insert(characteristic.handle - 1U);
      known.insert(characteristic.handle);
      for (const auto &descriptor : characteristic.descriptors) known.insert(descriptor.handle);
    }
    std::string result;
    uint32_t range_start = UINT32_MAX;
    uint32_t previous = UINT32_MAX;
    const auto append_range = [&result](uint32_t first, uint32_t last) {
      if (!result.empty()) result += ",";
      result += first == last ? std::to_string(first) : std::to_string(first) + "-" + std::to_string(last);
    };
    for (uint32_t handle = service.start_handle; handle <= service.end_handle; handle++) {
      if (known.count(static_cast<uint16_t>(handle)) != 0) continue;
      if (range_start == UINT32_MAX) range_start = handle;
      if (previous != UINT32_MAX && handle != previous + 1U) {
        append_range(range_start, previous);
        range_start = handle;
      }
      previous = handle;
    }
    if (range_start != UINT32_MAX) append_range(range_start, previous);
    return result.empty() ? "none" : result;
  };

  size_t characteristic_count = 0;
  size_t descriptor_count = 0;
  size_t include_count = 0;
  size_t readable_count = 0;
  size_t writable_count = 0;
  size_t notifiable_count = 0;
  size_t indicatable_count = 0;
  for (const auto &service : this->services_) {
    characteristic_count += service.characteristics.size();
    include_count += service.included_services.size();
    for (const auto &characteristic : service.characteristics) {
      descriptor_count += characteristic.descriptors.size();
      if ((characteristic.properties & ESP_GATT_CHAR_PROP_BIT_READ) != 0) readable_count++;
      if ((characteristic.properties & (ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_WRITE_NR)) != 0)
        writable_count++;
      if ((characteristic.properties & ESP_GATT_CHAR_PROP_BIT_NOTIFY) != 0) notifiable_count++;
      if ((characteristic.properties & ESP_GATT_CHAR_PROP_BIT_INDICATE) != 0) indicatable_count++;
    }
  }

  append_line(std::string("Device address=") + this->parent()->address_str());
  append_line("|-- Capture boundary: static profile finalized after HID_READY");
  append_line("|-- Identity");
  append_line("|   |-- Name: " + metadata("name"));
  append_line("|   |-- Appearance: " + metadata("appearance"));
  append_line("|   |-- Manufacturer: " + metadata("manufacturer"));
  append_line("|   |-- Model number: " + metadata("model_number"));
  append_line("|   |-- Serial number: " + metadata("serial_number") + " [privacy-sensitive]");
  append_line("|   |-- Hardware revision: " + metadata("hardware_revision"));
  append_line("|   |-- Firmware revision: " + metadata("firmware_revision"));
  append_line("|   |-- Software revision: " + metadata("software_revision"));
  append_line("|   |-- System ID: " + metadata("system_id"));
  append_line("|   |-- IEEE certification: " + metadata("ieee_certification"));
  append_line("|   `-- PnP ID: " + metadata("pnp_id"));

  append_line("|-- Advertising");
  append_line(str_sprintf("|   |-- Address type: %u (%s)", this->last_address_type_,
                          this->last_address_type_ == 0   ? "public"
                          : this->last_address_type_ == 1 ? "random"
                                                          : "unknown"));
  append_line(str_sprintf("|   |-- Last RSSI: %d dBm", this->last_rssi_));
  if (this->last_advertisement_length_ == 0) {
    append_line("|   |-- Advertisement data: <unavailable>");
    append_line("|   `-- Scan response data: <unavailable>");
  } else {
    append_line(
        str_sprintf("|   |-- Advertisement data: len=%u data=%s", this->last_advertisement_data_length_,
                    format_value_(this->last_advertisement_.data(), this->last_advertisement_data_length_).c_str()));
    append_line("|   |-- Advertisement fields");
    advertisement_fields(this->last_advertisement_.data(), this->last_advertisement_data_length_, "|   |   ");
    append_line(str_sprintf("|   |-- Scan response data: len=%u data=%s", this->last_scan_response_length_,
                            format_value_(this->last_advertisement_.data() + this->last_advertisement_data_length_,
                                          this->last_scan_response_length_)
                                .c_str()));
    append_line("|   `-- Scan response fields");
    advertisement_fields(this->last_advertisement_.data() + this->last_advertisement_data_length_,
                         this->last_scan_response_length_, "|       ");
  }

  append_line("|-- Device state");
  append_line("|   |-- Battery: " + metadata("battery"));
  append_line("|   |-- Preferred connection parameters: " + metadata("preferred_connection_parameters"));
  append_line(this->negotiated_mtu_available_ ? str_sprintf("|   |-- Negotiated ATT MTU: %u status=%d",
                                                            this->negotiated_mtu_, this->negotiated_mtu_status_)
                                              : "|   |-- Negotiated ATT MTU: <unavailable>");
  append_line(
      this->negotiated_conn_params_available_
          ? str_sprintf("|   |-- Active connection parameters: interval=%.2fms latency=%u timeout=%.1fms status=%d",
                        this->negotiated_interval_ms_, this->negotiated_latency_, this->negotiated_timeout_ms_,
                        this->negotiated_conn_params_status_)
          : "|   |-- Active connection parameters: <unavailable>");
  append_line("|   |-- Link security details: <unavailable: owned by BLE client stack>");
  append_line("|   |-- HID information: " + metadata("hid_information"));
  append_line("|   |-- Protocol mode read from device: " + metadata("protocol_mode"));
  append_line(std::string("|   |-- Protocol mode policy: ") +
              (this->protocol_mode_policy_ == ProtocolModePolicy::REPORT ? "report"
               : this->protocol_mode_policy_ == ProtocolModePolicy::BOOT ? "boot"
                                                                         : "unchanged"));
  append_line(str_sprintf("|   `-- Setup: status=%s operations_succeeded=%u operations_failed=%u",
                          this->hid_services_.empty() ? "NO_HID"
                          : this->degraded_           ? "DEGRADED"
                                                      : "OK",
                          static_cast<unsigned>(this->operations_succeeded_),
                          static_cast<unsigned>(this->operations_failed_)));

  append_line(str_sprintf("|-- Capability summary: readable=%u writable=%u notify=%u indicate=%u",
                          static_cast<unsigned>(readable_count), static_cast<unsigned>(writable_count),
                          static_cast<unsigned>(notifiable_count), static_cast<unsigned>(indicatable_count)));
  append_line("|   `-- Permissions remain unknown; properties describe supported procedures, not ATT authorization");
  append_line("|-- Writable control surface");
  for (const auto &service : this->services_) {
    for (const auto &characteristic : service.characteristics) {
      if ((characteristic.properties & (ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_WRITE_NR)) == 0)
        continue;
      append_line(str_sprintf("|   |-- handle=%u (%s) service=%s characteristic=%s (%s) procedures=%s",
                              characteristic.handle, hex16(characteristic.handle).c_str(),
                              short_uuid(service.uuid).c_str(), short_uuid(characteristic.uuid).c_str(),
                              characteristic_name(uuid16_value(characteristic.uuid)),
                              property_names(characteristic.properties).c_str()));
    }
  }
  append_line("|   `-- Unknown/vendor writes require controlled experiments; no payload semantics are inferred");

  append_line("|-- Database-level gaps");
  bool found_database_gap = false;
  for (size_t index = 0; index + 1U < this->services_.size(); index++) {
    const auto &current = this->services_[index];
    const auto &next = this->services_[index + 1U];
    if (current.end_handle + 1U >= next.start_handle) continue;
    found_database_gap = true;
    append_line(str_sprintf("|   |-- handles=%u-%u (%s-%s) not covered by a discovered service",
                            current.end_handle + 1U, next.start_handle - 1U,
                            hex16(current.end_handle + 1U).c_str(), hex16(next.start_handle - 1U).c_str()));
  }
  if (!found_database_gap) append_line("|   `-- none");

  append_line(
      str_sprintf("`-- GATT Database services=%u included_services=%u characteristics=%u descriptors=%u fingerprint=%s",
                  static_cast<unsigned>(this->services_.size()), static_cast<unsigned>(include_count),
                  static_cast<unsigned>(characteristic_count), static_cast<unsigned>(descriptor_count),
                  this->gatt_profile_hash_.empty() ? "<unavailable>" : this->gatt_profile_hash_.c_str()));

  for (size_t service_index = 0; service_index < this->services_.size(); service_index++) {
    const auto &service = this->services_[service_index];
    const bool last_service = service_index + 1U == this->services_.size();
    const std::string service_branch = last_service ? "    `-- " : "    |-- ";
    const std::string service_prefix = last_service ? "        " : "    |   ";
    const uint16_t service_uuid = uuid16_value(service.uuid);
    append_line(service_branch + str_sprintf("Service[%u] name=%s uuid=%s type=%s declaration_handle=%u (%s) handles=%u-%u (%s-%s)",
                                             service.instance, service_name(service_uuid),
                                             short_uuid(service.uuid).c_str(),
                                             service.primary ? "primary" : "secondary", service.start_handle,
                                             hex16(service.start_handle).c_str(), service.start_handle,
                                             service.end_handle, hex16(service.start_handle).c_str(),
                                             hex16(service.end_handle).c_str()));
    append_line(service_prefix + "|-- Permissions: <unknown: not exposed by cached GATT inventory>");
    append_line(service_prefix + "|-- Unresolved attribute handles in service range: " + unresolved_handles(service));

    for (const auto &include : service.included_services)
      append_line(service_prefix +
                  str_sprintf("|-- Included Service name=%s uuid=%s declaration_handle=%u handles=%u-%u",
                              service_name(uuid16_value(include.uuid)), short_uuid(include.uuid).c_str(),
                              include.declaration_handle, include.start_handle, include.end_handle));

    for (size_t characteristic_index = 0; characteristic_index < service.characteristics.size();
         characteristic_index++) {
      const auto &characteristic = service.characteristics[characteristic_index];
      const bool last_characteristic = characteristic_index + 1U == service.characteristics.size();
      const std::string characteristic_branch = last_characteristic ? "`-- " : "|-- ";
      const std::string characteristic_prefix = service_prefix + (last_characteristic ? "    " : "|   ");
      const uint16_t characteristic_uuid = uuid16_value(characteristic.uuid);
      append_line(service_prefix + characteristic_branch +
                  str_sprintf("Characteristic name=%s uuid=%s declaration_handle=%u (%s, inferred) value_handle=%u (%s) properties=0x%02X "
                              "[%s] permissions=unknown",
                              characteristic_name(characteristic_uuid), short_uuid(characteristic.uuid).c_str(),
                              characteristic.handle == 0 ? 0 : characteristic.handle - 1U,
                              hex16(characteristic.handle == 0 ? 0 : characteristic.handle - 1U).c_str(),
                              characteristic.handle, hex16(characteristic.handle).c_str(),
                              characteristic.properties, property_names(characteristic.properties).c_str()));
      append_line(characteristic_prefix + "|-- Value: " +
                  read_value(characteristic.read_planned, characteristic.read_complete, characteristic.read_succeeded,
                             characteristic.read_status, characteristic.value_length, characteristic.value_truncated,
                             characteristic.value, (characteristic.properties & ESP_GATT_CHAR_PROP_BIT_READ) != 0));

      if (characteristic.subscription_planned) {
        const std::string state = !characteristic.subscription_complete ? "incomplete"
                                  : characteristic.subscription_enabled ? "enabled"
                                                                        : "failed";
        append_line(characteristic_prefix +
                    str_sprintf("|-- Subscription: state=%s cccd_handle=%u (%s) final_status=%d",
                                state.c_str(), characteristic.cccd_handle, hex16(characteristic.cccd_handle).c_str(),
                                characteristic.subscription_status));
        append_line(characteristic_prefix +
                    str_sprintf("|   |-- Registration: complete=%s succeeded=%s status=%d",
                                characteristic.registration_complete ? "true" : "false",
                                characteristic.registration_succeeded ? "true" : "false",
                                characteristic.registration_status));
        append_line(characteristic_prefix +
                    str_sprintf("|   |-- CCCD write: complete=%s succeeded=%s status=%d",
                                characteristic.cccd_write_complete ? "true" : "false",
                                characteristic.cccd_write_succeeded ? "true" : "false",
                                characteristic.cccd_write_status));
      } else if ((characteristic.properties & (ESP_GATT_CHAR_PROP_BIT_NOTIFY | ESP_GATT_CHAR_PROP_BIT_INDICATE)) != 0) {
        append_line(characteristic_prefix + "|-- Subscription: <not attempted>");
      }

      const auto source_entry = this->handle_report_source_.find(characteristic.handle);
      if (source_entry != this->handle_report_source_.end()) {
        const HIDReportSource &source = source_entry->second;
        std::string schema = "unknown";
        if (source.has_report_id && source.has_report_type && source.report_type >= 1 && source.report_type <= 3) {
          const HIDServiceContext *context = this->find_hid_context_(source.service_instance);
          const HIDReportKind kind = static_cast<HIDReportKind>(source.report_type);
          schema = context != nullptr && context->report_map != nullptr &&
                           context->report_map->find_report(kind, source.report_id) != nullptr
                       ? "defined"
                       : "missing";
        }
        append_line(characteristic_prefix +
                    str_sprintf("|-- HID Report identity: report_id=%s report_type=%s schema=%s transport=%s",
                                source.has_report_id ? std::to_string(source.report_id).c_str() : "unknown",
                                source.has_report_type && source.report_type >= 1 && source.report_type <= 3
                                    ? hid_report_kind_name(static_cast<HIDReportKind>(source.report_type))
                                    : "unknown",
                                schema.c_str(),
                                (characteristic.properties & ESP_GATT_CHAR_PROP_BIT_NOTIFY) != 0     ? "notify"
                                : (characteristic.properties & ESP_GATT_CHAR_PROP_BIT_INDICATE) != 0 ? "indicate"
                                                                                                     : "unknown"));
      }

      for (size_t descriptor_index = 0; descriptor_index < characteristic.descriptors.size(); descriptor_index++) {
        const auto &descriptor = characteristic.descriptors[descriptor_index];
        const uint16_t descriptor_uuid = uuid16_value(descriptor.uuid);
        append_line(characteristic_prefix + str_sprintf("|-- Descriptor name=%s uuid=%s handle=%u (%s) permissions=unknown",
                                                        descriptor_name(descriptor_uuid),
                                                        short_uuid(descriptor.uuid).c_str(), descriptor.handle,
                                                        hex16(descriptor.handle).c_str()));
        append_line(characteristic_prefix + "|   `-- Value: " +
                    read_value(descriptor.read_planned, descriptor.read_complete, descriptor.read_succeeded,
                               descriptor.read_status, descriptor.value_length, descriptor.value_truncated,
                               descriptor.value, true));
      }

      if (characteristic_uuid == UUID_HID_REPORT_MAP) {
        const HIDServiceContext *context = this->find_hid_context_(service.instance);
        if (context == nullptr || context->report_map == nullptr) {
          append_line(characteristic_prefix + "`-- Parsed HID schema: <unavailable>");
        } else {
          append_line(characteristic_prefix +
                      str_sprintf("`-- Parsed HID schema hash=%s valid=%s reports=%u fields=%u collections=%u",
                                  context->report_map_hash.c_str(), context->report_map->valid() ? "true" : "false",
                                  static_cast<unsigned>(context->report_map->reports().size()),
                                  static_cast<unsigned>(context->report_map->fields().size()),
                                  static_cast<unsigned>(context->report_map->collections().size())));
          for (const auto &collection : context->report_map->collections()) {
            append_line(characteristic_prefix +
                        str_sprintf("    |-- Collection id=%u parent=%s type=%u (%s) usage={%s}", collection.id,
                                    collection.parent == HIDCollectionSchema::NO_PARENT
                                        ? "none"
                                        : std::to_string(collection.parent).c_str(),
                                    collection.type, collection_type_name(collection.type),
                                    usage_text(collection.usage).c_str()));
          }
          for (const auto &report : context->report_map->reports()) {
            append_line(characteristic_prefix + str_sprintf("    |-- Report kind=%s id=%u bits=%u bytes=%u fields=%u",
                                                            hid_report_kind_name(report.kind), report.report_id,
                                                            static_cast<unsigned>(report.bit_size),
                                                            static_cast<unsigned>(report.byte_size()),
                                                            static_cast<unsigned>(report.field_ids.size())));
            for (uint16_t field_id : report.field_ids) {
              const HIDFieldSchema *field = context->report_map->find_field(field_id);
              if (field == nullptr) {
                append_line(characteristic_prefix + str_sprintf("    |   |-- Field id=%u <unavailable>", field_id));
                continue;
              }
              const HIDUsage application = context->report_map->application_usage(field->collection_id);
              append_line(
                  characteristic_prefix +
                  str_sprintf(
                      "    |   |-- Field id=%u collection=%s bit_offset=%u size=%u count=%u flags=0x%03X data_kind=%s "
                      "value_kind=%s logical=%lld..%lld physical=%lld..%lld unit=0x%08X unit_exp=%d application={%s}",
                      field->id,
                      field->collection_id == HIDCollectionSchema::NO_PARENT
                          ? "unknown"
                          : std::to_string(field->collection_id).c_str(),
                      static_cast<unsigned>(field->bit_offset), static_cast<unsigned>(field->report_size),
                      static_cast<unsigned>(field->report_count), field->flags,
                      field->is_constant()   ? "constant"
                      : field->is_variable() ? "variable"
                                             : "array",
                      field->is_relative() ? "relative" : "absolute", static_cast<long long>(field->logical.minimum),
                      static_cast<long long>(field->logical.maximum), static_cast<long long>(field->physical.minimum),
                      static_cast<long long>(field->physical.maximum), static_cast<unsigned>(field->unit),
                      field->unit_exponent, usage_text(application).c_str()));
              const size_t element_count = std::min<size_t>(field->report_count, MAX_TREE_FIELD_ELEMENTS);
              for (size_t element = 0; element < element_count; element++)
                append_line(characteristic_prefix +
                            str_sprintf("    |   |   |-- Element[%u] bit_offset=%u usage={%s}",
                                        static_cast<unsigned>(element),
                                        static_cast<unsigned>(field->bit_offset + element * field->report_size),
                                        usage_text(field->usage_at(element, true)).c_str()));
              if (field->report_count > element_count)
                append_line(characteristic_prefix +
                            str_sprintf("    |   |   `-- ... %u elements omitted by tree limit",
                                        static_cast<unsigned>(field->report_count - element_count)));
            }
          }
          for (const auto &diagnostic : context->report_map->diagnostics())
            append_line(characteristic_prefix + str_sprintf("    `-- Diagnostic severity=%s offset=%u message=%s",
                                                            diagnostic.error ? "error" : "info",
                                                            static_cast<unsigned>(diagnostic.offset),
                                                            diagnostic.message.c_str()));
        }
      }
    }
  }
}

}  // namespace ble_client_hid
}  // namespace esphome

#endif
