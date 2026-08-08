#include "../ble_client_hid.h"

#if defined(USE_ESP32) && defined(USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING)

#include <algorithm>
#include <cctype>
#include <string>

#include "../usages.h"
#include "esphome/components/web_server_base/web_server_base.h"
#include "esphome/core/helpers.h"

namespace esphome {
namespace ble_client_hid {

namespace {

constexpr uint16_t UUID_GAP_SERVICE = 0x1800;
constexpr uint16_t UUID_GATT_SERVICE = 0x1801;
constexpr uint16_t UUID_DEVICE_INFORMATION_SERVICE = 0x180A;
constexpr uint16_t UUID_BATTERY_SERVICE = 0x180F;
constexpr uint16_t UUID_HID_SERVICE = 0x1812;
constexpr uint16_t UUID_CCCD = 0x2902;
constexpr uint16_t UUID_REPORT_REFERENCE = 0x2908;

void json_string(ForensicResponseWriter &out, const std::string &value) {
  static constexpr char HEX[] = "0123456789ABCDEF";
  out.write('"');
  for (const unsigned char c : value) {
    switch (c) {
      case '"': out.print("\\\""); break;
      case '\\': out.print("\\\\"); break;
      case '\b': out.print("\\b"); break;
      case '\f': out.print("\\f"); break;
      case '\n': out.print("\\n"); break;
      case '\r': out.print("\\r"); break;
      case '\t': out.print("\\t"); break;
      default:
        if (c < 0x20) {
          out.print("\\u00");
          out.write(HEX[c >> 4U]);
          out.write(HEX[c & 0x0FU]);
        } else {
          out.write(static_cast<char>(c));
        }
    }
  }
  out.write('"');
}

void key(ForensicResponseWriter &out, const char *name) {
  json_string(out, name);
  out.write(':');
}

void comma(ForensicResponseWriter &out, bool &first) {
  if (!first) out.write(',');
  first = false;
}

void string_field(ForensicResponseWriter &out, const char *name, const std::string &value, bool &first) {
  comma(out, first);
  key(out, name);
  json_string(out, value);
}

template<typename T> void number_field(ForensicResponseWriter &out, const char *name, T value,
                                       bool &first) {
  comma(out, first);
  key(out, name);
  out.print(std::to_string(value));
}

void bool_field(ForensicResponseWriter &out, const char *name, bool value, bool &first) {
  comma(out, first);
  key(out, name);
  out.print(value ? "true" : "false");
}

void null_field(ForensicResponseWriter &out, const char *name, bool &first) {
  comma(out, first);
  key(out, name);
  out.print("null");
}

std::string hex16(uint16_t value) { return str_sprintf("0x%04X", value); }

std::string bytes_hex(const uint8_t *data, size_t length) {
  static constexpr char HEX[] = "0123456789ABCDEF";
  if (data == nullptr || length == 0) return "";
  std::string result(length * 2U, '0');
  for (size_t i = 0; i < length; i++) {
    result[i * 2U] = HEX[data[i] >> 4U];
    result[i * 2U + 1U] = HEX[data[i] & 0x0FU];
  }
  return result;
}

bool printable(const std::vector<uint8_t> &value) {
  return !value.empty() && std::all_of(value.begin(), value.end(), [](uint8_t c) { return std::isprint(c) != 0; });
}

uint16_t uuid16(const espbt::ESPBTUUID &uuid) {
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
    default: return nullptr;
  }
}

const char *attribute_name(uint16_t uuid) {
  switch (uuid) {
    case 0x2A00: return "Device Name";
    case 0x2A01: return "Appearance";
    case 0x2A04: return "Peripheral Preferred Connection Parameters";
    case 0x2A05: return "Service Changed";
    case 0x2A19: return "Battery Level";
    case 0x2A23: return "System ID";
    case 0x2A24: return "Model Number";
    case 0x2A25: return "Serial Number";
    case 0x2A26: return "Firmware Revision";
    case 0x2A27: return "Hardware Revision";
    case 0x2A28: return "Software Revision";
    case 0x2A29: return "Manufacturer Name";
    case 0x2A2A: return "IEEE Certification Data";
    case 0x2A33: return "Boot Mouse Input Report";
    case 0x2A4A: return "HID Information";
    case 0x2A4B: return "Report Map";
    case 0x2A4C: return "HID Control Point";
    case 0x2A4D: return "Report";
    case 0x2A4E: return "Protocol Mode";
    case 0x2A50: return "PnP ID";
    case 0x2901: return "Characteristic User Description";
    case UUID_CCCD: return "Client Characteristic Configuration";
    case 0x2904: return "Characteristic Presentation Format";
    case 0x2905: return "Characteristic Aggregate Format";
    case 0x2907: return "External Report Reference";
    case UUID_REPORT_REFERENCE: return "Report Reference";
    default: return nullptr;
  }
}

void uuid_object(ForensicResponseWriter &out, const espbt::ESPBTUUID &uuid,
                 const std::string &canonical, const char *name) {
  out.write('{');
  bool first = true;
  string_field(out, "canonical", canonical, first);
  const uint16_t short_value = uuid16(uuid);
  if (short_value != 0) string_field(out, "short", hex16(short_value), first);
  else null_field(out, "short", first);
  if (name != nullptr) string_field(out, "name", name, first);
  else null_field(out, "name", first);
  bool_field(out, "vendor_defined", short_value == 0 || short_value >= 0xAE00, first);
  out.write('}');
}

const char *gatt_status_name(int status) {
  switch (status) {
    case ESP_GATT_OK: return "ESP_GATT_OK";
    case ESP_GATT_INVALID_HANDLE: return "ESP_GATT_INVALID_HANDLE";
    case ESP_GATT_READ_NOT_PERMIT: return "ESP_GATT_READ_NOT_PERMIT";
    case ESP_GATT_WRITE_NOT_PERMIT: return "ESP_GATT_WRITE_NOT_PERMIT";
    case ESP_GATT_INSUF_AUTHENTICATION: return "ESP_GATT_INSUF_AUTHENTICATION";
    case ESP_GATT_INSUF_AUTHORIZATION: return "ESP_GATT_INSUF_AUTHORIZATION";
    case ESP_GATT_INSUF_ENCRYPTION: return "ESP_GATT_INSUF_ENCRYPTION";
    case ESP_GATT_INVALID_ATTR_LEN: return "ESP_GATT_INVALID_ATTR_LEN";
    case ESP_GATT_NO_RESOURCES: return "ESP_GATT_NO_RESOURCES";
    default: return "unknown";
  }
}

void status_object(ForensicResponseWriter &out, const char *domain, int status) {
  out.write('{');
  bool first = true;
  string_field(out, "domain", domain, first);
  number_field(out, "code", status, first);
  string_field(out, "hex", str_sprintf("0x%02X", static_cast<unsigned>(status) & 0xFFU), first);
  if (std::string(domain) == "gatt") string_field(out, "name", gatt_status_name(status), first);
  else if (std::string(domain) == "local") string_field(out, "name", "local_precondition_failed", first);
  else string_field(out, "name", status == ESP_OK ? "ESP_OK" : "unknown", first);
  out.write('}');
}

void handle_fields(ForensicResponseWriter &out, uint16_t handle, bool &first) {
  number_field(out, "handle", handle, first);
  string_field(out, "handle_hex", hex16(handle), first);
}

void properties_object(ForensicResponseWriter &out, uint8_t properties) {
  out.write('{');
  bool first = true;
  number_field(out, "raw", properties, first);
  string_field(out, "hex", str_sprintf("0x%02X", properties), first);
  comma(out, first);
  key(out, "names");
  out.write('[');
  bool property_first = true;
  const auto add = [&out, &property_first](const char *name) {
    if (!property_first) out.write(',');
    property_first = false;
    json_string(out, name);
  };
  if ((properties & ESP_GATT_CHAR_PROP_BIT_BROADCAST) != 0) add("broadcast");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_READ) != 0) add("read");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_WRITE_NR) != 0) add("write_without_response");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_WRITE) != 0) add("write");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_NOTIFY) != 0) add("notify");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_INDICATE) != 0) add("indicate");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_AUTH) != 0) add("authenticated_signed_write");
  if ((properties & ESP_GATT_CHAR_PROP_BIT_EXT_PROP) != 0) add("extended_properties");
  out.write(']');
  out.write('}');
}

void read_evidence(ForensicResponseWriter &out, bool planned, bool complete, bool succeeded, int status,
                   size_t length, bool truncated, const std::vector<uint8_t> &value, bool readable) {
  out.write('{');
  bool first = true;
  const char *availability = !planned ? (readable ? "not_observed" : "not_readable")
                                      : !complete ? "incomplete" : !succeeded ? "read_failed" : "observed";
  string_field(out, "availability", availability, first);
  bool_field(out, "planned", planned, first);
  bool_field(out, "complete", complete, first);
  bool_field(out, "succeeded", succeeded, first);
  if (planned && complete) {
    comma(out, first);
    key(out, "status");
    status_object(out, "gatt", status);
  } else {
    null_field(out, "status", first);
  }
  number_field(out, "length", length, first);
  bool_field(out, "truncated", truncated, first);
  if (succeeded) {
    string_field(out, "bytes_hex", bytes_hex(value.data(), value.size()), first);
    if (printable(value)) string_field(out, "text", std::string(value.begin(), value.end()), first);
    else null_field(out, "text", first);
  } else {
    null_field(out, "bytes_hex", first);
    null_field(out, "text", first);
  }
  out.write('}');
}

std::string service_id(const GattServiceInfo &service) {
  return str_sprintf("service/%u/%s", service.instance, hex16(uuid16(service.uuid)).c_str());
}

std::string characteristic_id(const GattServiceInfo &service, const GattCharacteristicInfo &characteristic,
                              size_t ordinal) {
  return str_sprintf("%s/characteristic/%s/%u", service_id(service).c_str(),
                     hex16(uuid16(characteristic.uuid)).c_str(), static_cast<unsigned>(ordinal));
}

void usage_object(ForensicResponseWriter &out, HIDUsage usage) {
  out.write('{');
  bool first = true;
  number_field(out, "page", usage.page, first);
  string_field(out, "page_hex", hex16(usage.page), first);
  number_field(out, "id", usage.usage, first);
  string_field(out, "id_hex", hex16(usage.usage), first);
  const char *name = lookup_usage_name(usage.page, usage.usage);
  if (name != nullptr) string_field(out, "name", name, first);
  else null_field(out, "name", first);
  out.write('}');
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

void hid_profile(ForensicResponseWriter &out, const HIDServiceContext &context) {
  out.write('{');
  bool first = true;
  number_field(out, "service_instance", context.service_instance, first);
  string_field(out, "report_map_sha256", context.report_map_hash, first);
  string_field(out, "protocol_mode", context.protocol_mode == 0 ? "boot" : context.protocol_mode == 1 ? "report" : "unknown", first);
  if (context.report_map == nullptr) {
    string_field(out, "availability", "unavailable", first);
    out.write('}');
    return;
  }
  string_field(out, "availability", "parsed", first);
  bool_field(out, "valid", context.report_map->valid(), first);
  bool_field(out, "uses_report_ids", context.report_map->uses_report_ids(), first);

  comma(out, first);
  key(out, "collections");
  out.write('[');
  for (size_t i = 0; i < context.report_map->collections().size(); i++) {
    if (i != 0) out.write(',');
    const auto &collection = context.report_map->collections()[i];
    out.write('{');
    bool collection_first = true;
    number_field(out, "id", collection.id, collection_first);
    if (collection.parent == HIDCollectionSchema::NO_PARENT) null_field(out, "parent_id", collection_first);
    else number_field(out, "parent_id", collection.parent, collection_first);
    number_field(out, "type", collection.type, collection_first);
    string_field(out, "type_name", collection_type_name(collection.type), collection_first);
    comma(out, collection_first);
    key(out, "usage");
    usage_object(out, collection.usage);
    comma(out, collection_first);
    key(out, "aliases");
    out.write('[');
    for (size_t alias = 0; alias < collection.aliases.size(); alias++) {
      if (alias != 0) out.write(',');
      usage_object(out, collection.aliases[alias]);
    }
    out.write(']');
    out.write('}');
  }
  out.write(']');

  comma(out, first);
  key(out, "reports");
  out.write('[');
  for (size_t i = 0; i < context.report_map->reports().size(); i++) {
    if (i != 0) out.write(',');
    const auto &report = context.report_map->reports()[i];
    out.write('{');
    bool report_first = true;
    string_field(out, "kind", hid_report_kind_name(report.kind), report_first);
    number_field(out, "report_id", report.report_id, report_first);
    number_field(out, "bit_size", report.bit_size, report_first);
    number_field(out, "byte_size", report.byte_size(), report_first);
    comma(out, report_first);
    key(out, "field_ids");
    out.write('[');
    for (size_t field = 0; field < report.field_ids.size(); field++) {
      if (field != 0) out.write(',');
      out.print(std::to_string(report.field_ids[field]));
    }
    out.write(']');
    out.write('}');
  }
  out.write(']');

  comma(out, first);
  key(out, "fields");
  out.write('[');
  for (size_t i = 0; i < context.report_map->fields().size(); i++) {
    if (i != 0) out.write(',');
    const auto &field = context.report_map->fields()[i];
    out.write('{');
    bool field_first = true;
    number_field(out, "id", field.id, field_first);
    string_field(out, "kind", hid_report_kind_name(field.kind), field_first);
    number_field(out, "report_id", field.report_id, field_first);
    if (field.collection_id == HIDCollectionSchema::NO_PARENT) null_field(out, "collection_id", field_first);
    else number_field(out, "collection_id", field.collection_id, field_first);
    number_field(out, "bit_offset", field.bit_offset, field_first);
    number_field(out, "size_bits", field.report_size, field_first);
    number_field(out, "count", field.report_count, field_first);
    number_field(out, "flags", field.flags, field_first);
    string_field(out, "flags_hex", str_sprintf("0x%03X", field.flags), field_first);
    string_field(out, "data_kind", field.is_constant() ? "constant" : field.is_variable() ? "variable" : "array", field_first);
    string_field(out, "value_kind", field.is_relative() ? "relative" : "absolute", field_first);
    comma(out, field_first);
    key(out, "logical_range");
    out.print(str_sprintf("{%s:%lld,%s:%lld}", "\"minimum\"", static_cast<long long>(field.logical.minimum),
                          "\"maximum\"", static_cast<long long>(field.logical.maximum)));
    comma(out, field_first);
    key(out, "physical_range");
    out.print(str_sprintf("{%s:%lld,%s:%lld}", "\"minimum\"", static_cast<long long>(field.physical.minimum),
                          "\"maximum\"", static_cast<long long>(field.physical.maximum)));
    number_field(out, "unit", field.unit, field_first);
    string_field(out, "unit_hex", str_sprintf("0x%08X", static_cast<unsigned>(field.unit)), field_first);
    number_field(out, "unit_exponent", static_cast<int>(field.unit_exponent), field_first);
    comma(out, field_first);
    key(out, "usages");
    out.write('[');
    for (size_t usage = 0; usage < field.usages.size(); usage++) {
      if (usage != 0) out.write(',');
      usage_object(out, field.usages[usage]);
    }
    out.write(']');
    comma(out, field_first);
    key(out, "usage_range");
    if (field.has_usage_range) {
      out.write('{');
      bool range_first = true;
      comma(out, range_first); key(out, "minimum"); usage_object(out, field.usage_minimum);
      comma(out, range_first); key(out, "maximum"); usage_object(out, field.usage_maximum);
      out.write('}');
    } else out.print("null");
    out.write('}');
  }
  out.write(']');

  comma(out, first);
  key(out, "diagnostics");
  out.write('[');
  for (size_t i = 0; i < context.report_map->diagnostics().size(); i++) {
    if (i != 0) out.write(',');
    const auto &diagnostic = context.report_map->diagnostics()[i];
    out.write('{');
    bool diagnostic_first = true;
    string_field(out, "severity", diagnostic.error ? "error" : "info", diagnostic_first);
    number_field(out, "offset", diagnostic.offset, diagnostic_first);
    string_field(out, "message", diagnostic.message, diagnostic_first);
    out.write('}');
  }
  out.write(']');
  out.write('}');
}

void operation_object(ForensicResponseWriter &out, const ForensicOperation &operation) {
  out.write('{');
  bool first = true;
  number_field(out, "sequence", operation.sequence, first);
  number_field(out, "offset_ms", operation.offset_ms, first);
  string_field(out, "type", operation.type, first);
  string_field(out, "stage", operation.stage, first);
  handle_fields(out, operation.handle, first);
  if (operation.related_handle != 0) {
    number_field(out, "related_handle", operation.related_handle, first);
    string_field(out, "related_handle_hex", hex16(operation.related_handle), first);
  } else {
    null_field(out, "related_handle", first);
    null_field(out, "related_handle_hex", first);
  }
  bool_field(out, "complete", operation.complete, first);
  bool_field(out, "succeeded", operation.succeeded, first);
  comma(out, first);
  key(out, "status");
  status_object(out, operation.status_domain.c_str(), operation.status);
  number_field(out, "value_length", operation.value_length, first);
  bool_field(out, "value_truncated", operation.value_truncated, first);
  bool_field(out, "value_redacted", operation.value_redacted, first);
  if (operation.value_redacted) null_field(out, "value_hex", first);
  else string_field(out, "value_hex", bytes_hex(operation.value.data(), operation.value.size()), first);
  out.write('}');
}

}  // namespace

void BLEClientHID::render_gatt_json_(ForensicResponseWriter &out) {
  size_t characteristic_count = 0;
  size_t descriptor_count = 0;
  size_t readable_count = 0;
  size_t writable_count = 0;
  size_t notifiable_count = 0;
  size_t indicatable_count = 0;
  size_t subscription_failure_count = 0;
  bool cccd_write_performed = false;
  for (const auto &service : this->services_) {
    characteristic_count += service.characteristics.size();
    for (const auto &characteristic : service.characteristics) {
      descriptor_count += characteristic.descriptors.size();
      if ((characteristic.properties & ESP_GATT_CHAR_PROP_BIT_READ) != 0) readable_count++;
      if ((characteristic.properties & (ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_WRITE_NR)) != 0)
        writable_count++;
      if ((characteristic.properties & ESP_GATT_CHAR_PROP_BIT_NOTIFY) != 0) notifiable_count++;
      if ((characteristic.properties & ESP_GATT_CHAR_PROP_BIT_INDICATE) != 0) indicatable_count++;
      if (characteristic.subscription_complete && !characteristic.subscription_enabled) subscription_failure_count++;
      if (characteristic.cccd_write_complete) cccd_write_performed = true;
    }
  }

  out.write('{');
  bool root_first = true;
  string_field(out, "format", "ble-gatt-forensic-profile", root_first);

  comma(out, root_first);
  key(out, "capture");
  out.write('{');
  bool capture_first = true;
  string_field(out, "state", this->hid_services_.empty() ? "no_hid" : this->degraded_ ? "degraded" : "ready", capture_first);
  string_field(out, "discovery_mode", "forensic", capture_first);
  string_field(out, "protocol_mode_policy",
               this->protocol_mode_policy_ == ProtocolModePolicy::REPORT ? "report" :
               this->protocol_mode_policy_ == ProtocolModePolicy::BOOT ? "boot" : "unchanged", capture_first);
  number_field(out, "ready_offset_ms", this->forensic_capture_completed_ms_ - this->forensic_capture_started_ms_, capture_first);
  bool_field(out, "complete_at_hid_ready", this->forensic_snapshot_available_, capture_first);
  comma(out, capture_first);
  key(out, "coverage");
  out.print("{\"cached_gatt_inventory\":true,\"readable_values_attempted\":true,"
            "\"parsed_hid_schema\":true,\"att_permissions_available\":false,"
            "\"raw_att_declarations_available\":false,\"dynamic_values_complete\":false}");
  comma(out, capture_first);
  key(out, "mutations");
  out.write('{');
  bool mutation_first = true;
  bool_field(out, "cccd_writes_performed", cccd_write_performed, mutation_first);
  bool_field(out, "protocol_mode_write_performed", this->protocol_mode_policy_ != ProtocolModePolicy::UNCHANGED,
             mutation_first);
  bool_field(out, "unknown_characteristics_written", false, mutation_first);
  out.write('}');
  out.write('}');

  comma(out, root_first);
  key(out, "device");
  out.write('{');
  bool device_first = true;
  string_field(out, "address", this->parent()->address_str(), device_first);
  number_field(out, "address_type", this->last_address_type_, device_first);
  string_field(out, "address_type_name", this->last_address_type_ == 0 ? "public" : this->last_address_type_ == 1 ? "random" : "unknown", device_first);
  comma(out, device_first);
  key(out, "metadata");
  out.write('{');
  bool metadata_first = true;
  for (const auto &entry : this->device_metadata_) string_field(out, entry.first.c_str(), entry.second, metadata_first);
  out.write('}');
  comma(out, device_first);
  key(out, "advertising");
  out.write('{');
  bool advertising_first = true;
  number_field(out, "rssi_dbm", this->last_rssi_, advertising_first);
  number_field(out, "advertisement_length", this->last_advertisement_data_length_, advertising_first);
  string_field(out, "advertisement_hex", bytes_hex(this->last_advertisement_.data(), this->last_advertisement_data_length_), advertising_first);
  number_field(out, "scan_response_length", this->last_scan_response_length_, advertising_first);
  string_field(out, "scan_response_hex", bytes_hex(this->last_advertisement_.data() + this->last_advertisement_data_length_, this->last_scan_response_length_), advertising_first);
  out.write('}');
  out.write('}');

  comma(out, root_first);
  key(out, "connection");
  out.write('{');
  bool connection_first = true;
  if (this->negotiated_mtu_available_) number_field(out, "att_mtu", this->negotiated_mtu_, connection_first);
  else null_field(out, "att_mtu", connection_first);
  if (this->negotiated_conn_params_available_) {
    number_field(out, "interval_ms", this->negotiated_interval_ms_, connection_first);
    number_field(out, "latency", this->negotiated_latency_, connection_first);
    number_field(out, "timeout_ms", this->negotiated_timeout_ms_, connection_first);
  } else {
    null_field(out, "interval_ms", connection_first);
    null_field(out, "latency", connection_first);
    null_field(out, "timeout_ms", connection_first);
  }
  string_field(out, "security", "unavailable_from_ble_client_stack", connection_first);
  out.write('}');

  comma(out, root_first);
  key(out, "summary");
  out.write('{');
  bool summary_first = true;
  number_field(out, "services", this->services_.size(), summary_first);
  number_field(out, "characteristics", characteristic_count, summary_first);
  number_field(out, "descriptors", descriptor_count, summary_first);
  number_field(out, "readable_characteristics", readable_count, summary_first);
  number_field(out, "writable_characteristics", writable_count, summary_first);
  number_field(out, "notifiable_characteristics", notifiable_count, summary_first);
  number_field(out, "indicatable_characteristics", indicatable_count, summary_first);
  number_field(out, "operations_succeeded", this->operations_succeeded_, summary_first);
  number_field(out, "operations_failed", this->operations_failed_, summary_first);
  number_field(out, "subscription_failures", subscription_failure_count, summary_first);
  out.write('}');

  comma(out, root_first);
  key(out, "findings");
  out.write('[');
  bool finding_first = true;
  const auto finding = [&out, &finding_first](const char *severity, const char *code, const std::string &message,
                                               uint16_t handle) {
    if (!finding_first) out.write(',');
    finding_first = false;
    out.write('{');
    bool first = true;
    string_field(out, "severity", severity, first);
    string_field(out, "code", code, first);
    string_field(out, "message", message, first);
    if (handle != 0) handle_fields(out, handle, first);
    else { null_field(out, "handle", first); null_field(out, "handle_hex", first); }
    out.write('}');
  };
  for (size_t i = 0; i + 1U < this->services_.size(); i++) {
    if (this->services_[i].end_handle + 1U < this->services_[i + 1U].start_handle)
      finding("info", "database_handle_gap",
              str_sprintf("No discovered service covers handles %s-%s",
                          hex16(this->services_[i].end_handle + 1U).c_str(),
                          hex16(this->services_[i + 1U].start_handle - 1U).c_str()), 0);
  }
  for (const auto &service : this->services_) {
    for (const auto &characteristic : service.characteristics) {
      if (characteristic.subscription_complete && !characteristic.subscription_enabled)
        finding("warning", "subscription_failed", "Notification or indication subscription failed",
                characteristic.handle);
      const auto source = this->handle_report_source_.find(characteristic.handle);
      if (source != this->handle_report_source_.end() && source->second.has_report_id &&
          source->second.has_report_type && source->second.report_type >= 1 && source->second.report_type <= 3) {
        const HIDServiceContext *context = this->find_hid_context_(source->second.service_instance);
        if (context == nullptr || context->report_map == nullptr ||
            context->report_map->find_report(static_cast<HIDReportKind>(source->second.report_type),
                                             source->second.report_id) == nullptr)
          finding("warning", "hid_report_schema_missing",
                  str_sprintf("Report reference kind=%s id=%u is not defined by the Report Map",
                              hid_report_kind_name(static_cast<HIDReportKind>(source->second.report_type)),
                              source->second.report_id), characteristic.handle);
      }
      for (const auto &descriptor : characteristic.descriptors)
        if (uuid16(descriptor.uuid) == UUID_CCCD && descriptor.read_succeeded && descriptor.value_length == 0)
          finding("warning", "empty_cccd_value", "CCCD read succeeded with a zero-length value", descriptor.handle);
    }
  }
  out.write(']');

  comma(out, root_first);
  key(out, "database");
  out.write('{');
  bool database_first = true;
  string_field(out, "fingerprint_sha256", this->gatt_profile_hash_, database_first);
  comma(out, database_first);
  key(out, "services");
  out.write('[');
  for (size_t service_index = 0; service_index < this->services_.size(); service_index++) {
    if (service_index != 0) out.write(',');
    const auto &service = this->services_[service_index];
    out.write('{');
    bool service_first = true;
    string_field(out, "id", service_id(service), service_first);
    number_field(out, "instance", service.instance, service_first);
    comma(out, service_first); key(out, "uuid");
    uuid_object(out, service.uuid, uuid_string_(service.uuid), service_name(uuid16(service.uuid)));
    string_field(out, "type", service.primary ? "primary" : "secondary", service_first);
    number_field(out, "start_handle", service.start_handle, service_first);
    string_field(out, "start_handle_hex", hex16(service.start_handle), service_first);
    number_field(out, "end_handle", service.end_handle, service_first);
    string_field(out, "end_handle_hex", hex16(service.end_handle), service_first);
    string_field(out, "permissions", "unknown_not_exposed_by_cached_inventory", service_first);
    comma(out, service_first); key(out, "included_services");
    out.write('[');
    for (size_t include_index = 0; include_index < service.included_services.size(); include_index++) {
      if (include_index != 0) out.write(',');
      const auto &include = service.included_services[include_index];
      out.write('{'); bool include_first = true;
      handle_fields(out, include.declaration_handle, include_first);
      comma(out, include_first); key(out, "uuid");
      uuid_object(out, include.uuid, uuid_string_(include.uuid), service_name(uuid16(include.uuid)));
      number_field(out, "start_handle", include.start_handle, include_first);
      number_field(out, "end_handle", include.end_handle, include_first);
      out.write('}');
    }
    out.write(']');
    comma(out, service_first); key(out, "characteristics");
    out.write('[');
    for (size_t characteristic_index = 0; characteristic_index < service.characteristics.size(); characteristic_index++) {
      if (characteristic_index != 0) out.write(',');
      const auto &characteristic = service.characteristics[characteristic_index];
      size_t ordinal = 0;
      for (size_t previous = 0; previous < characteristic_index; previous++)
        if (service.characteristics[previous].uuid == characteristic.uuid) ordinal++;
      out.write('{');
      bool characteristic_first = true;
      string_field(out, "id", characteristic_id(service, characteristic, ordinal), characteristic_first);
      comma(out, characteristic_first); key(out, "uuid");
      uuid_object(out, characteristic.uuid, uuid_string_(characteristic.uuid), attribute_name(uuid16(characteristic.uuid)));
      number_field(out, "declaration_handle", characteristic.handle - 1U, characteristic_first);
      string_field(out, "declaration_handle_hex", hex16(characteristic.handle - 1U), characteristic_first);
      bool_field(out, "declaration_handle_inferred", true, characteristic_first);
      number_field(out, "value_handle", characteristic.handle, characteristic_first);
      string_field(out, "value_handle_hex", hex16(characteristic.handle), characteristic_first);
      comma(out, characteristic_first); key(out, "properties"); properties_object(out, characteristic.properties);
      string_field(out, "permissions", "unknown_not_exposed_by_cached_inventory", characteristic_first);
      comma(out, characteristic_first); key(out, "value");
      read_evidence(out, characteristic.read_planned, characteristic.read_complete, characteristic.read_succeeded,
                    characteristic.read_status, characteristic.value_length, characteristic.value_truncated,
                    characteristic.value, (characteristic.properties & ESP_GATT_CHAR_PROP_BIT_READ) != 0);
      comma(out, characteristic_first); key(out, "subscription");
      out.write('{');
      bool subscription_first = true;
      string_field(out, "state", !characteristic.subscription_planned ? "not_planned" :
                   !characteristic.subscription_complete ? "incomplete" :
                   characteristic.subscription_enabled ? "enabled" : "failed", subscription_first);
      number_field(out, "cccd_handle", characteristic.cccd_handle, subscription_first);
      if (characteristic.cccd_handle != 0) string_field(out, "cccd_handle_hex", hex16(characteristic.cccd_handle), subscription_first);
      else null_field(out, "cccd_handle_hex", subscription_first);
      comma(out, subscription_first); key(out, "registration");
      out.write('{'); bool registration_first = true;
      bool_field(out, "complete", characteristic.registration_complete, registration_first);
      bool_field(out, "succeeded", characteristic.registration_succeeded, registration_first);
      if (characteristic.registration_complete) { comma(out, registration_first); key(out, "status"); status_object(out, characteristic.registration_status_is_esp_err ? "esp_err" : "gatt", characteristic.registration_status); }
      else null_field(out, "status", registration_first);
      out.write('}');
      comma(out, subscription_first); key(out, "cccd_write");
      out.write('{'); bool cccd_first = true;
      bool_field(out, "complete", characteristic.cccd_write_complete, cccd_first);
      bool_field(out, "succeeded", characteristic.cccd_write_succeeded, cccd_first);
      if (characteristic.cccd_write_complete) { comma(out, cccd_first); key(out, "status"); status_object(out, characteristic.cccd_write_status_is_esp_err ? "esp_err" : "gatt", characteristic.cccd_write_status); }
      else null_field(out, "status", cccd_first);
      out.write('}');
      out.write('}');
      const auto source = this->handle_report_source_.find(characteristic.handle);
      comma(out, characteristic_first); key(out, "hid_report_identity");
      if (source == this->handle_report_source_.end()) out.print("null");
      else {
        out.write('{'); bool source_first = true;
        if (source->second.has_report_id) number_field(out, "report_id", source->second.report_id, source_first);
        else null_field(out, "report_id", source_first);
        if (source->second.has_report_type && source->second.report_type >= 1 && source->second.report_type <= 3)
          string_field(out, "kind", hid_report_kind_name(static_cast<HIDReportKind>(source->second.report_type)), source_first);
        else null_field(out, "kind", source_first);
        string_field(out, "transport", (characteristic.properties & ESP_GATT_CHAR_PROP_BIT_NOTIFY) != 0 ? "notify" :
                     (characteristic.properties & ESP_GATT_CHAR_PROP_BIT_INDICATE) != 0 ? "indicate" : "none", source_first);
        const HIDServiceContext *context = this->find_hid_context_(source->second.service_instance);
        const bool schema_defined = source->second.has_report_id && source->second.has_report_type &&
          source->second.report_type >= 1 && source->second.report_type <= 3 && context != nullptr &&
          context->report_map != nullptr && context->report_map->find_report(
            static_cast<HIDReportKind>(source->second.report_type), source->second.report_id) != nullptr;
        string_field(out, "schema_status", schema_defined ? "defined" : "missing", source_first);
        out.write('}');
      }
      comma(out, characteristic_first); key(out, "descriptors");
      out.write('[');
      for (size_t descriptor_index = 0; descriptor_index < characteristic.descriptors.size(); descriptor_index++) {
        if (descriptor_index != 0) out.write(',');
        const auto &descriptor = characteristic.descriptors[descriptor_index];
        out.write('{'); bool descriptor_first = true;
        handle_fields(out, descriptor.handle, descriptor_first);
        comma(out, descriptor_first); key(out, "uuid");
        uuid_object(out, descriptor.uuid, uuid_string_(descriptor.uuid), attribute_name(uuid16(descriptor.uuid)));
        string_field(out, "permissions", "unknown_not_exposed_by_cached_inventory", descriptor_first);
        comma(out, descriptor_first); key(out, "value");
        read_evidence(out, descriptor.read_planned, descriptor.read_complete, descriptor.read_succeeded,
                      descriptor.read_status, descriptor.value_length, descriptor.value_truncated, descriptor.value, true);
        out.write('}');
      }
      out.write(']');
      out.write('}');
    }
    out.write(']');
    out.write('}');
  }
  out.write(']');
  out.write('}');

  comma(out, root_first);
  key(out, "hid_profiles");
  out.write('[');
  for (size_t i = 0; i < this->hid_services_.size(); i++) {
    if (i != 0) out.write(',');
    hid_profile(out, this->hid_services_[i]);
  }
  out.write(']');

  comma(out, root_first);
  key(out, "setup_evidence");
  out.write('{');
  bool evidence_first = true;
  number_field(out, "capacity", MAX_FORENSIC_OPERATIONS, evidence_first);
  number_field(out, "retained", this->forensic_operations_.size(), evidence_first);
  number_field(out, "dropped", this->forensic_operations_dropped_, evidence_first);
  bool_field(out, "complete", this->forensic_operations_dropped_ == 0, evidence_first);
  comma(out, evidence_first); key(out, "operations");
  out.write('[');
  for (size_t i = 0; i < this->forensic_operations_.size(); i++) {
    if (i != 0) out.write(',');
    operation_object(out, this->forensic_operations_[i]);
  }
  out.write(']');
  out.write('}');
  out.write('}');
  out.write('\n');
}

void BLEClientHID::render_recorder_json_(ForensicResponseWriter &out) {
  out.write('{');
  bool first = true;
  string_field(out, "format", "ble-gatt-forensic-recording", first);
  string_field(out, "device_address", this->parent()->address_str(), first);
  string_field(out, "gatt_profile_sha256", this->gatt_profile_hash_, first);
  string_field(out, "state", this->forensic_recording_active_ ? "recording" : "stopped", first);
  number_field(out, "capacity", MAX_FORENSIC_OPERATIONS, first);
  number_field(out, "retained", this->forensic_recording_events_.size(), first);
  number_field(out, "dropped", this->forensic_recording_events_dropped_, first);
  bool_field(out, "complete", this->forensic_recording_events_dropped_ == 0, first);
  comma(out, first); key(out, "events");
  out.write('[');
  for (size_t i = 0; i < this->forensic_recording_events_.size(); i++) {
    if (i != 0) out.write(',');
    const auto &event = this->forensic_recording_events_[i];
    out.write('{');
    bool event_first = true;
    number_field(out, "sequence", event.sequence, event_first);
    number_field(out, "offset_ms", event.offset_ms, event_first);
    string_field(out, "transport", event.type, event_first);
    handle_fields(out, event.handle, event_first);
    const GattCharacteristicInfo *characteristic = this->find_characteristic_(event.handle);
    if (characteristic != nullptr) {
      comma(out, event_first); key(out, "characteristic_uuid");
      uuid_object(out, characteristic->uuid, uuid_string_(characteristic->uuid), attribute_name(uuid16(characteristic->uuid)));
    } else null_field(out, "characteristic_uuid", event_first);
    string_field(out, "value_hex", bytes_hex(event.value.data(), event.value.size()), event_first);
    number_field(out, "length", event.value_length, event_first);
    bool_field(out, "truncated", event.value_truncated, event_first);
    const auto source = this->handle_report_source_.find(event.handle);
    comma(out, event_first); key(out, "hid_report_identity");
    if (source == this->handle_report_source_.end()) out.print("null");
    else {
      out.write('{'); bool source_first = true;
      if (source->second.has_report_id) number_field(out, "report_id", source->second.report_id, source_first);
      else null_field(out, "report_id", source_first);
      if (source->second.has_report_type && source->second.report_type >= 1 && source->second.report_type <= 3)
        string_field(out, "kind", hid_report_kind_name(static_cast<HIDReportKind>(source->second.report_type)), source_first);
      else null_field(out, "kind", source_first);
      out.write('}');
    }
    out.write('}');
  }
  out.write(']');
  out.write('}');
  out.write('\n');
}

}  // namespace ble_client_hid
}  // namespace esphome

#endif
