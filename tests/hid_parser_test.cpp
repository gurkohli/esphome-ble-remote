#include <cassert>
#include <cstdint>
#include <random>
#include <vector>

#include "hid_parser.h"

using namespace esphome::ble_client_hid;

static HIDReportSource input_source(uint16_t handle, uint8_t id) {
  HIDReportSource source;
  source.characteristic_handle = handle;
  source.report_id = id;
  source.has_report_id = true;
  source.report_type = 1;
  source.has_report_type = true;
  return source;
}

int main() {
  // Composite mouse and Consumer Control fixture with packed 12-bit axes,
  // relative Wheel/Pan fields, padding, and more variables than usages.
  const std::vector<uint8_t> fixture_report_map = {
      0x05,0x01,0x09,0x02,0xA1,0x01,0x85,0x03,0x09,0x01,0xA1,0x00,
      0x95,0x05,0x75,0x01,0x05,0x09,0x19,0x01,0x29,0x05,0x15,0x00,
      0x25,0x01,0x81,0x02,0x95,0x01,0x75,0x03,0x81,0x01,0x75,0x08,
      0x95,0x01,0x05,0x01,0x09,0x38,0x15,0x81,0x25,0x7F,0x81,0x06,
      0x05,0x0C,0x0A,0x38,0x02,0x95,0x01,0x81,0x06,0xC0,0x85,0x02,
      0x09,0x01,0xA1,0x00,0x75,0x0C,0x95,0x02,0x05,0x01,0x09,0x30,
      0x09,0x31,0x16,0x01,0xF8,0x26,0xFF,0x07,0x81,0x06,0xC0,0xC0,
      0x05,0x0C,0x09,0x01,0xA1,0x01,0x85,0x01,0x09,0xE9,0x09,0xEA,
      0x09,0x30,0x09,0x40,0x09,0xA0,0x09,0xB5,0x0A,0x23,0x02,0x0A,
      0x24,0x02,0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x10,0x81,0x02,0xC0};
  HIDReportMap *map = HIDReportMap::parse_report_map_data(fixture_report_map.data(), fixture_report_map.size());
  assert(map != nullptr);

  const uint8_t volume_up[] = {0x01, 0x00};
  auto values = map->parse(input_source(39, 1), volume_up, sizeof(volume_up));
  assert(values.size() == 1 && values[0].usage.page == 0x0C && values[0].usage.usage == 0xE9 && values[0].value == 1);
  const uint8_t released[] = {0x00, 0x00};
  values = map->parse(input_source(39, 1), released, sizeof(released));
  assert(values.size() == 1 && values[0].usage.usage == 0xE9 && values[0].value == 0);

  // HID variable-item rules assign the last usage to excess fields.
  const uint8_t upper_bit[] = {0x00, 0x01};
  values = map->parse(input_source(39, 1), upper_bit, sizeof(upper_bit));
  assert(values.size() == 1 && values[0].usage.usage == 0x224 && values[0].value == 1);

  const uint8_t xy[] = {0xFF, 0x2F, 0x00};  // X=-1, Y=2, packed 12-bit.
  values = map->parse(input_source(43, 2), xy, sizeof(xy));
  assert(values.size() == 2 && values[0].value == -1 && values[1].value == 2);
  assert(values[0].aggregation == HIDReportItemValue::Aggregation::SUM);
  assert(values[1].aggregation == HIDReportItemValue::Aggregation::SUM);
  const uint8_t mouse[] = {0x01, 0xFF, 0x01};
  values = map->parse(input_source(50, 3), mouse, sizeof(mouse));
  assert(values.size() == 3);
  assert(values[0].usage.page == 9 && values[0].usage.usage == 1 && values[0].value == 1);
  assert(values[0].aggregation == HIDReportItemValue::Aggregation::PASSTHROUGH);
  assert(values[1].usage.page == 1 && values[1].usage.usage == 0x38 && values[1].value == -1);
  assert(values[2].usage.page == 0x0C && values[2].usage.usage == 0x238 && values[2].value == 1);
  assert(values[2].aggregation == HIDReportItemValue::Aggregation::SUM);
  HIDReportSource output = input_source(47, 1);
  output.report_type = 2;
  bool recognized = true;
  assert(map->parse(output, volume_up, sizeof(volume_up), &recognized).empty());
  assert(!recognized);
  delete map;

  // Array state is a set of asserted usages, not a slot-by-slot state. Merely
  // reordering keys must not synthesize releases and presses.
  const uint8_t keyboard_descriptor[] = {
      0x05,0x07,0x19,0x00,0x29,0x65,0x15,0x00,0x25,0x65,0x75,0x08,0x95,0x02,0x81,0x00};
  map = HIDReportMap::parse_report_map_data(keyboard_descriptor, sizeof(keyboard_descriptor));
  assert(map != nullptr);
  HIDReportSource no_id;
  const uint8_t keys_45[] = {4, 5};
  values = map->parse(no_id, keys_45, sizeof(keys_45));
  assert(values.size() == 2 && values[0].raw_value == 4 && values[1].raw_value == 5);
  const uint8_t keys_54[] = {5, 4};
  assert(map->parse(no_id, keys_54, sizeof(keys_54)).empty());
  const uint8_t key_5[] = {5, 0};
  values = map->parse(no_id, key_5, sizeof(key_5));
  assert(values.size() == 1 && values[0].usage.usage == 4 && values[0].value == 0);
  delete map;

  // Synthetic metadata fixture: nested collections, physical/unit metadata,
  // strings/designators, aliases, and all three report kinds.
  const uint8_t metadata_descriptor[] = {
      0x05,0x01,0x09,0x04,0xA1,0x01,0x09,0x00,0xA1,0x02,0x85,0x01,
      0x15,0x81,0x25,0x7F,0x36,0x18,0xFC,0x46,0xE8,0x03,0x55,0x0E,
      0x65,0x11,0x05,0x09,0x09,0x01,0xA9,0x01,0x09,0x02,0xA9,0x00,
      0x39,0x02,0x49,0x02,0x59,0x03,0x79,0x03,0x89,0x03,0x99,0x04,
      0x75,0x08,0x95,0x01,0x81,0x02,0x05,0x01,0x09,0x31,0x91,0x02,
      0x09,0x32,0xB1,0x02,0xC0,0xC0};
  map = HIDReportMap::parse_report_map_data(metadata_descriptor, sizeof(metadata_descriptor));
  assert(map != nullptr && map->valid() && map->uses_report_ids());
  assert(map->collections().size() == 2);
  assert(map->collections()[0].type == 1 && map->collections()[0].usage == HIDUsage(4, 1));
  assert(map->collections()[1].parent == 0 && map->collections()[1].type == 2);
  assert(map->reports().size() == 3 && map->fields().size() == 3);
  const auto &metadata_field = map->fields()[0];
  assert(metadata_field.kind == HIDReportKind::INPUT && metadata_field.logical.minimum == -127);
  assert(metadata_field.physical.minimum == -1000 && metadata_field.physical.maximum == 1000);
  assert(metadata_field.unit == 0x11 && metadata_field.unit_exponent == -2);
  assert(metadata_field.usages.size() == 1 && metadata_field.usages[0] == HIDUsage(1, 9));
  assert(metadata_field.alternative_usages.size() == 1);
  assert(metadata_field.alternative_usages[0][0] == HIDUsage(2, 9));
  assert(metadata_field.string_indices[0] == 3 && metadata_field.has_string_range);
  assert(metadata_field.designator_indices[0] == 2 && metadata_field.has_designator_range);
  assert(map->application_usage(metadata_field.collection_id) == HIDUsage(4, 1));
  delete map;

  // Report Count can define several scalar fields with the same Usage. Their
  // bit positions, and therefore their field IDs, must remain distinct.
  const uint8_t duplicate_usage_descriptor[] = {
      0x05,0x09,0x09,0x01,0x15,0x00,0x25,0x01,0x75,0x01,0x95,0x02,0x81,0x02};
  map = HIDReportMap::parse_report_map_data(duplicate_usage_descriptor, sizeof(duplicate_usage_descriptor));
  assert(map != nullptr);
  const uint8_t both_active[] = {0x03};
  values = map->parse(HIDReportSource{}, both_active, sizeof(both_active));
  assert(values.size() == 2 && values[0].usage == values[1].usage);
  assert(values[0].field_id != values[1].field_id);
  delete map;

  // A short packet is rejected before it can mutate transition state.
  const uint8_t one_button_descriptor[] = {
      0x05,0x09,0x09,0x01,0x15,0x00,0x25,0x01,0x75,0x08,0x95,0x01,0x81,0x02};
  map = HIDReportMap::parse_report_map_data(one_button_descriptor, sizeof(one_button_descriptor));
  assert(map != nullptr);
  const uint8_t pressed[] = {1};
  HIDDecodeStatus decode_status = HIDDecodeStatus::SCHEMA_MISSING;
  values = map->parse(HIDReportSource{}, pressed, sizeof(pressed), nullptr, &decode_status);
  assert(values.size() == 1 && decode_status == HIDDecodeStatus::EXACT);
  assert(map->parse(HIDReportSource{}, nullptr, 0, nullptr, &decode_status).empty());
  assert(decode_status == HIDDecodeStatus::SHORT);
  const uint8_t unpressed[] = {0};
  values = map->parse(HIDReportSource{}, unpressed, sizeof(unpressed), nullptr, &decode_status);
  assert(values.size() == 1 && values[0].value == 0);
  const uint8_t long_packet[] = {1, 0xA5};
  values = map->parse(HIDReportSource{}, long_packet, sizeof(long_packet), nullptr, &decode_status);
  assert(values.size() == 1 && decode_status == HIDDecodeStatus::LONG);
  delete map;

  const uint8_t unmatched_end_collection[] = {0xC0};
  assert(HIDReportMap::parse_report_map_data(unmatched_end_collection, sizeof(unmatched_end_collection)) == nullptr);
  const uint8_t pop_without_push[] = {0xB4};
  assert(HIDReportMap::parse_report_map_data(pop_without_push, sizeof(pop_without_push)) == nullptr);
  const uint8_t nested_delimiter[] = {0xA9,0x01,0xA9,0x01,0x81,0x02};
  assert(HIDReportMap::parse_report_map_data(nested_delimiter, sizeof(nested_delimiter)) == nullptr);
  const uint8_t oversized_report[] = {0x75,0x20,0x96,0x01,0x10,0x81,0x02};
  assert(HIDReportMap::parse_report_map_data(oversized_report, sizeof(oversized_report)) == nullptr);

  const uint8_t truncated_short[] = {0x75};
  assert(HIDReportMap::parse_report_map_data(truncated_short, sizeof(truncated_short)) == nullptr);
  const uint8_t truncated_long[] = {0xFE, 0x04, 0x01, 0xAA};
  assert(HIDReportMap::parse_report_map_data(truncated_long, sizeof(truncated_long)) == nullptr);

  // Deterministic malformed-input smoke fuzzing. The parser must either
  // reject each byte stream or return a safely destructible map.
  std::mt19937 random(0x484944);
  for (size_t iteration = 0; iteration < 10000; iteration++) {
    std::vector<uint8_t> bytes(1 + random() % 128);
    for (auto &byte : bytes)
      byte = static_cast<uint8_t>(random());
    delete HIDReportMap::parse_report_map_data(bytes.data(), bytes.size());
  }
}
