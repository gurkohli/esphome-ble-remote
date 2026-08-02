#include <cassert>
#include <cstdint>

#include "boot_report_decoder.h"

using namespace esphome::ble_client_hid;

static HIDReportSource source(uint16_t handle, uint16_t uuid) {
  HIDReportSource result;
  result.characteristic_handle = handle;
  result.characteristic_uuid = uuid;
  return result;
}

int main() {
  HIDBootReportDecoder decoder;
  HIDDecodeStatus status = HIDDecodeStatus::SCHEMA_MISSING;

  const auto mouse = source(10, HIDBootReportDecoder::BOOT_MOUSE_INPUT_UUID);
  const uint8_t mouse_press_move[] = {0x01, 0xFE, 0x03};
  auto values = decoder.decode(mouse, mouse_press_move, sizeof(mouse_press_move), &status);
  assert(status == HIDDecodeStatus::EXACT && values.size() == 3);
  assert(values[0].usage == HIDUsage(1, 9) && values[0].value == 1);
  assert(values[1].usage == HIDUsage(0x30, 1) && values[1].value == -2 && values[1].is_relative);
  assert(values[2].usage == HIDUsage(0x31, 1) && values[2].value == 3 && values[2].is_relative);

  const uint8_t mouse_same[] = {0x01, 0, 0};
  assert(decoder.decode(mouse, mouse_same, sizeof(mouse_same), &status).empty());
  const uint8_t mouse_release[] = {0, 0, 0, 0xAA};
  values = decoder.decode(mouse, mouse_release, sizeof(mouse_release), &status);
  assert(status == HIDDecodeStatus::LONG && values.size() == 1 && values[0].value == 0);

  // A short report is rejected before it mutates the stored button state.
  const uint8_t mouse_short[] = {0x01, 0};
  assert(decoder.decode(mouse, mouse_short, sizeof(mouse_short), &status).empty());
  assert(status == HIDDecodeStatus::SHORT);
  const uint8_t mouse_press[] = {0x01, 0, 0};
  values = decoder.decode(mouse, mouse_press, sizeof(mouse_press), &status);
  assert(values.size() == 1 && values[0].value == 1);

  const auto keyboard = source(20, HIDBootReportDecoder::BOOT_KEYBOARD_INPUT_UUID);
  const uint8_t key_press[] = {0x02, 0, 4, 5, 0, 0, 0, 0};
  values = decoder.decode(keyboard, key_press, sizeof(key_press), &status);
  assert(status == HIDDecodeStatus::EXACT && values.size() == 3);
  assert(values[0].usage == HIDUsage(0xE1, 7) && values[0].value == 1);
  assert(values[1].usage == HIDUsage(4, 7) && values[2].usage == HIDUsage(5, 7));

  // Reordering the six-key rollover slots must not create transitions.
  const uint8_t reordered[] = {0x02, 0, 5, 4, 0, 0, 0, 0};
  assert(decoder.decode(keyboard, reordered, sizeof(reordered), &status).empty());
  const uint8_t release[] = {0, 0, 5, 0, 0, 0, 0, 0};
  values = decoder.decode(keyboard, release, sizeof(release), &status);
  assert(values.size() == 2);
  assert(values[0].usage == HIDUsage(0xE1, 7) && values[0].value == 0);
  assert(values[1].usage == HIDUsage(4, 7) && values[1].value == 0);

  const auto other_keyboard = source(21, HIDBootReportDecoder::BOOT_KEYBOARD_INPUT_UUID);
  values = decoder.decode(other_keyboard, key_press, sizeof(key_press), &status);
  assert(values.size() == 3);  // Runtime state is isolated by characteristic.

  assert(decoder.decode(keyboard, nullptr, 1, &status).empty());
  assert(status == HIDDecodeStatus::INVALID_PAYLOAD);
  const auto unknown = source(30, 0xFFFF);
  assert(decoder.decode(unknown, nullptr, 0, &status).empty());
  assert(status == HIDDecodeStatus::BOOT_REPORT);

  decoder.reset();
  values = decoder.decode(keyboard, key_press, sizeof(key_press), &status);
  assert(values.size() == 3);
}
