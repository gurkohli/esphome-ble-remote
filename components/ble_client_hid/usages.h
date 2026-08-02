#pragma once

#include <cstdint>

namespace esphome {
namespace ble_client_hid {

extern const char *const HID_USAGE_TABLE_VERSION;
const char *lookup_usage_page_name(uint16_t page);
const char *lookup_usage_name(uint16_t page, uint16_t usage);
const char *lookup_usage_kinds(uint16_t page, uint16_t usage);

}  // namespace ble_client_hid
}  // namespace esphome
