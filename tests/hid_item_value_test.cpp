#include <cassert>

#include "hid_item_value.h"

using esphome::ble_client_hid::decode_signed_hid_item;
using esphome::ble_client_hid::hid_item_data_size;

int main() {
  assert(decode_signed_hid_item(0xF801, 0x16) == -2047);
  assert(decode_signed_hid_item(0x81, 0x15) == -127);

  assert(decode_signed_hid_item(0x07FF, 0x26) == 2047);
  assert(decode_signed_hid_item(0x7F, 0x25) == 127);
  assert(decode_signed_hid_item(0xFFFFFFFF, 0x17) == -1);

  assert(hid_item_data_size(0x14) == 0);
  assert(hid_item_data_size(0x15) == 1);
  assert(hid_item_data_size(0x16) == 2);
  assert(hid_item_data_size(0x17) == 4);
}
