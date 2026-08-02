#include <cassert>
#include <cstring>

#include "usages.h"

using namespace esphome::ble_client_hid;

int main() {
  assert(std::strcmp(HID_USAGE_TABLE_VERSION, "1.7.0") == 0);
  assert(std::strcmp(lookup_usage_page_name(0x01), "Generic Desktop") == 0);
  assert(std::strcmp(lookup_usage_name(0x01, 0x30), "X") == 0);
  assert(std::strcmp(lookup_usage_kinds(0x01, 0x30), "DV") == 0);
  // FIDO Alliance proves that usage-page lookup is not truncated to 8 bits.
  assert(std::strcmp(lookup_usage_page_name(0xF1D0), "FIDO Alliance") == 0);
  assert(std::strcmp(lookup_usage_name(0xF1D0, 0x01), "U2F Authenticator Device") == 0);
  assert(lookup_usage_page_name(0xFFFF) == nullptr);
  assert(lookup_usage_name(0x01, 0xFFFF) == nullptr);
}
