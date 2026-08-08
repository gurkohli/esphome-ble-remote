#pragma once

#include <array>
#include <cstdint>

namespace esphome {
namespace ble_client_hid {

// Computes the 128-bit SRES || ACO output of the Bluetooth legacy E1
// authentication function (Core Specification, Vol 2, Part H, section 6.1).
std::array<uint8_t, 16> bluetooth_e1(const std::array<uint8_t, 16> &key,
                                    const std::array<uint8_t, 16> &random,
                                    const std::array<uint8_t, 6> &address);

}  // namespace ble_client_hid
}  // namespace esphome
