#include "bluetooth_e1.h"

#include <array>
#include <cstddef>

namespace esphome {
namespace ble_client_hid {

namespace {

using Block = std::array<uint8_t, 16>;
using KeySchedule = std::array<Block, 18>;

uint16_t power_mod_257(uint16_t base, uint16_t exponent) {
  uint16_t result = 1;
  while (exponent != 0) {
    if ((exponent & 1U) != 0) result = static_cast<uint16_t>((result * base) % 257U);
    base = static_cast<uint16_t>((base * base) % 257U);
    exponent >>= 1U;
  }
  return result;
}

struct SaferTables {
  std::array<uint8_t, 256> exponential{};
  std::array<uint8_t, 256> logarithm{};
  std::array<Block, 18> biases{};

  SaferTables() {
    for (uint16_t index = 0; index < 256; index++) {
      const uint8_t value = static_cast<uint8_t>(power_mod_257(45, index) % 256U);
      this->exponential[index] = value;
      this->logarithm[value] = static_cast<uint8_t>(index);
    }
    for (uint16_t round = 2; round < 18; round++)
      for (uint16_t index = 0; index < 16; index++) {
        const uint16_t exponent = power_mod_257(45, static_cast<uint16_t>(17U * round + index + 1U));
        this->biases[round][index] = static_cast<uint8_t>(power_mod_257(45, exponent) % 256U);
      }
  }
};

const SaferTables &tables() {
  static const SaferTables instance;
  return instance;
}

uint8_t rotate_left_3(uint8_t value) {
  return static_cast<uint8_t>((static_cast<uint16_t>(value) << 3U) | (value >> 5U));
}

KeySchedule key_schedule(const Block &key) {
  KeySchedule keys{};
  keys[1] = key;
  std::array<uint8_t, 17> state{};
  for (size_t index = 0; index < 16; index++) {
    state[index] = key[index];
    state[16] ^= key[index];
  }
  const auto &biases = tables().biases;
  for (size_t round = 2; round < 18; round++) {
    for (auto &byte : state) byte = rotate_left_3(byte);
    for (size_t index = 0; index < 16; index++)
      keys[round][index] = static_cast<uint8_t>(state[(round - 1U + index) % 17U] + biases[round][index]);
  }
  return keys;
}

bool xor_position(size_t index) {
  return index == 0 || index == 3 || index == 4 || index == 7 || index == 8 || index == 11 || index == 12 ||
         index == 15;
}

Block add_one(const Block &left, const Block &right) {
  Block result{};
  for (size_t index = 0; index < result.size(); index++)
    result[index] = xor_position(index) ? static_cast<uint8_t>(left[index] ^ right[index])
                                        : static_cast<uint8_t>(left[index] + right[index]);
  return result;
}

Block add_two(const Block &left, const Block &right) {
  Block result{};
  for (size_t index = 0; index < result.size(); index++)
    result[index] = xor_position(index) ? static_cast<uint8_t>(left[index] + right[index])
                                        : static_cast<uint8_t>(left[index] ^ right[index]);
  return result;
}

Block nonlinear_substitution(const Block &input) {
  Block result{};
  const auto &lookup = tables();
  for (size_t index = 0; index < result.size(); index++)
    result[index] = xor_position(index) ? lookup.exponential[input[index]] : lookup.logarithm[input[index]];
  return result;
}

Block pseudo_hadamard(const Block &input) {
  Block result{};
  for (size_t index = 0; index < result.size(); index += 2) {
    result[index] = static_cast<uint8_t>(2U * input[index] + input[index + 1]);
    result[index + 1] = static_cast<uint8_t>(input[index] + input[index + 1]);
  }
  return result;
}

Block permute(const Block &input) {
  constexpr std::array<uint8_t, 16> PERMUTATION{{8, 11, 12, 15, 2, 1, 6, 5, 10, 9, 14, 13, 0, 7, 4, 3}};
  Block result{};
  for (size_t index = 0; index < result.size(); index++) result[index] = input[PERMUTATION[index]];
  return result;
}

Block ar_rounds(const KeySchedule &keys, const Block &input, bool prime) {
  Block current = input;
  for (size_t round = 1; round <= 8; round++) {
    if (prime && round == 3) current = add_one(current, input);
    current = add_one(current, keys[2U * round - 1U]);
    current = nonlinear_substitution(current);
    current = add_two(current, keys[2U * round]);
    for (size_t layer = 0; layer < 4; layer++) {
      current = pseudo_hadamard(current);
      if (layer != 3) current = permute(current);
    }
  }
  return add_one(current, keys[17]);
}

Block transformed_key(const Block &key) {
  constexpr Block CONSTANTS{{233, 229, 223, 193, 179, 167, 149, 131, 233, 229, 223, 193, 179, 167, 149, 131}};
  Block result{};
  for (size_t index = 0; index < result.size(); index++) {
    const bool add = index == 0 || index == 2 || index == 4 || index == 6 || index == 9 || index == 11 ||
                     index == 13 || index == 15;
    result[index] = add ? static_cast<uint8_t>(key[index] + CONSTANTS[index])
                        : static_cast<uint8_t>(key[index] ^ CONSTANTS[index]);
  }
  return result;
}

}  // namespace

std::array<uint8_t, 16> bluetooth_e1(const std::array<uint8_t, 16> &key,
                                    const std::array<uint8_t, 16> &random,
                                    const std::array<uint8_t, 6> &address) {
  const Block ar = ar_rounds(key_schedule(key), random, false);
  Block prime_input{};
  for (size_t index = 0; index < prime_input.size(); index++)
    prime_input[index] = static_cast<uint8_t>(address[index % address.size()] + (ar[index] ^ random[index]));
  return ar_rounds(key_schedule(transformed_key(key)), prime_input, true);
}

}  // namespace ble_client_hid
}  // namespace esphome
