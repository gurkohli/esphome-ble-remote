#include "forensic_transaction.h"

#include <cctype>
#include <limits>

namespace esphome {
namespace ble_client_hid {

void ForensicTransactionResponseRecorder::reset(uint32_t started_ms) {
  this->events_.clear();
  this->started_ms_ = started_ms;
  this->next_sequence_ = 1;
  this->dropped_ = 0;
}

bool ForensicTransactionResponseRecorder::append(uint32_t now, size_t step, uint16_t handle, bool is_notify,
                                                 bool matched, const uint8_t *value, size_t length) {
  if ((value == nullptr && length != 0) || length > FORENSIC_TRANSACTION_MAX_VALUE_BYTES ||
      this->events_.size() >= FORENSIC_TRANSACTION_MAX_RESPONSE_EVENTS) {
    this->dropped_++;
    return false;
  }
  ForensicTransactionResponse response;
  response.sequence = this->next_sequence_++;
  response.offset_ms = now - this->started_ms_;
  response.step = step;
  response.handle = handle;
  response.is_notify = is_notify;
  response.matched = matched;
  if (length != 0) response.value.assign(value, value + length);
  this->events_.push_back(std::move(response));
  return true;
}

void ForensicRecipeBodyBuffer::append(const uint8_t *data, size_t length, size_t index, size_t total) {
  if (index == 0) {
    this->reset();
    this->started_ = true;
    this->expected_size_ = total;
    this->too_large_ = total > FORENSIC_TRANSACTION_MAX_RECIPE_BYTES;
    this->malformed_ = total == 0;
    if (!this->too_large_ && !this->malformed_) this->body_.reserve(total);
  } else if (!this->started_) {
    this->started_ = true;
    this->expected_size_ = total;
    this->malformed_ = true;
    return;
  }
  if (!this->started_ || this->too_large_ || this->malformed_) return;
  if ((data == nullptr && length != 0) || total != this->expected_size_ || index != this->body_.size() ||
      index > total || length > total - index) {
    this->malformed_ = true;
    this->body_.clear();
    return;
  }
  if (length != 0) this->body_.append(reinterpret_cast<const char *>(data), length);
}

void ForensicRecipeBodyBuffer::reset() {
  this->body_.clear();
  this->expected_size_ = 0;
  this->started_ = false;
  this->too_large_ = false;
  this->malformed_ = false;
}

bool ForensicRecipeBodyBuffer::complete() const {
  return this->started_ && !this->too_large_ && !this->malformed_ && this->body_.size() == this->expected_size_;
}

std::string ForensicRecipeBodyBuffer::take() {
  std::string result = std::move(this->body_);
  this->reset();
  return result;
}

bool parse_forensic_hex(const std::string &input, size_t maximum_bytes, std::vector<uint8_t> &output,
                        std::string &error, bool allow_empty) {
  output.clear();
  std::string digits;
  digits.reserve(input.size());
  for (const unsigned char character : input) {
    if (std::isxdigit(character)) {
      digits.push_back(static_cast<char>(character));
    } else if (!std::isspace(character) && character != ':' && character != '-' && character != ',') {
      error = "Value must contain only hexadecimal bytes and separators.";
      return false;
    }
  }
  if (digits.empty() && !allow_empty) {
    error = "Value must contain at least one byte.";
    return false;
  }
  if ((digits.size() & 1U) != 0) {
    error = "Value must contain complete two-digit hexadecimal bytes.";
    return false;
  }
  if (digits.size() / 2 > maximum_bytes) {
    error = "Value exceeds the configured byte limit.";
    return false;
  }
  output.reserve(digits.size() / 2);
  auto nibble = [](char value) -> uint8_t {
    if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
    if (value >= 'a' && value <= 'f') return static_cast<uint8_t>(value - 'a' + 10);
    return static_cast<uint8_t>(value - 'A' + 10);
  };
  for (size_t index = 0; index < digits.size(); index += 2)
    output.push_back(static_cast<uint8_t>((nibble(digits[index]) << 4) | nibble(digits[index + 1])));
  error.clear();
  return true;
}

bool parse_forensic_u16(const std::string &input, uint16_t &output) {
  if (input.empty()) return false;
  uint32_t value = 0;
  for (const char character : input) {
    if (character < '0' || character > '9') return false;
    const uint32_t digit = static_cast<uint32_t>(character - '0');
    if (value > (std::numeric_limits<uint16_t>::max() - digit) / 10U) return false;
    value = value * 10U + digit;
  }
  output = static_cast<uint16_t>(value);
  return true;
}

bool forensic_variable_name_valid(const std::string &name) {
  if (name.empty() || name.size() > 32) return false;
  const unsigned char first = static_cast<unsigned char>(name.front());
  if (std::isalpha(first) == 0 && first != '_') return false;
  for (const unsigned char character : name)
    if (std::isalnum(character) == 0 && character != '_') return false;
  return true;
}

bool compose_forensic_value(const std::vector<ForensicValuePart> &parts,
                            const std::map<std::string, ForensicTransactionVariable> &variables,
                            size_t maximum_bytes, std::vector<uint8_t> &output, std::string &error) {
  output.clear();
  for (const auto &part : parts) {
    const std::vector<uint8_t> *source = &part.literal;
    size_t offset = 0;
    size_t length = part.literal.size();
    if (part.kind == ForensicValuePartKind::VARIABLE) {
      const auto variable = variables.find(part.variable);
      if (variable == variables.end()) {
        error = "Value references an unavailable variable: " + part.variable;
        return false;
      }
      source = &variable->second.value;
      offset = part.offset;
      if (offset > source->size()) {
        error = "Variable slice offset is outside: " + part.variable;
        return false;
      }
      length = part.to_end ? source->size() - offset : part.length;
      if (length > source->size() - offset) {
        error = "Variable slice length is outside: " + part.variable;
        return false;
      }
    }
    if (length > maximum_bytes - output.size()) {
      error = "Composed value exceeds the current ATT write limit.";
      output.clear();
      return false;
    }
    output.insert(output.end(), source->begin() + static_cast<std::ptrdiff_t>(offset),
                  source->begin() + static_cast<std::ptrdiff_t>(offset + length));
  }
  if (output.empty()) {
    error = "Composed value must contain at least one byte.";
    return false;
  }
  error.clear();
  return true;
}

bool forensic_notification_matches(const ForensicNotificationMatcher &matcher, uint16_t handle, bool is_notify,
                                   const uint8_t *value, size_t length) {
  if (handle != matcher.handle || (is_notify && !matcher.accept_notify) || (!is_notify && !matcher.accept_indicate))
    return false;
  if (value == nullptr && length != 0) return false;
  if (length > FORENSIC_TRANSACTION_MAX_VALUE_BYTES) return false;
  if (matcher.has_exact_length && length != matcher.exact_length) return false;
  if (matcher.offset > length || matcher.value.size() > length - matcher.offset) return false;
  if (!matcher.allow_any && matcher.value.empty()) return false;
  for (size_t index = 0; index < matcher.value.size(); index++) {
    const uint8_t mask = matcher.mask.empty() ? 0xFF : matcher.mask[index];
    if ((value[matcher.offset + index] & mask) != (matcher.value[index] & mask)) return false;
  }
  return true;
}

bool apply_forensic_captures(const ForensicNotificationMatcher &matcher, const uint8_t *value, size_t length,
                             std::map<std::string, ForensicTransactionVariable> &variables, std::string &error) {
  if (value == nullptr && length != 0) {
    error = "Matched notification has a null payload.";
    return false;
  }
  for (const auto &capture : matcher.captures) {
    if (capture.offset > length || capture.length > length - capture.offset) {
      error = "Capture range is outside the matched notification: " + capture.variable;
      return false;
    }
    ForensicTransactionVariable variable;
    variable.secret = capture.secret;
    variable.value.assign(value + capture.offset, value + capture.offset + capture.length);
    variables[capture.variable] = std::move(variable);
  }
  error.clear();
  return true;
}

}  // namespace ble_client_hid
}  // namespace esphome
