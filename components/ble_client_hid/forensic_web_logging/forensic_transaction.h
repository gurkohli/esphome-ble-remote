#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace esphome {
namespace ble_client_hid {

constexpr size_t FORENSIC_TRANSACTION_MAX_STEPS = 64;
constexpr size_t FORENSIC_TRANSACTION_MAX_TARGETS = 24;
constexpr size_t FORENSIC_TRANSACTION_MAX_VARIABLES = 48;
constexpr size_t FORENSIC_TRANSACTION_MAX_VALUE_BYTES = 512;
constexpr size_t FORENSIC_TRANSACTION_MAX_RESPONSE_EVENTS = 128;
constexpr size_t FORENSIC_TRANSACTION_MAX_RECIPE_BYTES = 16384;
constexpr uint32_t FORENSIC_TRANSACTION_MAX_STEP_TIMEOUT_MS = 60000;
constexpr uint32_t FORENSIC_TRANSACTION_MAX_RUNTIME_MS = 120000;

class ForensicRecipeBodyBuffer {
 public:
  void append(const uint8_t *data, size_t length, size_t index, size_t total);
  void reset();
  bool started() const { return this->started_; }
  bool complete() const;
  bool too_large() const { return this->too_large_; }
  bool malformed() const { return this->malformed_; }
  std::string take();

 protected:
  std::string body_;
  size_t expected_size_{0};
  bool started_{false};
  bool too_large_{false};
  bool malformed_{false};
};

enum class ForensicTargetKind : uint8_t { CHARACTERISTIC, DESCRIPTOR, NOTIFICATION };
enum class ForensicWriteMode : uint8_t { WITH_RESPONSE, WITHOUT_RESPONSE };
enum class ForensicValuePartKind : uint8_t { LITERAL, VARIABLE };
enum class ForensicStepKind : uint8_t {
  WRITE,
  EXCHANGE,
  WAIT_NOTIFICATION,
  REQUIRE_NOTIFICATION,
  RANDOM_BYTES,
  TRANSFORM_BT_E1,
  ASSERT_EQUAL,
  DELAY,
};

struct ForensicTransactionTarget {
  std::string name;
  ForensicTargetKind kind{ForensicTargetKind::CHARACTERISTIC};
  uint16_t service_start_handle{0};
  uint16_t service_instance{0};
  uint16_t characteristic_handle{0};
  uint16_t attribute_handle{0};
  ForensicWriteMode write_mode{ForensicWriteMode::WITH_RESPONSE};
  bool notification_enabled{false};
};

struct ForensicTransactionVariable {
  std::vector<uint8_t> value;
  bool secret{false};
};

struct ForensicValuePart {
  ForensicValuePartKind kind{ForensicValuePartKind::LITERAL};
  std::vector<uint8_t> literal;
  std::string variable;
  size_t offset{0};
  size_t length{0};
  bool to_end{false};
};

struct ForensicNotificationCapture {
  std::string variable;
  size_t offset{0};
  size_t length{0};
  bool secret{false};
};

struct ForensicNotificationMatcher {
  uint16_t handle{0};
  bool accept_notify{true};
  bool accept_indicate{true};
  size_t offset{0};
  std::vector<uint8_t> value;
  std::vector<uint8_t> mask;
  size_t exact_length{0};
  bool has_exact_length{false};
  bool allow_any{false};
  std::vector<ForensicNotificationCapture> captures;
};

struct ForensicTransactionStep {
  ForensicStepKind kind{ForensicStepKind::WRITE};
  std::string target;
  std::vector<ForensicValuePart> value;
  ForensicNotificationMatcher matcher;
  uint32_t timeout_ms{15000};
  uint32_t delay_ms{0};
  size_t output_length{0};
  bool output_secret{false};
  std::string key_variable;
  std::string random_variable;
  std::string address_variable;
  std::string output_variable;
  std::string left_variable;
  std::string right_variable;
};

struct ForensicTransactionRecipe {
  uint32_t sequence{0};
  std::string name;
  std::string profile_hash;
  std::map<std::string, ForensicTransactionTarget> targets;
  std::map<std::string, ForensicTransactionVariable> variables;
  std::vector<ForensicTransactionStep> steps;
};

struct ForensicTransactionResponse {
  uint32_t sequence{0};
  uint32_t offset_ms{0};
  size_t step{0};
  uint16_t handle{0};
  bool is_notify{true};
  bool matched{false};
  std::vector<uint8_t> value;
};

class ForensicTransactionResponseRecorder {
 public:
  void reset(uint32_t started_ms = 0);
  bool append(uint32_t now, size_t step, uint16_t handle, bool is_notify, bool matched,
              const uint8_t *value, size_t length);
  const std::vector<ForensicTransactionResponse> &events() const { return this->events_; }
  size_t dropped() const { return this->dropped_; }
  bool complete() const { return this->dropped_ == 0; }

 protected:
  std::vector<ForensicTransactionResponse> events_;
  uint32_t started_ms_{0};
  uint32_t next_sequence_{1};
  size_t dropped_{0};
};

bool parse_forensic_hex(const std::string &input, size_t maximum_bytes, std::vector<uint8_t> &output,
                        std::string &error, bool allow_empty = false);
bool parse_forensic_u16(const std::string &input, uint16_t &output);
bool forensic_variable_name_valid(const std::string &name);
bool compose_forensic_value(const std::vector<ForensicValuePart> &parts,
                            const std::map<std::string, ForensicTransactionVariable> &variables,
                            size_t maximum_bytes, std::vector<uint8_t> &output, std::string &error);
bool forensic_notification_matches(const ForensicNotificationMatcher &matcher, uint16_t handle, bool is_notify,
                                   const uint8_t *value, size_t length);
bool apply_forensic_captures(const ForensicNotificationMatcher &matcher, const uint8_t *value, size_t length,
                             std::map<std::string, ForensicTransactionVariable> &variables, std::string &error);

}  // namespace ble_client_hid
}  // namespace esphome
