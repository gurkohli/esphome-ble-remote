#include <array>
#include <cassert>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "forensic_web_logging/bluetooth_e1.h"
#include "forensic_web_logging/forensic_transaction.h"

using namespace esphome::ble_client_hid;

template<size_t N> std::array<uint8_t, N> fixed_hex(const char *text) {
  std::vector<uint8_t> parsed;
  std::string error;
  assert(parse_forensic_hex(text, N, parsed, error));
  assert(parsed.size() == N);
  std::array<uint8_t, N> result{};
  std::copy(parsed.begin(), parsed.end(), result.begin());
  return result;
}

int main() {
  ForensicTransactionResponseRecorder responses;
  responses.reset(1000);
  const uint8_t full_response[]{0xFE, 0xDC, 0xBA, 0x00, 0x03, 0x00, 0x02, 0x00, 0x12, 0xEF};
  assert(responses.append(1025, 11, 0x0084, true, true, full_response, sizeof(full_response)));
  assert(responses.complete());
  assert(responses.dropped() == 0);
  assert(responses.events().size() == 1);
  assert(responses.events()[0].sequence == 1);
  assert(responses.events()[0].offset_ms == 25);
  assert(responses.events()[0].step == 11);
  assert(responses.events()[0].handle == 0x0084);
  assert(responses.events()[0].is_notify);
  assert(responses.events()[0].matched);
  assert((responses.events()[0].value ==
          std::vector<uint8_t>(full_response, full_response + sizeof(full_response))));

  const uint8_t continuation[]{0x01, 0x02, 0x03};
  assert(responses.append(1030, 12, 0x0084, false, false, continuation, sizeof(continuation)));
  assert(responses.events()[1].sequence == 2);
  assert(!responses.events()[1].is_notify);
  assert(!responses.events()[1].matched);
  assert((responses.events()[1].value == std::vector<uint8_t>{0x01, 0x02, 0x03}));

  responses.reset(2000);
  for (size_t index = 0; index < FORENSIC_TRANSACTION_MAX_RESPONSE_EVENTS; index++)
    assert(responses.append(2000 + index, index + 1, 0x0084, true, false, continuation, sizeof(continuation)));
  assert(!responses.append(3000, 1, 0x0084, true, false, continuation, sizeof(continuation)));
  assert(!responses.complete());
  assert(responses.dropped() == 1);

  responses.reset(3000);
  std::vector<uint8_t> oversized(FORENSIC_TRANSACTION_MAX_VALUE_BYTES + 1, 0xAA);
  assert(!responses.append(3001, 1, 0x0084, true, false, oversized.data(), oversized.size()));
  assert(responses.events().empty());
  assert(responses.dropped() == 1);

  ForensicRecipeBodyBuffer request_body;
  const std::string json = R"({"version":1,"steps":[]})";
  request_body.append(reinterpret_cast<const uint8_t *>(json.data()), 10, 0, json.size());
  request_body.append(reinterpret_cast<const uint8_t *>(json.data() + 10), json.size() - 10, 10, json.size());
  assert(request_body.complete());
  assert(request_body.take() == json);
  assert(!request_body.started());

  const uint8_t byte = 0;
  request_body.append(&byte, 1, 0, FORENSIC_TRANSACTION_MAX_RECIPE_BYTES + 1);
  assert(request_body.too_large());
  assert(!request_body.complete());
  request_body.reset();
  request_body.append(&byte, 1, 1, 1);
  assert(request_body.malformed());
  assert(!request_body.complete());

  std::vector<uint8_t> value;
  std::string error;
  assert(parse_forensic_hex("01 23:45-67,89", 5, value, error));
  assert((value == std::vector<uint8_t>{0x01, 0x23, 0x45, 0x67, 0x89}));
  assert(error.empty());
  assert(parse_forensic_hex("", 20, value, error, true) && value.empty());

  assert(!parse_forensic_hex("", 20, value, error));
  assert(!parse_forensic_hex("ABC", 20, value, error));
  assert(!parse_forensic_hex("00GG", 20, value, error));
  assert(!parse_forensic_hex("0011", 1, value, error));

  uint16_t number = 0;
  assert(parse_forensic_u16("0", number) && number == 0);
  assert(parse_forensic_u16("65535", number) && number == 65535);
  assert(!parse_forensic_u16("65536", number));
  assert(!parse_forensic_u16("18446744073709551616", number));
  assert(!parse_forensic_u16("12x", number));
  assert(!parse_forensic_u16("", number));

  assert(forensic_variable_name_valid("challenge_1"));
  assert(forensic_variable_name_valid("_private"));
  assert(!forensic_variable_name_valid("1challenge"));
  assert(!forensic_variable_name_valid("has-dash"));
  assert(!forensic_variable_name_valid(std::string(33, 'a')));

  std::map<std::string, ForensicTransactionVariable> variables;
  variables["challenge"].value = {0x10, 0x20, 0x30, 0x40};
  ForensicValuePart prefix;
  prefix.literal = {0x00};
  ForensicValuePart slice;
  slice.kind = ForensicValuePartKind::VARIABLE;
  slice.variable = "challenge";
  slice.offset = 1;
  slice.length = 2;
  assert(compose_forensic_value({prefix, slice}, variables, 20, value, error));
  assert((value == std::vector<uint8_t>{0x00, 0x20, 0x30}));
  assert(!compose_forensic_value({prefix, slice}, variables, 2, value, error));

  ForensicNotificationMatcher matcher;
  matcher.handle = 42;
  matcher.offset = 1;
  matcher.value = {0xA0, 0x05};
  matcher.mask = {0xF0, 0xFF};
  matcher.has_exact_length = true;
  matcher.exact_length = 4;
  matcher.captures.push_back({"captured", 1, 2, false});
  const uint8_t notification[]{0x00, 0xAF, 0x05, 0x99};
  assert(forensic_notification_matches(matcher, 42, true, notification, sizeof(notification)));
  assert(!forensic_notification_matches(matcher, 43, true, notification, sizeof(notification)));
  assert(!forensic_notification_matches(matcher, 42, true, notification, 3));
  assert(apply_forensic_captures(matcher, notification, sizeof(notification), variables, error));
  assert((variables["captured"].value == std::vector<uint8_t>{0xAF, 0x05}));

  const auto key = fixed_hex<16>("06775F87918DD423005DF1D8CF0C142B");
  const auto address = fixed_hex<6>("112233332211");
  const auto published_random = fixed_hex<16>("ABB2CDC69BB454110E827441213DDC87");
  const auto published_result = fixed_hex<16>("61721F97C869523CCCE093D7F849CA02");
  assert(bluetooth_e1(key, published_random, address) == published_result);

  const auto observed_random = fixed_hex<16>("75CC8A2182DEC544972B6A7E8CDA52B3");
  const auto observed_result = fixed_hex<16>("D17F230884D8DC987E4FB9132D9191A4");
  assert(bluetooth_e1(key, observed_random, address) == observed_result);
}
