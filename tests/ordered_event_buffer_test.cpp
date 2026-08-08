#include <cassert>
#include <cstdint>
#include <limits>
#include <string>

#include "ordered_event_buffer.h"

using namespace esphome::ble_client_hid;

static HIDEvent event(const char *usage, int64_t value) {
  HIDEvent result;
  result.data = {{"usage", usage}, {"value", std::to_string(value)}, {"raw_value", std::to_string(value)},
                 {"seq_id_from", std::to_string(value)}, {"seq_id_to", std::to_string(value)}};
  return result;
}

int main() {
  const SampledEventKey x{0, 8, 2, 1};
  const SampledEventKey y{0, 20, 2, 1};
  const SampledEventKey dial{0, 8, 3, 1};

  OrderedEventBuffer buffer(3);
  assert(buffer.accumulate(y, HIDReportItemValue::Aggregation::SUM, 2, 2, event("Y", 2)));
  assert(buffer.accumulate(x, HIDReportItemValue::Aggregation::SUM, 3, 3, event("X", 3)));
  assert(buffer.accumulate(y, HIDReportItemValue::Aggregation::SUM, 4, 4, event("Y", 4)));
  assert(buffer.accumulate(dial, HIDReportItemValue::Aggregation::LATEST, 7, 7, event("Dial", 7)));
  assert(buffer.accumulate(dial, HIDReportItemValue::Aggregation::LATEST, 9, 9, event("Dial", 9)));

  auto flushed = buffer.drain_before(event("Release", 0));
  assert(flushed.size() == 4);
  // A flush follows first-observed order, never key-sorted order.
  assert(flushed[0].data.at("usage") == "Y" && flushed[0].data.at("value") == "6");
  assert(flushed[0].data.at("seq_id_from") == "2");
  assert(flushed[0].data.at("seq_id_to") == "4");
  assert(flushed[1].data.at("usage") == "X" && flushed[1].data.at("value") == "3");
  assert(flushed[2].data.at("usage") == "Dial" && flushed[2].data.at("value") == "9");
  assert(flushed[3].data.at("usage") == "Release");
  // Capacity is explicit, and relative accumulation cannot wrap around.
  OrderedEventBuffer bounded(1);
  assert(bounded.accumulate(x, HIDReportItemValue::Aggregation::SUM,
                            std::numeric_limits<int64_t>::max(), 1, event("X", 1)));
  assert(bounded.accumulate(x, HIDReportItemValue::Aggregation::SUM, 1, 1, event("X", 1)));
  assert(!bounded.accumulate(y, HIDReportItemValue::Aggregation::SUM, 1, 1, event("Y", 1)));
  flushed = bounded.drain();
  assert(flushed[0].data.at("value") == std::to_string(std::numeric_limits<int64_t>::max()));

  OrderedEventBuffer duplicate_fields(4);
  assert(duplicate_fields.accumulate({0, 8, 1, 1}, HIDReportItemValue::Aggregation::SUM, 1, 1,
                                     event("Button", 1)));
  assert(duplicate_fields.accumulate({0, 9, 1, 1}, HIDReportItemValue::Aggregation::SUM, 1, 1,
                                     event("Button", 1)));
  assert(duplicate_fields.size() == 2);
}
