#include <cassert>
#include <cstdint>
#include <limits>

#include "subscription_state.h"

using namespace esphome::ble_client_hid;

int main() {
  SubscriptionAttemptState state;
  state.begin(10, 11);
  assert(state.registration_result(99, true, 100, 250) == SubscriptionDecision::UNMATCHED);
  assert(state.registration_result(10, true, 100, 250) == SubscriptionDecision::WAIT_FOR_CCCD);
  assert(!state.fallback_due(349));
  assert(state.cccd_result(99, true) == SubscriptionDecision::UNMATCHED);
  assert(state.cccd_result(11, true) == SubscriptionDecision::COMPLETE);

  // V3 clients do not receive a framework-owned CCCD write; the deadline
  // therefore hands ownership to the component exactly once.
  state.begin(20, 21);
  assert(state.registration_result(20, true, 500, 250) == SubscriptionDecision::WAIT_FOR_CCCD);
  assert(state.fallback_due(750));
  state.own_cccd_write_attempted();
  assert(!state.fallback_due(751));
  assert(state.cccd_result(21, true) == SubscriptionDecision::COMPLETE);

  // A failed framework-owned write requests one component-owned retry. A
  // failure of that retry is terminal for this subscription attempt.
  state.begin(30, 31);
  assert(state.registration_result(30, true, 1000, 250) == SubscriptionDecision::WAIT_FOR_CCCD);
  assert(state.cccd_result(31, false) == SubscriptionDecision::RETRY_CCCD);
  state.own_cccd_write_attempted();
  assert(state.cccd_result(31, false) == SubscriptionDecision::FAILED);

  state.begin(40, 41);
  assert(state.registration_result(40, false, 0, 250) == SubscriptionDecision::FAILED);
  assert(state.cccd_result(41, true) == SubscriptionDecision::UNMATCHED);

  // Deadline comparisons remain correct when millis() wraps.
  state.begin(50, 51);
  constexpr uint32_t NEAR_WRAP = std::numeric_limits<uint32_t>::max() - 100;
  assert(state.registration_result(50, true, NEAR_WRAP, 250) == SubscriptionDecision::WAIT_FOR_CCCD);
  assert(!state.fallback_due(100));
  assert(state.fallback_due(149));
}
