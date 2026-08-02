#pragma once

#include <array>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "esphome/components/ble_client/ble_client.h"
#include "esphome/components/esp32_ble_tracker/esp32_ble_tracker.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/core/component.h"
#ifdef USE_API
#include "esphome/components/api/custom_api_device.h"
#endif

#include "hid_parser.h"
#include "boot_report_decoder.h"
#include "ordered_event_buffer.h"
#include "subscription_state.h"

#ifdef USE_ESP32

namespace esphome {
namespace ble_client_hid {

namespace espbt = esphome::esp32_ble_tracker;

enum class DiscoveryMode : uint8_t { STANDARD, FORENSIC };
enum class ProtocolModePolicy : uint8_t { UNCHANGED, REPORT, BOOT };

enum class SetupPhase : uint8_t {
  DISCONNECTED,
  WAITING_FOR_DISCOVERY,
  INVENTORY,
  READING,
  BUILDING_PROFILE,
  WRITING_PROTOCOL_MODE,
  REGISTERING,
  WAITING_FOR_CCCD,
  READY,
  DEGRADED,
  NO_HID,
};

struct GattDescriptorInfo {
  espbt::ESPBTUUID uuid;
  uint16_t handle{0};
};

struct GattCharacteristicInfo {
  espbt::ESPBTUUID uuid;
  uint16_t handle{0};
  uint8_t properties{0};
  uint16_t service_instance{0};
  std::vector<GattDescriptorInfo> descriptors;
};

struct GattIncludedServiceInfo {
  espbt::ESPBTUUID uuid;
  uint16_t declaration_handle{0};
  uint16_t start_handle{0};
  uint16_t end_handle{0};
};

struct GattServiceInfo {
  espbt::ESPBTUUID uuid;
  uint16_t instance{0};
  uint16_t start_handle{0};
  uint16_t end_handle{0};
  bool primary{true};
  std::vector<GattIncludedServiceInfo> included_services;
  std::vector<GattCharacteristicInfo> characteristics;
};

struct HIDServiceContext {
  uint16_t service_instance{0};
  uint16_t protocol_mode_handle{0};
  uint8_t protocol_mode{0xFF};
  std::string report_map_hash;
  std::unique_ptr<HIDReportMap> report_map;
};

enum class ReadPurpose : uint8_t {
  GENERIC_STANDARD,
  GENERIC_FORENSIC,
  DEVICE_NAME,
  APPEARANCE,
  PREFERRED_CONNECTION_PARAMETERS,
  BATTERY_LEVEL,
  PNP_ID,
  MANUFACTURER,
  SERIAL_NUMBER,
  HID_INFORMATION,
  HID_REPORT_MAP,
  HID_PROTOCOL_MODE,
  HID_REPORT_REFERENCE,
  HID_EXTERNAL_REPORT_REFERENCE,
  HID_REPORT_VALUE,
};

struct GattReadOperation {
  uint16_t handle{0};
  uint16_t characteristic_handle{0};
  uint16_t service_instance{0};
  ReadPurpose purpose{ReadPurpose::GENERIC_STANDARD};
  bool descriptor{false};
  bool required{false};
  espbt::ESPBTUUID service_uuid;
  espbt::ESPBTUUID characteristic_uuid;
  espbt::ESPBTUUID attribute_uuid;
};

struct PendingHIDReport {
  HIDReportSource source;
  std::vector<uint8_t> payload;
  uint64_t seq_id{0};
};

struct SubscriptionInfo {
  uint16_t characteristic_handle{0};
  uint16_t cccd_handle{0};
  uint16_t service_instance{0};
  uint8_t properties{0};
  bool required{false};
};

struct PendingAdvertisement {
  std::array<uint8_t, ESP_BLE_ADV_DATA_LEN_MAX + ESP_BLE_SCAN_RSP_DATA_LEN_MAX> bytes{};
  uint8_t advertisement_length{0};
  uint8_t scan_response_length{0};
  uint8_t address_type{0};
  int8_t rssi{0};
  bool available{false};
};

#ifdef USE_API
class BLEClientHID : public Component,
                     public api::CustomAPIDevice,
                     public ble_client::BLEClientNode,
                     public espbt::ESPBTDeviceListener {
#else
class BLEClientHID : public Component,
                     public ble_client::BLEClientNode,
                     public espbt::ESPBTDeviceListener {
#endif
 public:
  void loop() override;
  void dump_config() override;
  void gattc_event_handler(esp_gattc_cb_event_t event, esp_gatt_if_t gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;
  void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) override;
#ifdef USE_ESP32_BLE_DEVICE
  bool parse_device(const espbt::ESPBTDevice &device) override;
#endif
  float get_setup_priority() const override { return setup_priority::AFTER_BLUETOOTH; }

  void register_last_event_usage_text_sensor(text_sensor::TextSensor *sensor);
  void register_last_event_code_text_sensor(text_sensor::TextSensor *sensor);
  void register_last_event_value_sensor(sensor::Sensor *sensor);
  void register_battery_sensor(sensor::Sensor *sensor);
  void set_event_sampling_interval_us(uint32_t interval_us) { this->event_sampling_interval_us_ = interval_us; }
  void set_discovery_mode(DiscoveryMode mode) { this->discovery_mode_ = mode; }
  void set_protocol_mode_policy(ProtocolModePolicy policy) { this->protocol_mode_policy_ = policy; }

 protected:
  void reset_connection_state_();
  void transition_(SetupPhase phase);
  void mark_degraded_(const std::string &reason);
  void handle_phase_timeout_();

  bool inventory_gatt_database_();
  void plan_reads_();
  bool add_read_(const GattServiceInfo &service, const GattCharacteristicInfo &characteristic,
                 const GattDescriptorInfo *descriptor, ReadPurpose purpose, bool required);
  void start_next_read_();
  void finish_active_read_(esp_gatt_status_t status, const uint8_t *value, size_t length);
  void process_read_value_(const GattReadOperation &operation, const uint8_t *value, size_t length);
  void build_hid_profiles_();
  void log_hid_schema_(const HIDServiceContext &context) const;

  void start_protocol_mode_write_();
  void plan_subscriptions_();
  void start_next_subscription_();
  void handle_registration_result_(uint16_t handle, esp_gatt_status_t status);
  void handle_cccd_result_(uint16_t handle, esp_gatt_status_t status);
  void write_current_cccd_();
  void finalize_setup_();

  uint64_t log_raw_notification_(const esp_ble_gattc_cb_param_t::gattc_notify_evt_param &notification);
  void enqueue_input_report_(const esp_ble_gattc_cb_param_t::gattc_notify_evt_param &notification, uint64_t seq_id);
  void process_input_report_(PendingHIDReport report, const std::string &raw);
  void process_decoded_values_(const PendingHIDReport &report, const std::string &raw,
                               const std::vector<HIDReportItemValue> &values, HIDDecodeStatus status);
  HIDEvent make_hid_event_(const PendingHIDReport &report, const std::string &raw,
                           const HIDReportItemValue *value, HIDDecodeStatus status);
  void accumulate_event_(const PendingHIDReport &report, const std::string &raw,
                         const HIDReportItemValue &value, HIDDecodeStatus status);
  void update_sampling_window_();
  void flush_sampled_events_(const char *reason);
  void emit_hid_event_(HIDEvent event);

  void process_pending_advertisement_();
  void log_advertisement_elements_(const uint8_t *data, size_t length, const char *source) const;
  void request_rediscovery_();

  const GattCharacteristicInfo *find_characteristic_(uint16_t handle) const;
  const GattDescriptorInfo *find_descriptor_(const GattCharacteristicInfo &characteristic, uint16_t uuid) const;
  HIDServiceContext *find_hid_context_(uint16_t service_instance);
  const HIDServiceContext *find_hid_context_(uint16_t service_instance) const;
  static bool uuid16_(const espbt::ESPBTUUID &uuid, uint16_t expected);
  static std::string uuid_string_(const espbt::ESPBTUUID &uuid);
  static std::string sha256_(const uint8_t *data, size_t length);
  static std::string format_value_(const uint8_t *data, size_t length);

  std::vector<GattServiceInfo> services_;
  std::vector<HIDServiceContext> hid_services_;
  std::deque<GattReadOperation> read_queue_;
  std::unique_ptr<GattReadOperation> active_read_;
  std::deque<SubscriptionInfo> subscription_queue_;
  std::unique_ptr<SubscriptionInfo> active_subscription_;
  std::map<uint16_t, HIDReportSource> handle_report_source_;
  std::set<uint16_t> hid_report_handles_;
  std::set<uint16_t> battery_handles_;
  std::set<uint16_t> service_changed_handles_;
  std::set<uint16_t> planned_read_handles_;
  std::deque<PendingHIDReport> pending_reports_;
  size_t pending_report_bytes_{0};
  HIDBootReportDecoder boot_decoder_;

  text_sensor::TextSensor *last_event_usage_text_sensor_{nullptr};
  text_sensor::TextSensor *last_event_code_text_sensor_{nullptr};
  sensor::Sensor *last_event_value_sensor_{nullptr};
  sensor::Sensor *battery_sensor_{nullptr};

  SetupPhase setup_phase_{SetupPhase::DISCONNECTED};
  DiscoveryMode discovery_mode_{DiscoveryMode::STANDARD};
  ProtocolModePolicy protocol_mode_policy_{ProtocolModePolicy::UNCHANGED};
  uint32_t phase_started_ms_{0};
  uint32_t operations_succeeded_{0};
  uint32_t operations_failed_{0};
  bool degraded_{false};
  bool congested_{false};
  bool rediscovery_requested_{false};
  bool preferred_conn_params_valid_{false};
  esp_ble_conn_update_params_t preferred_conn_params_{};
  std::deque<uint16_t> protocol_write_handles_;
  SubscriptionAttemptState subscription_state_;

  std::string gatt_profile_hash_;
  PendingAdvertisement pending_advertisement_;
  std::array<uint8_t, ESP_BLE_ADV_DATA_LEN_MAX + ESP_BLE_SCAN_RSP_DATA_LEN_MAX> last_advertisement_{};
  uint8_t last_advertisement_length_{0};

  OrderedEventBuffer sampled_events_{16};
  uint32_t sampling_window_started_us_{0};
  uint32_t event_sampling_interval_us_{0};
  bool sampling_window_active_{false};
  uint32_t last_overflow_warning_{0};
  uint32_t reports_dropped_{0};
  uint64_t next_seq_id_{1};

  static constexpr size_t MAX_SERVICES = 64;
  static constexpr size_t MAX_INCLUDED_SERVICES = 128;
  static constexpr size_t MAX_CHARACTERISTICS = 256;
  static constexpr size_t MAX_DESCRIPTORS = 512;
  static constexpr size_t MAX_READ_OPERATIONS = 384;
  static constexpr size_t MAX_SUBSCRIPTIONS = 128;
  static constexpr size_t MAX_ATTRIBUTE_VALUE_BYTES = 4096;
  static constexpr size_t MAX_PENDING_REPORTS = 64;
  static constexpr size_t MAX_REPORT_PAYLOAD_BYTES = 512;
  static constexpr size_t MAX_PENDING_REPORT_BYTES = 4096;
  static constexpr size_t MAX_REPORTS_PER_LOOP = 8;
  static constexpr uint32_t MAX_PROCESSING_TIME_US = 4000;
  static constexpr uint32_t PHASE_TIMEOUT_MS = 15000;
  static constexpr uint32_t CCCD_FALLBACK_DELAY_MS = 250;
  static constexpr uint32_t OVERFLOW_WARNING_INTERVAL_MS = 5000;
};

}  // namespace ble_client_hid
}  // namespace esphome
#endif
