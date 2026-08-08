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

#include "boot_report_decoder.h"
#include "hid_parser.h"
#include "ordered_event_buffer.h"
#include "subscription_state.h"
#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
#include "forensic_web_logging/forensic_transaction.h"
#endif

#ifdef USE_ESP32

namespace esphome {
#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
namespace web_server_idf {
class AsyncWebServerRequest;
}
#endif
namespace ble_client_hid {

namespace espbt = esphome::esp32_ble_tracker;

enum class DiscoveryMode : uint8_t { STANDARD, FORENSIC };
enum class ProtocolModePolicy : uint8_t { UNCHANGED, REPORT, BOOT };

#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
class ForensicResponseWriter {
 public:
  explicit ForensicResponseWriter(web_server_idf::AsyncWebServerRequest *request)
      : request_(request), buffer_(BUFFER_SIZE) {}

  void print(const char *value);
  void print(const std::string &value) { this->append_(value.data(), value.size()); }
  void write(uint8_t value);
  bool finish();

 protected:
  static constexpr size_t BUFFER_SIZE = 1024;
  void append_(const char *data, size_t length);
  bool flush_();

  web_server_idf::AsyncWebServerRequest *request_;
  std::vector<char> buffer_;
  size_t buffer_length_{0};
  bool failed_{false};
};
#endif

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
  bool read_planned{false};
  bool read_complete{false};
  bool read_succeeded{false};
  int read_status{-1};
  size_t value_length{0};
  bool value_truncated{false};
  std::vector<uint8_t> value;
};

struct GattCharacteristicInfo {
  espbt::ESPBTUUID uuid;
  uint16_t handle{0};
  uint8_t properties{0};
  uint16_t service_instance{0};
  std::vector<GattDescriptorInfo> descriptors;
  bool read_planned{false};
  bool read_complete{false};
  bool read_succeeded{false};
  int read_status{-1};
  size_t value_length{0};
  bool value_truncated{false};
  std::vector<uint8_t> value;
  bool subscription_planned{false};
  bool subscription_complete{false};
  bool subscription_enabled{false};
  int subscription_status{-1};
  uint16_t cccd_handle{0};
  bool registration_complete{false};
  bool registration_succeeded{false};
  int registration_status{-1};
  bool registration_status_is_esp_err{false};
  bool cccd_write_complete{false};
  bool cccd_write_succeeded{false};
  int cccd_write_status{-1};
  bool cccd_write_status_is_esp_err{false};
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

#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
struct ForensicOperation {
  uint32_t sequence{0};
  uint32_t offset_ms{0};
  std::string type;
  std::string stage;
  uint16_t handle{0};
  uint16_t related_handle{0};
  std::string status_domain;
  int status{-1};
  bool complete{false};
  bool succeeded{false};
  size_t value_length{0};
  bool value_truncated{false};
  bool value_redacted{false};
  std::vector<uint8_t> value;
};

struct ForensicGattWrite {
  uint32_t sequence{0};
  size_t step_index{0};
  uint32_t started_ms{0};
  bool timed_out{false};
  bool descriptor{false};
  uint16_t characteristic_handle{0};
  uint16_t attribute_handle{0};
  bool with_response{true};
  bool value_secret{false};
  std::vector<uint8_t> value;
};

struct ForensicTransactionRuntime {
  ForensicTransactionRecipe recipe;
  size_t step_index{0};
  uint32_t started_ms{0};
  uint32_t step_started_ms{0};
  bool step_started{false};
  bool write_complete{false};
  bool notification_received{false};
  std::vector<uint8_t> notification_value;
};

struct ForensicTransactionStatus {
  bool available{false};
  uint32_t sequence{0};
  std::string name;
  std::string stage;
  std::string message;
  std::string status_domain;
  int status{-1};
  size_t current_step{0};
  size_t total_steps{0};
  uint32_t started_ms{0};
  uint32_t finished_ms{0};
  bool complete{false};
  bool succeeded{false};
  bool abortable{false};
  bool write_blocked{false};
  bool reconnect_required{false};
};
#endif

#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
class ForensicWebHandler;
class BLEClientHID;
void register_forensic_web_handler(BLEClientHID *client, const std::string &base_path);
#endif

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
  void setup() override;
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
#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
  void enable_forensic_web_logging(std::string path) { this->forensic_web_path_ = std::move(path); }
#endif

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
#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
  void render_gatt_tree_(ForensicResponseWriter &response);
  void render_gatt_json_(ForensicResponseWriter &response);
  void render_recorder_json_(ForensicResponseWriter &response);
  bool forensic_web_logging_enabled_() const { return !this->forensic_web_path_.empty(); }
  size_t forensic_transaction_payload_limit_() const;
  void process_forensic_transaction_();
  bool finish_forensic_transaction_write_(bool descriptor, uint16_t handle, esp_gatt_status_t status);
  void process_forensic_transaction_notification_(uint16_t handle, bool is_notify, const uint8_t *value,
                                                  size_t length);
  void fail_forensic_transaction_(const std::string &stage, const std::string &message,
                                  const char *status_domain = "local", int status = -1);
  void complete_forensic_transaction_();
  void advance_forensic_transaction_();
  bool abort_forensic_transaction_();
  void publish_forensic_snapshot_();
  void record_forensic_operation_(const char *type, const char *stage, uint16_t handle, uint16_t related_handle,
                                  const char *status_domain, int status, bool complete, bool succeeded,
                                  const uint8_t *value = nullptr, size_t length = 0, bool value_redacted = false);
  void record_forensic_operation_locked_(const char *type, const char *stage, uint16_t handle,
                                         uint16_t related_handle, const char *status_domain, int status,
                                         bool complete, bool succeeded, const uint8_t *value = nullptr,
                                         size_t length = 0, bool value_redacted = false);
#endif
  void record_read_result_(const GattReadOperation &operation, bool complete, bool succeeded, int status,
                           const uint8_t *value = nullptr, size_t length = 0);

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
  GattCharacteristicInfo *find_characteristic_(uint16_t handle);
  const GattDescriptorInfo *find_descriptor_(const GattCharacteristicInfo &characteristic, uint16_t uuid) const;
  GattDescriptorInfo *find_descriptor_by_handle_(uint16_t handle);
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
  bool negotiated_conn_params_available_{false};
  int negotiated_conn_params_status_{-1};
  float negotiated_interval_ms_{0};
  uint16_t negotiated_latency_{0};
  float negotiated_timeout_ms_{0};
  bool negotiated_mtu_available_{false};
  int negotiated_mtu_status_{-1};
  uint16_t negotiated_mtu_{0};
  std::deque<uint16_t> protocol_write_handles_;
  SubscriptionAttemptState subscription_state_;

  std::string gatt_profile_hash_;
  std::map<std::string, std::string> device_metadata_;
#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
  friend class ForensicWebHandler;

  bool forensic_snapshot_available_{false};
  std::string forensic_web_path_;
  Mutex forensic_export_mutex_;
  std::vector<ForensicOperation> forensic_operations_;
  uint32_t forensic_operations_dropped_{0};
  uint32_t forensic_capture_started_ms_{0};
  uint32_t forensic_capture_completed_ms_{0};
  uint32_t forensic_next_operation_sequence_{1};
  std::vector<ForensicOperation> forensic_recording_events_;
  uint32_t forensic_recording_events_dropped_{0};
  uint32_t forensic_recording_started_ms_{0};
  uint32_t forensic_next_recording_sequence_{1};
  bool forensic_recording_active_{false};
  uint32_t forensic_next_transaction_sequence_{1};
  std::unique_ptr<ForensicTransactionRecipe> forensic_transaction_pending_;
  std::unique_ptr<ForensicTransactionRuntime> forensic_transaction_active_;
  std::unique_ptr<ForensicGattWrite> forensic_gatt_write_active_;
  ForensicTransactionStatus forensic_transaction_status_;
  std::map<std::string, ForensicTransactionVariable> forensic_transaction_result_variables_;
  ForensicTransactionResponseRecorder forensic_transaction_responses_;
  bool forensic_transaction_reconnect_required_{false};
#endif
  PendingAdvertisement pending_advertisement_;
  std::array<uint8_t, ESP_BLE_ADV_DATA_LEN_MAX + ESP_BLE_SCAN_RSP_DATA_LEN_MAX> last_advertisement_{};
  uint8_t last_advertisement_length_{0};
  uint8_t last_advertisement_data_length_{0};
  uint8_t last_scan_response_length_{0};
  uint8_t last_address_type_{0};
  int8_t last_rssi_{0};

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
  static constexpr size_t MAX_TREE_VALUE_BYTES = 256;
  static constexpr size_t MAX_TREE_FIELD_ELEMENTS = 64;
#ifdef USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING
  static constexpr size_t MAX_FORENSIC_OPERATIONS = 512;
  static constexpr size_t MAX_FORENSIC_OPERATION_VALUE_BYTES = 512;
  static constexpr size_t MAX_FORENSIC_TRANSACTION_WRITE_BYTES = FORENSIC_TRANSACTION_MAX_VALUE_BYTES;
#endif
  static constexpr size_t MAX_PENDING_REPORTS = 64;
  static constexpr size_t MAX_REPORT_PAYLOAD_BYTES = 512;
  static constexpr size_t MAX_PENDING_REPORT_BYTES = 4096;
  static constexpr size_t MAX_REPORTS_PER_LOOP = 8;
  static constexpr uint32_t MAX_PROCESSING_TIME_US = 4000;
  static constexpr uint32_t PHASE_TIMEOUT_MS = 15000;
  // ESPHome V1/V2 clients write the CCCD on our behalf after registration.
  // Real write completions can take over 500 ms; a short fallback produces a
  // second write and a stale callback. V3 clients need our fallback, so retain
  // it with a conservative deadline rather than removing it.
  static constexpr uint32_t CCCD_FALLBACK_DELAY_MS = 2000;
  static constexpr uint32_t OVERFLOW_WARNING_INTERVAL_MS = 5000;
};

}  // namespace ble_client_hid
}  // namespace esphome
#endif
