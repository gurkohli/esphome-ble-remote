#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace esphome
{
  namespace ble_client_hid
  {

    struct HIDUsage
    {
      HIDUsage(uint16_t usage, uint16_t page) : usage(usage), page(page){};
      uint16_t usage = 0;
      uint16_t page = 0;
      bool operator<(const HIDUsage &other) const {
        return this->page < other.page || (this->page == other.page && this->usage < other.usage);
      }
    };

    struct HIDReportItemValue
    {
      HIDReportItemValue(const HIDUsage usage, const int64_t value, const int64_t raw_value,
                         uint16_t characteristic_handle = 0, uint8_t report_id = 0)
          : usage(usage), value(value), raw_value(raw_value),
            characteristic_handle(characteristic_handle), report_id(report_id){};
      std::string to_string() const;
      HIDUsage usage;
      int64_t value = 0;
      int64_t raw_value = 0;
      uint16_t characteristic_handle = 0;
      uint8_t report_id = 0;
      bool is_relative = false;
    };

    struct HIDReportSource
    {
      uint16_t characteristic_handle = 0;
      uint8_t report_id = 0;
      bool has_report_id = false;
      uint8_t report_type = 0;
      bool has_report_type = false;
      bool is_notification = true;
      bool has_transport = false;
      uint16_t characteristic_uuid = 0;
    };

    struct HIDUsageRangeLimits
    {
      HIDUsage minimum = HIDUsage(0, 0);
      HIDUsage maximum = HIDUsage(0, 0);
    };

    struct HIDLogicalRange
    {
      int64_t minimum = 0;
      int64_t maximum = 0;
    };

    struct HIDStateTable
    {
      uint32_t report_size = 0; // in bits
      HIDLogicalRange logical_range = {};
      uint32_t report_count = 0;
      uint8_t report_id = 0;
      uint16_t usage_page = 0;
    };

    class HIDUsageCollection
    {
    public:
      virtual HIDUsage get_usage(uint32_t index, bool repeat_last = false) const = 0;
      virtual ~HIDUsageCollection() = default;
    };

    class HIDUsageRange : public HIDUsageCollection
    {
    public:
      HIDUsageRange(const HIDUsage usage_min, const HIDUsage usage_max, uint16_t usage_page)
          : usage_min(usage_min), usage_max(usage_max), usage_page(usage_page){};
      HIDUsage get_usage(uint32_t index, bool repeat_last = false) const override;

    protected:
      const HIDUsage usage_min;
      const HIDUsage usage_max;
      const uint16_t usage_page;
    };

    class HIDUsageList : public HIDUsageCollection
    {
    public:
      HIDUsageList(std::vector<HIDUsage> usages) : usages(usages){};
      HIDUsage get_usage(uint32_t index, bool repeat_last = false) const override;

    protected:
      std::vector<HIDUsage> usages;
    };

    class HIDInputReportItem
    {
    public:
      HIDInputReportItem(HIDUsageCollection *usage_collection, uint32_t report_count, uint8_t report_id,
                         HIDLogicalRange logical_range, uint32_t report_size, size_t report_offset,
                         bool is_relative)
          : report_size(report_size),
            usage_collection(usage_collection),
            report_count(report_count),
            report_id(report_id),
            logical_range(logical_range),
            report_offset(report_offset),
            is_relative(is_relative)
      {
        this->last_values = std::vector<HIDReportItemValue>(report_count, HIDReportItemValue(HIDUsage(0, 0), 0, 0));
      }
      virtual ~HIDInputReportItem()
      {
        delete usage_collection;
      };
      size_t get_total_size();
      virtual std::vector<HIDReportItemValue> parse(const uint8_t *hid_report_data, size_t length) = 0;
      static bool parse_input_report_item(const uint8_t *report_data, size_t length, size_t bit_offset,
                                          uint32_t report_size, HIDLogicalRange logical_range, int64_t *value);
      const uint32_t report_size; // in bits

    protected:
      const HIDUsageCollection *usage_collection;
      const uint32_t report_count;
      const uint8_t report_id;
      const HIDLogicalRange logical_range;
      const size_t report_offset; // in bits
      const bool is_relative;
      std::vector<HIDReportItemValue> last_values;
      std::multimap<HIDUsage, int64_t> active_array_usages_;
    };

    class HIDInputReportArray : public HIDInputReportItem
    {
    public:
      using HIDInputReportItem::HIDInputReportItem;
      ~HIDInputReportArray(){};
      std::vector<HIDReportItemValue> parse(const uint8_t *hid_report_data, size_t length);

    protected:
    };

    class HIDInputReportVariable : public HIDInputReportItem
    {
    public:
     using HIDInputReportItem::HIDInputReportItem;
      ~HIDInputReportVariable(){};
      std::vector<HIDReportItemValue> parse(const uint8_t *hid_report_data, size_t length);
    };

    class HIDInputReport
    {
    public:
      HIDInputReport(uint8_t report_id) : report_id(report_id){};
      ~HIDInputReport()
      {
        for (auto &item : items)
        {
          delete item;
        }
      };
      bool push_back(HIDInputReportItem *item);
      bool add_padding(size_t padding_size);
      size_t get_next_offset();
      std::vector<HIDReportItemValue> parse(const uint8_t *hid_report_data, size_t length);

    protected:
      std::vector<HIDInputReportItem *> items;
      const uint8_t report_id;
      size_t report_size = 0;
    };

    class HIDReportMap
    {
    public:
      HIDReportMap(std::map<uint8_t, HIDInputReport *> input_reports)
          : input_reports(input_reports) {}
      ~HIDReportMap()
      {
        for (auto &input_report : input_reports)
        {
          delete input_report.second;
        }
      };
      static HIDReportMap *parse_report_map_data(
          const uint8_t *report_map_data, uint16_t report_map_size);
      static void esp_logd_report_map(const uint8_t *report_map_data, uint16_t report_map_size);
      static uint32_t parse_item(const uint8_t **report_map_data, uint16_t *report_map_size, uint8_t report_item_info);
      std::vector<HIDReportItemValue> parse(HIDReportSource source, const uint8_t *hid_report_data, size_t length);

    protected:
      const std::map<uint8_t, HIDInputReport *> input_reports;
    };
  } // namespace ble_client_hid
} // namespace esphome
