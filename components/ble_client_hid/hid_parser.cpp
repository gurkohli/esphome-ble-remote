#include <stack>
#include <map>
#include <cinttypes>
#include "esphome/core/log.h"

#include "hid_report_data.h"
#include "hid_item_value.h"
#include "hid_parser.h"

namespace esphome
{
  namespace ble_client_hid
  {

    static const char *const TAG = "hid_parser";

    // requires at least C++11
    const std::string vformat(const char *const zcFormat, ...)
    {

      // initialize use of the variable argument array
      va_list vaArgs;
      va_start(vaArgs, zcFormat);

      // reliably acquire the size
      // from a copy of the variable argument array
      // and a functionally reliable call to mock the formatting
      va_list vaArgsCopy;
      va_copy(vaArgsCopy, vaArgs);
      const int iLen = std::vsnprintf(NULL, 0, zcFormat, vaArgsCopy);
      va_end(vaArgsCopy);

      // return a formatted string without risking memory mismanagement
      // and without assuming any compiler or platform specific behavior
      std::vector<char> zc(iLen + 1);
      std::vsnprintf(zc.data(), zc.size(), zcFormat, vaArgs);
      va_end(vaArgs);
      return std::string(zc.data(), iLen);
    }
    void HIDReportMap::esp_logd_report_map(const uint8_t *report_map_data, uint16_t report_map_size)
    {
      ESP_LOGD(TAG, "Report Map:");
      while (report_map_data != nullptr && report_map_size > 0)
      {
        uint8_t report_item_info = report_map_data[0];
        report_map_size--;
        report_map_data++;
        if (report_item_info == 0xFE) {
          if (report_map_size < 2 || report_map_size < static_cast<uint16_t>(2 + report_map_data[0])) {
            ESP_LOGW(TAG, "Truncated HID long item while logging");
            return;
          }
          ESP_LOGD(TAG, "Long item tag=%X size=%u", report_map_data[1], report_map_data[0]);
          const uint8_t long_size = report_map_data[0];
          report_map_data += 2 + long_size;
          report_map_size -= 2 + long_size;
          continue;
        }
        const uint8_t size = hid_item_data_size(report_item_info);
        if (report_map_size < size) {
          ESP_LOGW(TAG, "Truncated HID short item while logging");
          return;
        }
        std::string item = vformat("%X", report_item_info);
        for (uint8_t i = 0; i < size; i++)
          item += vformat(", %X", report_map_data[i]);
        ESP_LOGD(TAG, "%s", item.c_str());
        report_map_data += size;
        report_map_size -= size;
      }
    }

    uint32_t HIDReportMap::parse_item(const uint8_t **p_report_map_data, uint16_t *report_map_size, uint8_t report_item_info)
    {
      uint32_t report_item_data;

      switch (report_item_info & HID_ITEM_SIZE_MASK)
      {
      case HID_ITEM_SIZE_32:
        report_item_data =
            (((uint32_t)(*p_report_map_data)[3] << 24) |
             ((uint32_t)(*p_report_map_data)[2] << 16) |
             ((uint16_t)(*p_report_map_data)[1] << 8) | (*p_report_map_data)[0]);
        (*report_map_size) -= 4;
        (*p_report_map_data) += 4;
        return report_item_data;

      case HID_ITEM_SIZE_16:
        report_item_data =
            (((uint16_t)(*p_report_map_data)[1] << 8) | ((*p_report_map_data)[0]));
        (*report_map_size) -= 2;
        (*p_report_map_data) += 2;
        return report_item_data;

      case HID_ITEM_SIZE_8:
        report_item_data = (*p_report_map_data)[0];
        (*report_map_size) -= 1;
        (*p_report_map_data) += 1;
        return report_item_data;

      default:
        report_item_data = 0;
        return report_item_data;
      }
    }

    static const HIDUsage parse_usage(uint8_t item_info, uint32_t data, uint16_t usage_page)
    {
      if ((item_info & HID_ITEM_SIZE_MASK) == HID_ITEM_SIZE_32)
      {
        ESP_LOGD(TAG,"Parsing extedned usage: %X, %X", (uint16_t)(data >> 16), (uint16_t)data);
        return HIDUsage((uint16_t)data, (uint16_t)(data >> 16));
      }
      ESP_LOGD(TAG,"Parsing simple usage: %X, %X", usage_page, (uint16_t)data);
      return HIDUsage((uint16_t)data, usage_page);
    }

    HIDUsage HIDUsageRange::get_usage(uint32_t index, bool repeat_last) const
    {
      if (index > this->usage_max.usage - this->usage_min.usage)
      {
        if (repeat_last)
          return this->usage_max;
        return HIDUsage(static_cast<uint16_t>(index), 0);
      }
      return HIDUsage(this->usage_min.usage + index, this->usage_page);
    }

    HIDUsage HIDUsageList::get_usage(uint32_t index, bool repeat_last) const
    {
      ESP_LOGD(TAG, "get usage for index %u with list size %u", static_cast<unsigned>(index),
               static_cast<unsigned>(this->usages.size()));
      if (index >= this->usages.size())
      {
        if (repeat_last && !this->usages.empty())
          return this->usages.back();
        return HIDUsage(static_cast<uint16_t>(index), 0);
      }
      return this->usages[index];
    }

    HIDReportMap *HIDReportMap::parse_report_map_data(
        const uint8_t *report_map_data, uint16_t report_map_size)
    {
      if (report_map_data == nullptr || report_map_size == 0) {
        ESP_LOGW(TAG, "Empty HID Report Map");
        return nullptr;
      }
      HIDStateTable state_table = {};
      std::stack<HIDStateTable> parser_states;
      HIDUsageRangeLimits usage_range = {};
      std::vector<HIDUsage> usages;
      bool alternative_usage_set = false;
      std::map<uint8_t, HIDInputReport *> input_reports;
      auto fail = [&input_reports]() -> HIDReportMap * {
        for (auto &entry : input_reports)
          delete entry.second;
        return nullptr;
      };

      while (report_map_size)
      {
        uint8_t report_item_info = report_map_data[0];

        report_map_data++;
        report_map_size--;

        // Long items are reserved for future use. Skip their payload without
        // interpreting their tag as a short item.
        if (report_item_info == 0xFE) {
          if (report_map_size < 2) {
            ESP_LOGW(TAG, "Truncated HID long-item header");
            return fail();
          }
          const uint8_t long_size = report_map_data[0];
          if (report_map_size < static_cast<uint16_t>(2 + long_size)) {
            ESP_LOGW(TAG, "Truncated HID long item");
            return fail();
          }
          report_map_data += 2 + long_size;
          report_map_size -= 2 + long_size;
          continue;
        }

        const uint8_t item_size = hid_item_data_size(report_item_info);
        if (report_map_size < item_size) {
          ESP_LOGW(TAG, "Truncated HID short item 0x%02X", report_item_info);
          return fail();
        }

        uint32_t report_item_data = HIDReportMap::parse_item(&report_map_data, &report_map_size, report_item_info);
        switch (report_item_info & (HID_ITEM_TYPE_MASK | HID_ITEM_TAG_MASK))
        {
        case HID_ITEM_TYPE_TAG_PUSH:
        {

          parser_states.push(state_table);
          break;
        }
        case HID_ITEM_TYPE_TAG_POP:
        {
          if (parser_states.size() <= 0)
          {
            ESP_LOGW(TAG,
                     "No parser state in HID parser states stack, error in HID "
                     "report map");
            return fail();
          }
          state_table = parser_states.top();
          parser_states.pop();
          break;
        }

        case HID_ITEM_TYPE_TAG_USAGE_PAGE:
        {
          ESP_LOGD(TAG, "Usage page: %X",
                   static_cast<unsigned int>(report_item_data));
          state_table.usage_page = report_item_data;
          break;
        }

        case HID_ITEM_TYPE_TAG_LOGICAL_MINIMUM:
        {
          // HID logical minima are signed values encoded in the short item's
          // declared width.
          state_table.logical_range.minimum = decode_signed_hid_item(report_item_data, report_item_info);
          break;
        }

        case HID_ITEM_TYPE_TAG_LOGICAL_MAXIMUM:
        {
          // Per the HID specification, Logical Maximum is signed when Logical
          // Minimum is negative and unsigned otherwise.
          state_table.logical_range.maximum = state_table.logical_range.minimum < 0
                                                  ? decode_signed_hid_item(report_item_data, report_item_info)
                                                  : static_cast<int64_t>(report_item_data);
          break;
        }

        case HID_ITEM_TYPE_TAG_PHYSICAL_MINIMUM:
          // Ignore for now
          break;

        case HID_ITEM_TYPE_TAG_PHYSICAL_MAXIMUM:
          // Ignore for now
          break;

        case HID_ITEM_TYPE_TAG_UNIT_EXPONENT:
          // Ignore for now
          break;

        case HID_ITEM_TYPE_TAG_UNIT:
          // Ignore for now
          break;

        case HID_ITEM_TYPE_TAG_REPORT_SIZE:
        {
          state_table.report_size = report_item_data;
          break;
        }

        case HID_ITEM_TYPE_TAG_REPORT_COUNT:
        {
          state_table.report_count = report_item_data;
          break;
        }

        case HID_ITEM_TYPE_TAG_REPORT_ID:
        {
          if (report_item_data == 0 || report_item_data > UINT8_MAX) {
            ESP_LOGW(TAG, "Invalid HID Report ID %u", static_cast<unsigned>(report_item_data));
            return fail();
          }
          if (input_reports.count(report_item_data) == 0)
          {
            input_reports.emplace(report_item_data, new HIDInputReport(report_item_data));
          }
          state_table.report_id = report_item_data;
          break;
        }

        case HID_ITEM_TYPE_TAG_USAGE:
        {
          if (!alternative_usage_set)
            usages.push_back(parse_usage(report_item_info, report_item_data, state_table.usage_page));
          break;
        }

        case HID_ITEM_TYPE_TAG_USAGE_MINIMUM:
        {
          if (!alternative_usage_set)
            usage_range.minimum = parse_usage(report_item_info, report_item_data, state_table.usage_page);
          break;
        }

        case HID_ITEM_TYPE_TAG_USAGE_MAXIMUM:
        {
          if (!alternative_usage_set)
            usage_range.maximum = parse_usage(report_item_info, report_item_data, state_table.usage_page);
          break;
        }

        case HID_ITEM_TYPE_TAG_DELIMITER:
        {
          // The first delimiter set is the preferred usage set. Alternative
          // sets describe aliases and must not be concatenated onto it.
          alternative_usage_set = report_item_data != 0;
          break;
        }

        case HID_ITEM_TYPE_TAG_COLLECTION:
          // Ignore for now
          break;

        case HID_ITEM_TYPE_TAG_END_COLLECTION:
          // Ignore for now
          break;

        case HID_ITEM_TYPE_TAG_INPUT:

        {
          ESP_LOGD(TAG, "Found input main item");
          uint16_t item_flags = report_item_data;

          if (state_table.report_id == 0)
          {
            if (input_reports.count(0) == 0)
            {
              ESP_LOGD(TAG, "Not using report ids");
              input_reports.emplace(0, new HIDInputReport(0));
            }
          }

          HIDInputReport *input_report = input_reports.at(state_table.report_id);
          if (state_table.report_size == 0 || state_table.report_size > 32 || state_table.report_count == 0 ||
              state_table.report_count > 4096) {
            ESP_LOGW(TAG, "Unsupported HID field size=%u count=%u", static_cast<unsigned>(state_table.report_size),
                     static_cast<unsigned>(state_table.report_count));
            return fail();
          }
          if (item_flags & HID_IOF_CONSTANT)
          {
            ESP_LOGD(TAG, "Parsed input report item of type: constant");
            if (!input_report->add_padding(static_cast<size_t>(state_table.report_size) * state_table.report_count))
              return fail();
            break;
          }
          HIDUsageCollection *usage_collection;
          if (usages.size() > 0)
          {
            usage_collection = new HIDUsageList(usages);
          }
          else
          {
            ESP_LOGD(TAG, "Creating usage range with min: %d, max: %d, page: %d", usage_range.minimum.usage, usage_range.maximum.usage, usage_range.minimum.page);
            usage_collection = new HIDUsageRange(usage_range.minimum, usage_range.maximum, usage_range.minimum.page);
          }
          if (item_flags & HID_IOF_VARIABLE)
          {
            if (!input_report->push_back(new HIDInputReportVariable(
                usage_collection, state_table.report_count, state_table.report_id,
                state_table.logical_range, state_table.report_size,
                input_report->get_next_offset(), item_flags & HID_IOF_RELATIVE)))
              return fail();
            ESP_LOGD(TAG, "Parsed input report item of type: variable, report size: %u, report count: %u, report id: %u",
                     static_cast<unsigned>(state_table.report_size), static_cast<unsigned>(state_table.report_count),
                     state_table.report_id);
          }
          else
          {
            if (!input_report->push_back(new HIDInputReportArray(
                usage_collection, state_table.report_count, state_table.report_id,
                state_table.logical_range, state_table.report_size,
                input_report->get_next_offset(), item_flags & HID_IOF_RELATIVE)))
              return fail();
            ESP_LOGD(TAG, "Parsed input report item of type: array, report size: %u, report count: %u, report id: %u",
                     static_cast<unsigned>(state_table.report_size), static_cast<unsigned>(state_table.report_count),
                     state_table.report_id);
          }
          break;
        }
        case HID_ITEM_TYPE_TAG_OUTPUT:
          // Ignore for now
          break;
        case HID_ITEM_TYPE_TAG_FEATURE:
          // Ignore for now
          break;

        default:
          break;
        }
        if ((report_item_info & HID_ITEM_TYPE_MASK) == HID_ITEM_TYPE_MAIN)
        {
          usages.clear();
          alternative_usage_set = false;
          usage_range.maximum = HIDUsage(0, 0);
          usage_range.minimum = HIDUsage(0, 0);
        }
      }
      HIDReportMap *report_map = new HIDReportMap(input_reports);
      ESP_LOGD(TAG, "Parsed report map with %d input reports", input_reports.size());
      return report_map;
    }

    size_t HIDInputReport::get_next_offset()
    {
      return this->report_size;
    }

    bool HIDInputReport::add_padding(size_t padding_size)
    {
      if (padding_size > SIZE_MAX - this->report_size)
        return false;
      this->report_size += padding_size;
      return true;
    }

    bool HIDInputReport::push_back(HIDInputReportItem *item)
    {
      if (item == nullptr || item->get_total_size() > SIZE_MAX - this->report_size) {
        delete item;
        return false;
      }
      this->items.push_back(item);
      this->report_size += item->get_total_size();
      return true;
    }

    std::vector<HIDReportItemValue> HIDReportMap::parse(
        HIDReportSource source, const uint8_t *hid_report_data, size_t length)
    {
      // This map contains Input main items only. A Report Reference with type
      // Output (2) or Feature (3) must not be decoded through an Input layout,
      // even when it reuses the same Report ID.
      if (source.has_report_type && source.report_type != 1)
      {
        ESP_LOGD(TAG, "Ignoring non-input HID report type %u from handle %u",
                 source.report_type, source.characteristic_handle);
        return {};
      }
      if (source.characteristic_uuid == 0x2A22 || source.characteristic_uuid == 0x2A33) {
        ESP_LOGD(TAG, "Boot Protocol report requires its fixed-format decoder");
        return {};
      }
      if (this->input_reports.empty())
      {
        ESP_LOGW(TAG, "No input reports found");
        return std::vector<HIDReportItemValue>();
      }
      uint8_t report_id = source.has_report_id ? source.report_id : 0;
      if (this->input_reports.count(report_id) == 0)
      {
        ESP_LOGW(TAG, "Unknown HID report ID %u from handle %u", report_id,
                 source.characteristic_handle);
        return {};
      }
      std::vector<HIDReportItemValue> values =
          this->input_reports.at(report_id)->parse(hid_report_data, length);
      for (auto &value : values) {
        value.characteristic_handle = source.characteristic_handle;
        value.report_id = report_id;
      }
      return values;
    }

    std::vector<HIDReportItemValue> HIDInputReport::parse(
        const uint8_t *report_data, size_t length)
    {
      std::vector<HIDReportItemValue> report_values;
      for (HIDInputReportItem *report_item : this->items)
      {
        std::vector<HIDReportItemValue> item_values = report_item->parse(report_data, length);
        for (HIDReportItemValue item_value : item_values)
        {
          report_values.push_back(item_value);
        }
      }
      return report_values;
    }

    size_t HIDInputReportItem::get_total_size()
    {
      return this->report_size * this->report_count;
    }

    bool HIDInputReportItem::parse_input_report_item(
        const uint8_t *report_data, size_t length, size_t bit_offset,
        uint32_t report_size, HIDLogicalRange logical_range, int64_t *result)
    {
      if (report_data == nullptr || result == nullptr || report_size == 0 || report_size > 32 ||
          bit_offset > length * 8 || report_size > length * 8 - bit_offset) {
        ESP_LOGW(TAG, "Truncated/unsupported HID field: offset=%u size=%u packet_bits=%u",
                 static_cast<unsigned>(bit_offset), static_cast<unsigned>(report_size),
                 static_cast<unsigned>(length * 8));
        return false;
      }
      uint32_t raw = 0;
      for (uint32_t bit = 0; bit < report_size; bit++)
        if ((report_data[(bit_offset + bit) / 8] & (uint8_t{1} << ((bit_offset + bit) % 8))) != 0)
          raw |= uint32_t{1} << bit;
      if (logical_range.minimum < 0) {
        if (report_size < 32 && (raw & (uint32_t{1} << (report_size - 1))) != 0)
          raw |= UINT32_MAX << report_size;
        *result = static_cast<int32_t>(raw);
      } else {
        *result = static_cast<int64_t>(raw);
      }
      return true;
    }

    std::string HIDReportItemValue::to_string() const
    {
      return vformat("HIDReportItemValue(usage_page: %u, usage: %u, value: %" PRId64 ")",
                     this->usage.page, this->usage.usage, this->value);
    }

    std::vector<HIDReportItemValue> HIDInputReportVariable::parse(
        const uint8_t *report_data, size_t length)
    {
      std::vector<HIDReportItemValue> values;
      for (uint32_t i = 0; i < this->report_count; i++)
      {
        int64_t value;
        if (!parse_input_report_item(report_data, length,
                                     this->report_offset + i * this->report_size,
                                     this->report_size, this->logical_range, &value))
          continue;
        if (value > this->logical_range.maximum || value < this->logical_range.minimum)
        {
          ESP_LOGD(TAG, "Value %" PRId64 " out of logical range [%" PRId64 ", %" PRId64 "]", value,
                   this->logical_range.minimum, this->logical_range.maximum);
          continue;
        }
        if (this->is_relative && value == 0)
          continue;
        if (!this->is_relative && this->last_values[i].raw_value == value)
          continue;
        values.push_back(HIDReportItemValue(this->usage_collection->get_usage(i, true), value, value));
        values.back().is_relative = this->is_relative;
        ESP_LOGD(TAG, values.back().to_string().c_str());

        this->last_values[i] = values.back();
      }
      return values;
    }

    std::vector<HIDReportItemValue> HIDInputReportArray::parse(
        const uint8_t *report_data, size_t length)
    {
      std::vector<HIDReportItemValue> values;
      std::multimap<HIDUsage, int64_t> current;
      for (uint32_t i = 0; i < this->report_count; i++) {
        int64_t raw;
        if (!parse_input_report_item(report_data, length,
                                     this->report_offset + i * this->report_size,
                                     this->report_size, this->logical_range, &raw))
          continue;
        if (raw < this->logical_range.minimum || raw > this->logical_range.maximum)
          continue;  // Array out-of-range means no control asserted in this slot.
        const uint32_t usage_index = static_cast<uint32_t>(raw - this->logical_range.minimum);
        HIDUsage usage = this->usage_collection->get_usage(usage_index);
        if (usage.page != 0 && usage.usage != 0)
          current.emplace(usage, raw);
      }

      auto previous = this->active_array_usages_;
      for (const auto &entry : current) {
        auto old = previous.find(entry.first);
        if (old != previous.end())
          previous.erase(old);
        else
          values.emplace_back(entry.first, 1, entry.second);
      }
      auto remaining = current;
      for (const auto &entry : this->active_array_usages_) {
        auto now = remaining.find(entry.first);
        if (now != remaining.end())
          remaining.erase(now);
        else
          values.emplace_back(entry.first, 0, 0);
      }
      this->active_array_usages_ = std::move(current);
      return values;
    }
  } // namespace ble_client_hid
} // namespace esphome
