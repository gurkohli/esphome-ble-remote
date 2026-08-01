#pragma once

// Native parser tests do not need ESPHome's runtime logger. Keep the logging
// call sites type-checked by the firmware build and compile them out here.
#define ESP_LOGD(tag, ...) do { (void) (tag); } while (0)
#define ESP_LOGI(tag, ...) do { (void) (tag); } while (0)
#define ESP_LOGW(tag, ...) do { (void) (tag); } while (0)
#define ESP_LOGE(tag, ...) do { (void) (tag); } while (0)
