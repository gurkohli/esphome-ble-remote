PYTHON ?= python3
VENV ?= .venv
ESPHOME := $(VENV)/bin/esphome
BUILD_CONFIG ?= tests/build.yml
BOARD ?= esp32-s3-devkitc-1

.PHONY: build setup test test-sanitize

test:
	$(CXX) -std=c++20 -Wall -Wextra -Werror -Icomponents/ble_client_hid tests/hid_item_value_test.cpp -o /tmp/hid_item_value_test
	/tmp/hid_item_value_test
	$(CXX) -std=c++20 -Wall -Wextra -Werror -Itests/stubs -Icomponents/ble_client_hid tests/hid_parser_test.cpp components/ble_client_hid/hid_parser.cpp -o /tmp/hid_parser_test
	/tmp/hid_parser_test
	$(CXX) -std=c++20 -Wall -Wextra -Werror -Icomponents/ble_client_hid tests/ordered_event_buffer_test.cpp -o /tmp/ordered_event_buffer_test
	/tmp/ordered_event_buffer_test
	$(CXX) -std=c++20 -Wall -Wextra -Werror -Icomponents/ble_client_hid tests/usage_lookup_test.cpp components/ble_client_hid/usage_data.cpp -o /tmp/usage_lookup_test
	/tmp/usage_lookup_test
	$(CXX) -std=c++20 -Wall -Wextra -Werror -Icomponents/ble_client_hid tests/boot_report_decoder_test.cpp components/ble_client_hid/boot_report_decoder.cpp -o /tmp/boot_report_decoder_test
	/tmp/boot_report_decoder_test
	$(CXX) -std=c++20 -Wall -Wextra -Werror -Icomponents/ble_client_hid tests/subscription_state_test.cpp -o /tmp/subscription_state_test
	/tmp/subscription_state_test

test-sanitize:
	$(CXX) -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Icomponents/ble_client_hid tests/hid_item_value_test.cpp -o /tmp/hid_item_value_test_sanitize
	/tmp/hid_item_value_test_sanitize
	$(CXX) -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Itests/stubs -Icomponents/ble_client_hid tests/hid_parser_test.cpp components/ble_client_hid/hid_parser.cpp -o /tmp/hid_parser_test_sanitize
	/tmp/hid_parser_test_sanitize
	$(CXX) -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Icomponents/ble_client_hid tests/ordered_event_buffer_test.cpp -o /tmp/ordered_event_buffer_test_sanitize
	/tmp/ordered_event_buffer_test_sanitize
	$(CXX) -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Icomponents/ble_client_hid tests/usage_lookup_test.cpp components/ble_client_hid/usage_data.cpp -o /tmp/usage_lookup_test_sanitize
	/tmp/usage_lookup_test_sanitize
	$(CXX) -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Icomponents/ble_client_hid tests/boot_report_decoder_test.cpp components/ble_client_hid/boot_report_decoder.cpp -o /tmp/boot_report_decoder_test_sanitize
	/tmp/boot_report_decoder_test_sanitize
	$(CXX) -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -Icomponents/ble_client_hid tests/subscription_state_test.cpp -o /tmp/subscription_state_test_sanitize
	/tmp/subscription_state_test_sanitize

build: setup
	./scripts/build-strict.sh $(ESPHOME) -s build_board $(BOARD) compile $(BUILD_CONFIG)

setup: $(ESPHOME)

$(ESPHOME): requirements-build.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/python -m pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements-build.txt
	@touch $(ESPHOME)
