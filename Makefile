PYTHON ?= python3
VENV ?= .venv
ESPHOME := $(VENV)/bin/esphome
BUILD_CONFIG ?= tests/build.yml
BOARD ?= esp32-s3-devkitc-1

.PHONY: build setup test

test:
	$(CXX) -std=c++20 -Wall -Wextra -Werror -Icomponents/ble_client_hid tests/hid_item_value_test.cpp -o /tmp/hid_item_value_test
	/tmp/hid_item_value_test
	$(CXX) -std=c++20 -Wall -Wextra -Werror -Itests/stubs -Icomponents/ble_client_hid tests/hid_parser_test.cpp components/ble_client_hid/hid_parser.cpp -o /tmp/hid_parser_test
	/tmp/hid_parser_test

build: setup
	./scripts/build-strict.sh $(ESPHOME) -s build_board $(BOARD) compile $(BUILD_CONFIG)

setup: $(ESPHOME)

$(ESPHOME): requirements-build.txt
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/python -m pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements-build.txt
	@touch $(ESPHOME)
