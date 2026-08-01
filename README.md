# ESPHome BLE HID

Use Bluetooth Low Energy keyboards, remotes, mice, media controllers, and other
HID peripherals as inputs for ESPHome and Home Assistant.

`ble_client_hid` discovers a device's HID-over-GATT service, reads its HID
Report Map, decodes incoming reports, and publishes normalized events through
ESPHome's native API. Report layouts are learned from the device instead of
being hard-coded for a particular remote.

> [!NOTE]
> This is an external ESPHome component for ESP32 using the ESP-IDF framework.
> BLE memory requirements vary by board and by the number of connected clients;
> PSRAM is recommended for larger configurations.

## Supported features

- Descriptor-driven HID Report Protocol input parsing.
- Multiple BLE HID devices on one ESPHome node—up to three
  `ble_client_hid` instances.
- Multiple Report characteristics and Report IDs per device.
- Input, Output, and Feature Report Reference identification. Only Input report
  layouts are decoded as input events.
- Variable and array input fields, including non-byte-aligned fields.
- Signed and unsigned values up to 32 bits.
- Relative inputs such as pointer axes, Wheel, and AC Pan. Every nonzero
  relative report is emitted, including consecutive equal values.
- Absolute input state changes, including button and key releases.
- HID usage names for Generic Desktop, Keyboard/Keypad, and Consumer pages.
  Other usage pages remain available as numeric page/usage pairs.
- Raw notification envelopes for reports that cannot be decoded, so unsupported
  traffic is visible instead of silently discarded.
- Report ID, Report Type, characteristic UUID, GATT handle,
  notification/indication transport, payload length, raw bytes, and timestamp
  diagnostics.
- Optional battery and last-decoded-event sensors.
- Safe disconnect/reconnect handling and report-map rediscovery.
- ESP32 and ESP32-S3 strict-build coverage in CI.

Previously reported working devices include Fire TV, Nvidia Shield, and Ruwido
BLE remotes. HID devices differ widely, so new device reports and sanitized
captures are welcome.

## How to use

### 1. Add the external component

```yaml
external_components:
  - source: github://fsievers22/esphome-ble-remote@master
    components: [ble_client_hid]
```

### 2. Configure a BLE client

```yaml
esp32:
  board: esp32dev
  framework:
    type: esp-idf

esp32_ble_tracker:

ble_client:
  - id: living_room_remote
    mac_address: "AA:BB:CC:DD:EE:01"

ble_client_hid:
  - id: living_room_hid
    ble_client_id: living_room_remote
```

`ble_client_id` may be omitted when ESPHome can resolve a single BLE client,
but explicit IDs are recommended for multi-device configurations.

### Multiple HID devices

Create one `ble_client` and one `ble_client_hid` entry per peripheral:

```yaml
ble_client:
  - id: presentation_remote
    mac_address: "AA:BB:CC:DD:EE:01"

  - id: media_remote
    mac_address: "AA:BB:CC:DD:EE:02"

ble_client_hid:
  - id: presentation_hid
    ble_client_id: presentation_remote

  - id: media_hid
    ble_client_id: media_remote
```

ESPHome currently permits up to three component instances. Actual concurrency
also depends on the board, BLE stack configuration, memory, connection
intervals, and other active BLE components.

### Home Assistant events

Decoded input values are published as `esphome.hid_events`:

```yaml
event_type: esphome.hid_events
data:
  device: AA:BB:CC:DD:EE:01
  handle: "39"
  report_id: "1"
  usage: Volume Increment
  usage_page: "12"
  usage_id: "233"
  value: "1"
```

- `usage` is a human-readable HID usage when known.
- `device` is the BLE peer address and distinguishes peripherals when several
  HID clients share one ESPHome node.
- Unknown usages use `<usage_page>_<usage_id>`, for example `32_17`.
- `value` is serialized as a string. A button normally emits `1` when pressed
  and `0` when released.
- Relative values are deltas, not persistent state.

If a notification is valid HID traffic but has no decodable value, the event
contains its report envelope instead:

```yaml
event_type: esphome.hid_events
data:
  device: AA:BB:CC:DD:EE:01
  handle: "54"
  characteristic_uuid: "10829"
  report_id: "4"
  hid_report_type: feature
  transport: notification
  length: "3"
  raw_data: 01.02.03
  timestamp: "123456"
```

`characteristic_uuid` is represented in decimal because ESPHome event fields
are strings; `10829` is hexadecimal `0x2A4D`, the standard HID Report
characteristic.

### Optional sensors

```yaml
sensor:
  - platform: ble_client_hid
    type: battery
    ble_client_hid_id: living_room_hid
    name: Living room remote battery

  - platform: ble_client_hid
    type: last_event_value
    ble_client_hid_id: living_room_hid
    name: Last HID value

text_sensor:
  - platform: ble_client_hid
    type: last_event_usage
    ble_client_hid_id: living_room_hid
    name: Last HID usage

  - platform: ble_client_hid
    type: last_event_code
    ble_client_hid_id: living_room_hid
    name: Last HID usage code
```

Available diagnostic entity types:

| Platform | Type | Value |
|---|---|---|
| `sensor` | `battery` | Battery percentage |
| `sensor` | `last_event_value` | Most recent decoded numeric value |
| `text_sensor` | `last_event_usage` | Most recent usage name |
| `text_sensor` | `last_event_code` | `<usage_page>_<usage_id>` |

`ble_client_hid_id` can be omitted only when there is one unambiguous parent.
For multiple devices, always set it explicitly.

## How to develop

### Repository layout

```text
components/ble_client_hid/  ESPHome component, GATT client, and HID parser
tests/                      Native parser tests and firmware build fixture
scripts/build-strict.sh     ESPHome build plus component-warning enforcement
```

### Set up the toolchain

The project uses a local Python virtual environment for ESPHome:

```bash
make setup
```

Dependencies are pinned through `requirements-build.txt`.

### Run native tests

```bash
make test
```

Native coverage includes:

- HID signed-item decoding.
- A composite mouse/Consumer Control Report Map fixture.
- Packed signed 12-bit axes.
- Buttons, Wheel, and AC Pan.
- Input versus Output/Feature Report routing.
- Variable usage assignment.
- Keyboard array reordering and release behavior.
- Truncated HID short and long items.
- Deterministic malformed-descriptor smoke fuzzing.

Tests compile with `-Wall -Wextra -Werror`.

### Build test firmware

```bash
make build
make build BOARD=esp32dev
make build BOARD=esp32-s3-devkitc-1
```

The firmware fixture is [tests/build.yml](tests/build.yml). The strict build
fails if `ble_client_hid` emits compiler warnings.

### Capture a device report

Run ESPHome with debug logging and include, at minimum:

- The complete connection and HID Report Map log.
- HID characteristic UUIDs, handles, properties, Report IDs, and Report Types.
- `HID_RAW` lines for isolated, clearly labeled physical actions.
- Disconnect/reconnect behavior.

Please remove MAC addresses, Wi-Fi credentials, API keys, and other personal
data before opening an issue or pull request. Prefer a minimal descriptor or
packet fixture in tests over committing a large device log.

### Contribution guidelines

- Keep the base parser device-agnostic.
- Derive meanings from the HID Report Map and Report Reference descriptors.
- Preserve unknown traffic numerically or as raw bytes; do not guess semantics.
- Add a regression fixture for every parser fix.
- Run `make test` and strict firmware builds before submitting a pull request.
- Avoid breaking the existing `esphome.hid_events` event name and generic
  `usage`/`value` shape.

## Missing features and roadmap

The following are not implemented yet and are good candidates for upcoming
work:

- More than one HID Service instance on a single BLE peripheral. Multiple
  separate peripherals are supported today; multiple HID services within one
  peripheral are not.
- Semantic decoding of Boot Keyboard and Boot Mouse reports. These
  characteristics are discovered and their traffic is preserved raw.
- Output and Feature report read/write APIs, including keyboard LEDs and device
  configuration.
- Explicit Protocol Mode selection and switching.
- Collection-path, physical-range, unit, unit-exponent, designator, and string
  metadata in emitted events.
- Broader human-readable HID Usage Table coverage.
- A reusable capture-replay test runner.
- Longer randomized and coverage-guided parser fuzzing in CI.

Until those features land, unsupported input is intentionally surfaced as a raw
report envelope rather than being discarded.

## License

See [LICENSE](LICENSE).
