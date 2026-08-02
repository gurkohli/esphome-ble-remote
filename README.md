# ESPHome BLE HID

`ble_client_hid` turns Bluetooth Low Energy HID peripherals into normalized
ESPHome and Home Assistant input events. It learns report layouts from the
device's GATT database and HID Report Map; it does not contain profiles for
particular remotes, keyboards, mice, or vendors.

The component also provides a bounded forensic discovery mode intended for
reverse engineering unfamiliar peripherals. Its diagnostic records retain raw
advertisements, the complete GATT topology, standard profile values, HID
schema metadata, subscription outcomes, and every delivered notification.

> [!NOTE]
> This is an external ESPHome component for ESP32 using the ESP-IDF framework.
> BLE memory usage depends on the board, number of clients, and peripheral
> database size. Every component-owned queue and parser collection is bounded,
> but PSRAM is still recommended for larger ESPHome configurations.

## Capabilities

- Complete passive inventory of primary/secondary services, included services,
  characteristics, properties, descriptors, and 16/32/128-bit UUIDs.
- Multiple BLE peripherals and multiple HID Service instances per peripheral.
- Serialized, bounded GATT reads with setup timeouts and explicit degraded
  readiness instead of indefinite waits.
- Notification readiness that covers both local registration and remote CCCD
  enablement.
- Standard and opt-in forensic discovery policies.
- Descriptor-driven Input decoding and complete schema retention for Input,
  Output, and Feature reports.
- Application/logical/physical collection hierarchy, physical and logical
  ranges, units, unit exponent, strings, designators, usage aliases, and all
  HID Main-item flags.
- Fixed-format Boot Keyboard and Boot Mouse decoding.
- Full USB-IF HID Usage Tables 1.7 naming and published usage kinds, stored in
  flash-resident sorted tables rather than runtime maps.
- Strict report-length validation. Short packets never partially mutate input
  state; long packets are identified while their defined portion is decoded.
- Ordered event coalescing for unstable or high-frequency sources.
- One raw-first `seq_id` for every delivered notification and
  `seq_id_from`/`seq_id_to` provenance for every emission.
- Raw visibility for HID, battery, Service Changed, forensic, and unknown-handle
  notifications.
- GATT-topology and Report Map SHA-256 fingerprints.
- Service Changed invalidation and clean reconnect rediscovery.
- Optional battery and last-event entities.

The generic behavior follows the Bluetooth SIG HID over GATT Profile, the USB
HID 1.11 descriptor format, USB-IF HID Usage Tables, and Bluetooth Assigned
Numbers. Unknown data is kept numeric or raw; the decoder does not guess.

## Configuration

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
    discovery_mode: standard
    protocol_mode: unchanged
    event_sampling_interval: 5ms
```

Add the component to ESPHome with:

```yaml
external_components:
  - source: github://fsievers22/esphome-ble-remote@master
    components: [ble_client_hid]
```

### Options

| Option                    |             Default | Meaning                                                   |
| ------------------------- | ------------------: | --------------------------------------------------------- |
| `ble_client_id`           | resolved by ESPHome | BLE client for this peripheral                            |
| `discovery_mode`          |          `standard` | `standard` or `forensic` discovery policy                 |
| `protocol_mode`           |         `unchanged` | Leave Protocol Mode unchanged, or request `report`/`boot` |
| `event_sampling_interval` |               `0ms` | Ordered coalescing window; zero disables coalescing       |

Explicit `ble_client_id` values are recommended and are required when ESPHome
cannot resolve an unambiguous parent. ESPHome permits up to three
`ble_client_hid` component instances; actual BLE concurrency also depends on
the board and the rest of the configuration.

### Standard versus forensic discovery

`standard` mode is appropriate for normal use. It:

- Captures changed target advertisements and scan responses.
- Enumerates the entire cached GATT structure without extra peripheral traffic.
- Reads relevant GAP, GATT, Device Information, Battery, and HID attributes.
- Reads Report Reference, External Report Reference, User Description,
  Presentation Format, and Aggregate Format descriptors when present.
- Subscribes to HID input traffic, Battery Level, and Service Changed.

`forensic` mode additionally:

- Reads all other readable characteristics and descriptors.
- Subscribes to all other characteristics that advertise Notify or Indicate.
- Logs their values and notifications without assigning device-specific
  meaning.

Forensic mode never writes unknown characteristics. It does write standard
CCCD descriptors to enable explicitly advertised notification streams and can
therefore increase radio, CPU, and log load. Use it intentionally while
capturing or reverse engineering a device.

### Protocol Mode

The component reads and logs Protocol Mode when the characteristic exists.
The default, `unchanged`, avoids changing peripheral behavior. `report` or
`boot` requests the corresponding standard mode with a Write Without Response.

Report characteristics use the Report Map decoder. Boot Keyboard and Boot
Mouse input characteristics use their fixed HID-over-GATT formats. If a device
does not expose or accept Protocol Mode, setup continues as degraded and raw
traffic remains visible.

## Connection and discovery lifecycle

The component does not treat BLE connection as decoder readiness. Setup passes
through bounded inventory, read, schema, protocol, registration, and CCCD
phases. It reports one of:

```text
HID_READY status=OK ...
HID_READY status=DEGRADED ...
HID_READY status=NO_HID ...
```

`DEGRADED` means every enabled setup operation reached a known outcome, but at
least one operation, schema check, or subscription failed. It does not mean the
component is still waiting. ESPHome's service cache is retained until this
finalization point.

Connection parameter updates are diagnostic only and never determine HID
readiness. A Service Changed indication invalidates the saved profile and
causes a controlled reconnect and rediscovery.

## Discovery logs

Discovery uses stable record prefixes:

```text
BLE_ADV
BLE_ADV_FIELD
GATT_SERVICE
GATT_INCLUDE
GATT_CHARACTERISTIC
GATT_DESCRIPTOR
GATT_VALUE
GATT_PROFILE
HID_DEVICE
HID_INFO
HID_PROTOCOL
HID_REPORT_MAP
HID_REPORT_REFERENCE
HID_EXTERNAL_REPORT_REFERENCE
HID_COLLECTION
HID_REPORT_SCHEMA
HID_FIELD
HID_SCHEMA_WARNING
HID_SUBSCRIPTION
HID_PROFILE
HID_READY
```

`DEBUG` provides summaries and readiness. `VERBOSE` exposes full topology,
attribute values, advertisement elements, descriptor items, collection trees,
and field schemas. Warnings identify invalid lengths, malformed descriptors,
missing schema links, resource limits, failed operations, and timeouts.

The GATT fingerprint excludes connection-specific handles. Report Map hashes
cover the exact bytes read from each HID service. Fingerprints are comparison
tools, not secure device identities.

Device Information Service values can include serial numbers, system IDs, and
other personally identifying information. Raw advertising, manufacturer data,
service data, vendor characteristics, and BLE addresses can also be sensitive.
Sanitize captures before sharing them.

## Raw notification tracing

Every notification or indication delivered to this client receives exactly one
monotonic `seq_id`. `HID_RAW` is the first component log for that ingress item,
before routing, queue admission, decoding, state mutation, coalescing, or
emission:

```text
HID_RAW seq_id=41 class=HID service_instance=3 handle=43 uuid=00002a4d-0000-1000-8000-00805f9b34fb report_id=2 report_type=input transport=notify len=3 data=05.00.00
HID_RAW seq_id=42 class=BATTERY service_instance=1 handle=18 uuid=00002a19-0000-1000-8000-00805f9b34fb report_id=- report_type=- transport=notify len=1 data=64
HID_RAW seq_id=43 class=UNKNOWN service_instance=0 handle=99 uuid=unknown report_id=- report_type=- transport=notify len=2 data=01.02
```

The classes are `HID`, `BATTERY`, `SERVICE_CHANGED`, and `UNKNOWN`. Unknown
traffic remains useful even when no decoder handles it:

```text
HID_RAW_HANDLING seq_id=43 result=raw_only reason=no_decoder
```

Raw logging is deliberately not sampled. Debug logging itself can overload a
slow serial connection during extreme ingress; enable it for diagnosis rather
than routine production use.

## Ordered coalescing and overload protection

`event_sampling_interval` shapes high-frequency continuous input without
requiring a strict output rate:

```yaml
ble_client_hid:
  - id: living_room_hid
    ble_client_id: living_room_remote
    event_sampling_interval: 500us
```

The first mergeable value after idle is emitted immediately. Within a window:

- Relative scalar fields are summed.
- Suitable absolute scalar fields retain the latest value.
- Buttons, keys, arrays, small enumerations, unsupported raw reports, and
  other nonmergeable values are ordering barriers.
- Older accumulated values are flushed before a barrier.

Thus `press, +1, +2, release` may become `press, +3, release`, never
`press, release, +3`.

Aggregation identity is based on HID service instance, report kind, Report ID,
and descriptor-defined field bit position. Two fields with the same Usage are
not merged. Usage names are descriptive metadata, not field identity.

The input FIFO has both item-count and total-byte limits. The coalescing buffer,
setup queues, GATT inventory, parser stacks, collections, fields, reports, and
attribute lengths also have explicit limits. The notification FIFO drops its
oldest queued item under pressure so recent state—especially releases—can still
progress. It emits a rate-limited warning with the dropped `seq_id`; retained
items remain FIFO.

## Home Assistant events

Decoded input is published as `esphome.hid_events`:

```yaml
event_type: esphome.hid_events
data:
  device: AA:BB:CC:DD:EE:01
  hid_service: "3"
  handle: "43"
  characteristic_uuid: 00002a4d-0000-1000-8000-00805f9b34fb
  report_id: "2"
  hid_report_type: input
  transport: notification
  length: "3"
  raw_data: 05.00.00
  decode_status: exact
  profile_id: 3da2b9015a413f09
  seq_id_from: "41"
  seq_id_to: "41"
  field_id: "8"
  collection_id: "1"
  application_usage: Mouse
  application_usage_page: "1"
  application_usage_id: "2"
  usage: X
  usage_page: "1"
  usage_id: "48"
  value: "5"
  raw_value: "5"
  relative: "true"
```

Compatibility fields remain available:

- Event name: `esphome.hid_events`
- `usage`, `usage_page`, `usage_id`
- `value`, `raw_value`, `relative`
- Device/handle/report/transport/raw envelope

Additional fields identify the HID service, schema field, application
collection, decode status, and profile. Unknown usages are formatted as
`<usage_page>_<usage_id>`.

Every emission has `seq_id_from` and `seq_id_to`. They are equal for one source
notification. Coalesced values retain the inclusive sequence span from their
first through last contribution. No event timestamp or coalesced-count field
is emitted.

Unsupported, schema-less, short, mismatched, or otherwise undecodable HID
traffic produces a raw Home Assistant envelope with `decode_status` rather than
being silently discarded. Recognized exact reports with no state changes log
`HID_NO_EVENT` and do not emit an event.

## Optional entities

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

| Platform      | Type               | Value                             |
| ------------- | ------------------ | --------------------------------- |
| `sensor`      | `battery`          | Battery percentage                |
| `sensor`      | `last_event_value` | Most recent decoded numeric value |
| `text_sensor` | `last_event_usage` | Most recent usage name            |
| `text_sensor` | `last_event_code`  | `<usage_page>_<usage_id>`         |

## Reverse-engineering workflow

1. Use `discovery_mode: forensic`, `protocol_mode: unchanged`, and verbose
   logging.
2. Capture the complete connection through `HID_READY`.
3. Perform one isolated physical action at a time.
4. Compare `HID_RAW` handles and payloads with `HID_REPORT_SCHEMA`,
   `HID_COLLECTION`, `HID_FIELD`, and other `GATT_VALUE`/raw streams.
5. Compare Report Map and GATT fingerprints across reconnects or firmware
   revisions.
6. Sanitize the capture before sharing it.

If two physical controls produce the same handle, Report ID, bytes, mode,
surrounding traffic, and readable state, a generic decoder cannot distinguish
them. The forensic inventory maximizes the observable evidence; it cannot
reconstruct information the peripheral never transmits.

## Development

Set up the pinned ESPHome toolchain:

```bash
make setup
```

Run warning-clean native tests:

```bash
make test
make test-sanitize
```

Native coverage includes signed HID items, all report kinds, Boot Keyboard and
Boot Mouse transitions, collections,
physical/unit metadata, string/designator metadata, delimiter aliases, packed
fields, arrays, duplicate usages, short/long payload behavior, malformed-input
smoke fuzzing, Boot report transitions, CCCD setup sequencing and timeout
wraparound, ordered coalescing, saturation, and the generated HID Usage Tables
lookup.

Build both supported CI targets:

```bash
make build BOARD=esp32dev
make build BOARD=esp32-s3-devkitc-1
```

The firmware fixture contains two independent BLE HID clients. One compiles
standard discovery and unchanged Protocol Mode; the other compiles forensic
discovery and explicit Report Mode. Component compiler warnings fail the build.

Contribution requirements:

- Keep discovery and decoding device-agnostic.
- Never branch on a captured device name, address, VID/PID, handle, Report ID,
  vendor UUID, or payload signature.
- Derive semantics from published protocols, GATT metadata, Report References,
  and the Report Map.
- Preserve unknown data numerically or raw.
- Use synthetic minimal fixtures for new tests.
- Run native tests, sanitizers, and both strict firmware builds.
- Preserve the existing event name and compatibility fields.

## Deliberate limitations

- Output and Feature layouts are retained and logged, but the component does
  not expose arbitrary write APIs for them.
- Unknown readable values can have undocumented vendor semantics. Forensic mode
  records them but does not interpret them.
- A successful Write Without Response only proves that ESP-IDF accepted the
  Protocol Mode request for transmission; the peripheral does not provide a
  write response.
- Profile fingerprints describe observed structure and bytes, not secure or
  globally unique identity.
- Observationally identical physical controls cannot be separated without an
  additional signal from the peripheral.

## License

See [LICENSE](LICENSE).
