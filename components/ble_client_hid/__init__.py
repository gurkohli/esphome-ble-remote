from esphome import loader
import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import ble_client, esp32_ble_tracker
from esphome.const import CONF_ID


DEPENDENCIES = ["ble_client"]
AUTO_LOAD = ["json", "sensor", "text_sensor"]
CODE_OWNERS = ["@fsievers22"]

MULTI_CONF = 3
CONF_EVENT_SAMPLING_INTERVAL = "event_sampling_interval"
CONF_DISCOVERY_MODE = "discovery_mode"
CONF_PROTOCOL_MODE = "protocol_mode"
CONF_FORENSIC_ENABLE_WEB_LOGS = "forensic_enable_web_logs"


def validate_event_sampling_interval(value):
    value = cv.positive_time_period_microseconds(value)
    if value.total_microseconds > 3_600_000_000:
        raise cv.Invalid("event_sampling_interval must not exceed 1 hour")
    return value


ble_client_hid_ns = cg.esphome_ns.namespace("ble_client_hid")

BLEClientHID = ble_client_hid_ns.class_(
    "BLEClientHID",
    cg.Component,
    ble_client.BLEClientNode,
    esp32_ble_tracker.ESPBTDeviceListener,
)
DiscoveryMode = ble_client_hid_ns.enum("DiscoveryMode", is_class=True)
ProtocolModePolicy = ble_client_hid_ns.enum("ProtocolModePolicy", is_class=True)

DISCOVERY_MODES = {
    "standard": DiscoveryMode.STANDARD,
    "forensic": DiscoveryMode.FORENSIC,
}
PROTOCOL_MODES = {
    "unchanged": ProtocolModePolicy.UNCHANGED,
    "report": ProtocolModePolicy.REPORT,
    "boot": ProtocolModePolicy.BOOT,
}


def validate_forensic_web_logs(config):
    if not config[CONF_FORENSIC_ENABLE_WEB_LOGS]:
        return config
    discovery_mode = str(config[CONF_DISCOVERY_MODE])
    if discovery_mode not in ("forensic", str(DiscoveryMode.FORENSIC)):
        raise cv.Invalid("forensic_enable_web_logs requires discovery_mode: forensic")
    cv.requires_component("web_server")(True)
    return config


CONFIG_SCHEMA = cv.All(
    (
        cv.Schema(
            {
                cv.GenerateID(): cv.declare_id(BLEClientHID),
                cv.Optional(
                    CONF_EVENT_SAMPLING_INTERVAL, default="0ms"
                ): validate_event_sampling_interval,
                cv.Optional(CONF_DISCOVERY_MODE, default="standard"): cv.enum(
                    DISCOVERY_MODES, lower=True
                ),
                cv.Optional(CONF_PROTOCOL_MODE, default="unchanged"): cv.enum(
                    PROTOCOL_MODES, lower=True
                ),
                cv.Optional(
                    CONF_FORENSIC_ENABLE_WEB_LOGS, default=False
                ): cv.boolean,
            }
        )
        .extend(cv.COMPONENT_SCHEMA)
        .extend(ble_client.BLE_CLIENT_SCHEMA)
        .extend(esp32_ble_tracker.ESP_BLE_DEVICE_SCHEMA)
    ),
    validate_forensic_web_logs,
)

CONF_BLE_CLIENT_HID_ID = "ble_client_hid_id"

BLE_CLIENT_HID_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_BLE_CLIENT_HID_ID): cv.use_id(BLEClientHID),
    }
)


async def register_last_event_usage_text_sensor(var, config):
    parent = await cg.get_variable(config[CONF_BLE_CLIENT_HID_ID])
    cg.add(parent.register_last_event_usage_text_sensor(var))


async def register_last_event_code_text_sensor(var, config):
    parent = await cg.get_variable(config[CONF_BLE_CLIENT_HID_ID])
    cg.add(parent.register_last_event_code_text_sensor(var))


async def register_last_event_value_sensor(var, config):
    parent = await cg.get_variable(config[CONF_BLE_CLIENT_HID_ID])
    cg.add(parent.register_last_event_value_sensor(var))


async def register_battery_sensor(var, config):
    parent = await cg.get_variable(config[CONF_BLE_CLIENT_HID_ID])
    cg.add(parent.register_battery_sensor(var))


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await ble_client.register_ble_node(var, config)
    await esp32_ble_tracker.register_ble_device(var, config)
    cg.add(var.set_event_sampling_interval_us(config[CONF_EVENT_SAMPLING_INTERVAL]))
    cg.add(var.set_discovery_mode(config[CONF_DISCOVERY_MODE]))
    cg.add(var.set_protocol_mode_policy(config[CONF_PROTOCOL_MODE]))
    if config[CONF_FORENSIC_ENABLE_WEB_LOGS]:
        # External components are non-recursive by default. Enable their supported
        # manifest mode so the isolated forensic_web_logging sources are copied.
        manifest = loader.get_component("ble_client_hid", exception=True)
        manifest.recursive_sources = True
        cg.add_define("USE_BLE_CLIENT_HID_FORENSIC_WEB_LOGGING")
        cg.add(
            var.enable_forensic_web_logging(
                f"/ble-hid/{config[CONF_ID]}/forensic"
            )
        )
