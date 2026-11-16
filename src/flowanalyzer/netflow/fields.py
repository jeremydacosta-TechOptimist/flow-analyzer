"""Field registry and value codecs for NetFlow v9 and IPFIX.

NetFlow v9 and IPFIX share the IANA "IPFIX Information Elements" numbering for
the common fields, so one registry covers both formats.  Unknown field IDs are
not fatal: they are surfaced as raw octets under a synthetic name.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

NTP_EPOCH_OFFSET_SECONDS = 2_208_988_800


@dataclass(frozen=True)
class FieldSpec:
    """Description of one known flow field."""

    field_id: int
    name: str
    codec: str
    description: str = ""


def _field(field_id: int, name: str, codec: str, description: str = "") -> tuple[int, FieldSpec]:
    """Build one registry entry."""
    return field_id, FieldSpec(field_id=field_id, name=name, codec=codec, description=description)


FIELD_REGISTRY: dict[int, FieldSpec] = dict(
    [
        _field(1, "IN_BYTES", "uint", "Incoming octet count"),
        _field(2, "IN_PKTS", "uint", "Incoming packet count"),
        _field(4, "PROTOCOL", "uint", "IP protocol number"),
        _field(5, "SRC_TOS", "uint", "IP type of service"),
        _field(6, "TCP_FLAGS", "uint", "Cumulative TCP flags"),
        _field(7, "SRC_PORT", "uint", "TCP/UDP source port"),
        _field(8, "IPV4_SRC_ADDR", "ipv4", "Source IPv4 address"),
        _field(9, "SRC_MASK", "uint", "Source address prefix length"),
        _field(10, "INPUT_SNMP", "uint", "Input interface index"),
        _field(11, "DST_PORT", "uint", "TCP/UDP destination port"),
        _field(12, "IPV4_DST_ADDR", "ipv4", "Destination IPv4 address"),
        _field(13, "DST_MASK", "uint", "Destination address prefix length"),
        _field(14, "OUTPUT_SNMP", "uint", "Output interface index"),
        _field(15, "IPV4_NEXT_HOP", "ipv4", "Next-hop IPv4 address"),
        _field(16, "SRC_AS", "uint", "Source autonomous system number"),
        _field(17, "DST_AS", "uint", "Destination autonomous system number"),
        _field(21, "LAST_SWITCHED", "uint", "sysUpTime at the end of the flow"),
        _field(22, "FIRST_SWITCHED", "uint", "sysUpTime at the start of the flow"),
        _field(27, "IPV6_SRC_ADDR", "ipv6", "Source IPv6 address"),
        _field(28, "IPV6_DST_ADDR", "ipv6", "Destination IPv6 address"),
        _field(29, "IPV6_SRC_MASK", "uint", "Source IPv6 prefix length"),
        _field(30, "IPV6_DST_MASK", "uint", "Destination IPv6 prefix length"),
        _field(34, "SAMPLING_INTERVAL", "uint", "Sampling interval"),
        _field(35, "SAMPLING_ALGORITHM", "uint", "Sampling algorithm"),
        _field(38, "ENGINE_TYPE", "uint", "Exporter engine type"),
        _field(39, "ENGINE_ID", "uint", "Exporter engine id"),
        _field(61, "FLOW_DIRECTION", "uint", "Flow direction"),
        _field(62, "IPV6_NEXT_HOP", "ipv6", "Next-hop IPv6 address"),
        _field(85, "OCTET_DELTA", "uint", "Octet count (IPFIX octetDeltaCount)"),
        _field(86, "PACKET_DELTA", "uint", "Packet count (IPFIX packetDeltaCount)"),
        _field(150, "FLOW_START_SECONDS", "datetime_sec", "Flow start (seconds)"),
        _field(151, "FLOW_END_SECONDS", "datetime_sec", "Flow end (seconds)"),
        _field(152, "FLOW_START_MS", "datetime_ms", "Flow start (milliseconds)"),
        _field(153, "FLOW_END_MS", "datetime_ms", "Flow end (milliseconds)"),
        _field(154, "FLOW_START_US", "datetime_ntp", "Flow start (microseconds)"),
        _field(155, "FLOW_END_US", "datetime_ntp", "Flow end (microseconds)"),
        _field(156, "FLOW_START_NS", "datetime_ntp", "Flow start (nanoseconds)"),
        _field(157, "FLOW_END_NS", "datetime_ntp", "Flow end (nanoseconds)"),
        _field(160, "SYSTEM_INIT_MS", "datetime_ms", "Exporter system init time"),
        _field(305, "SAMPLING_PACKET_INTERVAL", "uint", "Packet sampling interval"),
        _field(306, "SAMPLING_PACKET_SPACE", "uint", "Packet sampling space"),
    ]
)


def get_field_spec(field_id: int) -> FieldSpec:
    """Return the registry entry for a field ID, or a synthetic raw-octets entry."""
    spec = FIELD_REGISTRY.get(field_id)
    if spec is not None:
        return spec
    return FieldSpec(
        field_id=field_id,
        name=f"FIELD_{field_id}",
        codec="octets",
        description="unknown field, kept as raw octets",
    )


def get_field_name(field_id: int, *, enterprise: int = 0) -> str:
    """Return the display name of a field, honouring enterprise numbers."""
    if enterprise:
        return f"ENTERPRISE_{enterprise}_FIELD_{field_id}"
    return get_field_spec(field_id).name


def decode_value(raw: bytes, codec: str) -> Any:
    """Decode raw field bytes according to a codec name."""
    if codec == "uint":
        return int.from_bytes(raw, "big") if raw else 0
    if codec == "ipv4":
        if len(raw) != 4:
            return raw.hex()
        return str(ipaddress.IPv4Address(raw))
    if codec == "ipv6":
        if len(raw) != 16:
            return raw.hex()
        return str(ipaddress.IPv6Address(raw))
    if codec == "mac":
        return ":".join(f"{byte:02x}" for byte in raw)
    if codec == "octets":
        return bytes(raw)
    if codec == "datetime_ms":
        return int.from_bytes(raw, "big") if len(raw) == 8 else int.from_bytes(raw, "big") * 1000
    if codec == "datetime_sec":
        return int.from_bytes(raw, "big") * 1000 if raw else 0
    if codec == "datetime_ntp":
        return ntp_to_epoch_ms(raw)
    raise ValueError(f"unknown field codec {codec!r}")


def decode_field(field_id: int, raw: bytes, *, enterprise: int = 0) -> tuple[str, Any]:
    """Decode one field to ``(name, value)``."""
    if enterprise:
        return get_field_name(field_id, enterprise=enterprise), bytes(raw)
    spec = get_field_spec(field_id)
    return spec.name, decode_value(raw, spec.codec)


def ntp_to_epoch_ms(raw: bytes) -> int:
    """Convert a 64-bit NTP timestamp (seconds + 32-bit fraction) to epoch ms."""
    if len(raw) != 8:
        return 0
    seconds = int.from_bytes(raw[:4], "big")
    fraction = int.from_bytes(raw[4:], "big")
    unix_seconds = seconds - NTP_EPOCH_OFFSET_SECONDS
    return unix_seconds * 1000 + (fraction * 1000) // (1 << 32)


def format_value(value: Any) -> str:
    """Format a decoded field value for text output."""
    if isinstance(value, bytes):
        return "0x" + value.hex() if value else "0x"
    return str(value)
