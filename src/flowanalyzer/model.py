"""Data model for decoded flow records and exports.

A :class:`FlowRecord` is the normalised view of one exported flow, independent
of the NetFlow/IPFIX version it came from.  :func:`build_record` is the single
place where version-specific field values are mapped onto that normalised
record, so the v5, v9 and IPFIX decoders stay small and consistent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .sampling import normalize_interval

FORMAT_V5 = "v5"
FORMAT_V9 = "v9"
FORMAT_IPFIX = "ipfix"

IPV4_ANY = "0.0.0.0"

PROTOCOL_NAMES: dict[int, str] = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    4: "IP-in-IP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

ENGINE_TYPE_NAMES: dict[int, str] = {
    0: "standard",
    1: "NetFlow v5 flow-switch",
    2: "NetFlow v5 flow-router",
    3: "NetFlow v5 switch",
}
_unknown_protocol = "protocol {number}"


def protocol_name(protocol: int) -> str:
    """Return the human name of an IP protocol number."""
    return PROTOCOL_NAMES.get(protocol, _unknown_protocol.format(number=protocol))


def uptime_to_epoch_ms(export_time_ms: int, sys_uptime_ms: int, uptime_ms: int) -> int:
    """Convert a sysUpTime-based flow timestamp to epoch milliseconds.

    NetFlow v5 and v9 report ``FIRST_SWITCHED``/``LAST_SWITCHED`` as the value
    of ``sysUpTime`` when the flow started or ended.  Subtracting the age of
    that uptime value from the export wall-clock time yields the epoch time.
    The 32-bit subtraction is wrapped to handle counter wrap-around.
    """
    delta = (sys_uptime_ms - uptime_ms) & 0xFFFFFFFF
    if delta >= 0x80000000:
        delta -= 0x100000000
    return export_time_ms - delta


def _first(fields: dict[str, Any], *names: str) -> Any:
    """Return the first present, non-None value among ``names``."""
    for name in names:
        value = fields.get(name)
        if value is not None:
            return value
    return None


def _int_value(value: Any) -> int:
    """Coerce an exported counter to ``int`` while tolerating odd values."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, bytes):
        return int.from_bytes(value, "big") if value else 0
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return 0
    return 0


def _timestamp_ms(
    fields: dict[str, Any],
    *,
    absolute: tuple[str, ...],
    seconds: tuple[str, ...],
    ntp: tuple[str, ...],
    uptime: tuple[str, ...],
    export_time_ms: int,
    sys_uptime_ms: int,
    system_init_ms: int | None,
) -> int:
    """Resolve one flow timestamp from the available field variants."""
    value = _first(fields, *absolute)
    if value is not None:
        return _int_value(value)
    value = _first(fields, *seconds)
    if value is not None:
        return _int_value(value) * 1000
    value = _first(fields, *ntp)
    if value is not None:
        return _int_value(value)
    value = _first(fields, *uptime)
    if value is not None:
        if system_init_ms is not None:
            return system_init_ms + _int_value(value)
        return uptime_to_epoch_ms(export_time_ms, sys_uptime_ms, _int_value(value))
    return export_time_ms


@dataclass
class FlowRecord:
    """One normalised flow record."""

    exporter: str
    version: int
    source_id: int
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    tcp_flags: int = 0
    bytes: int = 0
    packets: int = 0
    start_ms: int = 0
    end_ms: int = 0
    input_if: int = 0
    output_if: int = 0
    src_as: int = 0
    dst_as: int = 0
    tos: int = 0
    sampled: bool = False
    sample_interval: int = 1
    raw_bytes: int | None = None
    raw_packets: int | None = None
    next_hop: str | None = None
    src_mask: int = 0
    dst_mask: int = 0
    engine_type: int = 0
    engine_id: int = 0

    @property
    def duration_ms(self) -> int:
        """Return the flow duration in milliseconds (never negative)."""
        return max(0, self.end_ms - self.start_ms)

    @property
    def protocol_name(self) -> str:
        """Return the human name of the IP protocol number."""
        return protocol_name(self.protocol)

    @property
    def endpoint_source(self) -> str:
        """Return the source endpoint as a display string."""
        return format_endpoint(self.src_ip, self.src_port)

    @property
    def endpoint_destination(self) -> str:
        """Return the destination endpoint as a display string."""
        return format_endpoint(self.dst_ip, self.dst_port)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        payload: dict[str, Any] = {
            "exporter": self.exporter,
            "version": self.version,
            "source_id": self.source_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "protocol_name": self.protocol_name,
            "tcp_flags": self.tcp_flags,
            "bytes": self.bytes,
            "packets": self.packets,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "duration_ms": self.duration_ms,
            "input_if": self.input_if,
            "output_if": self.output_if,
            "src_as": self.src_as,
            "dst_as": self.dst_as,
            "tos": self.tos,
            "sampled": self.sampled,
            "sample_interval": self.sample_interval,
            "next_hop": self.next_hop,
            "src_mask": self.src_mask,
            "dst_mask": self.dst_mask,
            "engine_type": self.engine_type,
            "engine_id": self.engine_id,
        }
        if self.raw_bytes is not None:
            payload["raw_bytes"] = self.raw_bytes
        if self.raw_packets is not None:
            payload["raw_packets"] = self.raw_packets
        return payload


def format_endpoint(address: str, port: int) -> str:
    """Format an address and port, bracketing IPv6 addresses.

    A zero port means the protocol has no ports (for example ICMP), so only the
    address is rendered.
    """
    if not address:
        return "-"
    if not port:
        return address
    if ":" in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"


@dataclass
class FlowExport:
    """One decoded export (a single NetFlow/IPFIX message)."""

    format: str
    version: int
    exporter: str = ""
    records: list[FlowRecord] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    header: dict[str, Any] = field(default_factory=dict)
    template_count: int = 0
    truncated: bool = False

    @property
    def record_count(self) -> int:
        """Return the number of decoded flow records."""
        return len(self.records)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the export metadata."""
        return {
            "format": self.format,
            "version": self.version,
            "exporter": self.exporter,
            "header": dict(self.header),
            "records": self.record_count,
            "templates": self.template_count,
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "records_detail": [record.to_dict() for record in self.records],
        }


def build_record(
    *,
    exporter: str,
    version: int,
    source_id: int,
    fields: dict[str, Any],
    header: dict[str, Any],
    engine_type: int = 0,
    engine_id: int = 0,
    default_sampling: int = 1,
) -> FlowRecord:
    """Build a :class:`FlowRecord` from decoded template fields."""
    export_time_ms = _int_value(header.get("export_time_ms"))
    sys_uptime_ms = _int_value(header.get("sys_uptime_ms"))
    system_init_ms_raw = header.get("system_init_ms")
    system_init_ms = (
        _int_value(system_init_ms_raw) if system_init_ms_raw is not None else None
    )

    start_ms = _timestamp_ms(
        fields,
        absolute=("FLOW_START_MS",),
        seconds=("FLOW_START_SECONDS",),
        ntp=("FLOW_START_US", "FLOW_START_NS"),
        uptime=("FIRST_SWITCHED",),
        export_time_ms=export_time_ms,
        sys_uptime_ms=sys_uptime_ms,
        system_init_ms=system_init_ms,
    )
    end_ms = _timestamp_ms(
        fields,
        absolute=("FLOW_END_MS",),
        seconds=("FLOW_END_SECONDS",),
        ntp=("FLOW_END_US", "FLOW_END_NS"),
        uptime=("LAST_SWITCHED",),
        export_time_ms=export_time_ms,
        sys_uptime_ms=sys_uptime_ms,
        system_init_ms=system_init_ms,
    )
    if end_ms < start_ms:
        end_ms = start_ms

    sampling_value = _first(fields, "SAMPLING_INTERVAL", "SAMPLING_PACKET_INTERVAL")
    if sampling_value is not None:
        interval = normalize_interval(_int_value(sampling_value))
    else:
        interval = normalize_interval(default_sampling)

    raw_bytes = _int_value(_first(fields, "IN_BYTES", "OCTET_DELTA"))
    raw_packets = _int_value(_first(fields, "IN_PKTS", "PACKET_DELTA"))
    if interval > 1:
        scaled_bytes = raw_bytes * interval
        scaled_packets = raw_packets * interval
    else:
        scaled_bytes = raw_bytes
        scaled_packets = raw_packets

    next_hop = _first(fields, "IPV4_NEXT_HOP", "IPV6_NEXT_HOP")
    src_ip = _first(fields, "IPV4_SRC_ADDR", "IPV6_SRC_ADDR") or ""
    dst_ip = _first(fields, "IPV4_DST_ADDR", "IPV6_DST_ADDR") or ""

    return FlowRecord(
        exporter=exporter,
        version=version,
        source_id=source_id,
        src_ip=str(src_ip),
        dst_ip=str(dst_ip),
        src_port=_int_value(_first(fields, "SRC_PORT")),
        dst_port=_int_value(_first(fields, "DST_PORT")),
        protocol=_int_value(_first(fields, "PROTOCOL")),
        tcp_flags=_int_value(_first(fields, "TCP_FLAGS")),
        bytes=scaled_bytes,
        packets=scaled_packets,
        start_ms=start_ms,
        end_ms=end_ms,
        input_if=_int_value(_first(fields, "INPUT_SNMP")),
        output_if=_int_value(_first(fields, "OUTPUT_SNMP")),
        src_as=_int_value(_first(fields, "SRC_AS")),
        dst_as=_int_value(_first(fields, "DST_AS")),
        tos=_int_value(_first(fields, "SRC_TOS")),
        sampled=interval > 1,
        sample_interval=interval,
        raw_bytes=raw_bytes if interval > 1 else None,
        raw_packets=raw_packets if interval > 1 else None,
        next_hop=str(next_hop) if next_hop is not None else None,
        src_mask=_int_value(_first(fields, "SRC_MASK")),
        dst_mask=_int_value(_first(fields, "DST_MASK")),
        engine_type=engine_type,
        engine_id=engine_id,
    )
