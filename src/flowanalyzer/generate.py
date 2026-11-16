"""Deterministic synthetic NetFlow v5, NetFlow v9 and IPFIX exporters.

The generator exists so the tool can be demonstrated and tested offline.  It
encodes a small lab capture with realistic flows from the documentation address
ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32) and is
fully deterministic for a given seed.
"""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .model import FORMAT_IPFIX, FORMAT_V5, FORMAT_V9

SUPPORTED_FORMATS = (FORMAT_V5, FORMAT_V9, FORMAT_IPFIX)
DEFAULT_FLOWS = 12
DEFAULT_SEED = 7
DEFAULT_SAMPLING_INTERVAL = 1

BASE_TIME_MS = (
    int(datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc).timestamp()) * 1000
)
EXPORT_TIME_MS = BASE_TIME_MS + 600_000
SYS_UPTIME_MS = 3_600_000
V9_SOURCE_ID = 7
IPFIX_OBSERVATION_DOMAIN = 99
V5_SEQUENCE = 1000
V9_SEQUENCE = 42
IPFIX_SEQUENCE = 200
V5_MAX_RECORDS = 30


@dataclass(frozen=True)
class Scenario:
    """One traffic pattern used to build synthetic flows."""

    name: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    protocol: int
    tcp_flags: int
    bytes: int
    packets: int


SCENARIOS: tuple[Scenario, ...] = (
    Scenario("web-http", "192.0.2.10", "198.51.100.10", 49876, 80, 6, 0x1B, 4120, 9),
    Scenario("web-https", "192.0.2.11", "198.51.100.10", 51422, 443, 6, 0x10, 8640, 18),
    Scenario("dns", "192.0.2.12", "198.51.100.20", 53523, 53, 17, 0x00, 164, 1),
    Scenario("smtp", "192.0.2.13", "198.51.100.30", 49152, 25, 6, 0x18, 980, 7),
    Scenario("ssh", "192.0.2.10", "198.51.100.40", 51000, 22, 6, 0x18, 6400, 24),
    Scenario("ntp", "192.0.2.11", "198.51.100.50", 123, 123, 17, 0x00, 76, 1),
    Scenario("icmp", "192.0.2.30", "203.0.113.5", 0, 0, 1, 0x00, 128, 2),
    Scenario("web-remote", "192.0.2.12", "203.0.113.20", 49100, 443, 6, 0x10, 5230, 12),
    Scenario("ipv6-https", "2001:db8::10", "2001:db8:100::10", 52000, 443, 6, 0x10, 7420, 15),
    Scenario("ipv6-dns", "2001:db8::11", "2001:db8::53", 5353, 53, 17, 0x00, 150, 1),
)


@dataclass(frozen=True)
class GeneratedFlow:
    """One synthetic flow before it is encoded into an export format."""

    src: str
    dst: str
    src_port: int
    dst_port: int
    protocol: int
    tcp_flags: int
    bytes: int
    packets: int
    start_ms: int
    end_ms: int
    input_if: int
    output_if: int
    src_as: int
    dst_as: int
    tos: int
    next_hop: str

    @property
    def is_ipv6(self) -> bool:
        """Return whether the flow uses IPv6 addresses."""
        return ":" in self.src or ":" in self.dst


def is_ipv6(address: str) -> bool:
    """Return whether an address is an IPv6 address."""
    return ":" in address


def build_flows(
    count: int = DEFAULT_FLOWS,
    seed: int = DEFAULT_SEED,
    *,
    allow_ipv6: bool = True,
) -> list[GeneratedFlow]:
    """Build a deterministic list of synthetic flows.

    Every fourth flow (after the first) is the reverse direction of the
    previous one, so bidirectional conversations always exist in the output.
    """
    if count < 1:
        raise ValueError("flow count must be at least 1")
    randomizer = random.Random(seed)
    scenarios = [
        scenario for scenario in SCENARIOS if allow_ipv6 or not is_ipv6(scenario.src)
    ]
    flows: list[GeneratedFlow] = []
    for index in range(count):
        if flows and index % 4 == 3:
            previous = flows[-1]
            flows.append(
                GeneratedFlow(
                    src=previous.dst,
                    dst=previous.src,
                    src_port=previous.dst_port,
                    dst_port=previous.src_port,
                    protocol=previous.protocol,
                    tcp_flags=0x10 if previous.protocol == 6 else 0x00,
                    bytes=max(1, previous.bytes // 2),
                    packets=max(1, previous.packets // 2),
                    start_ms=previous.start_ms + 200,
                    end_ms=previous.end_ms + 400,
                    input_if=previous.output_if,
                    output_if=previous.input_if,
                    src_as=previous.dst_as,
                    dst_as=previous.src_as,
                    tos=0,
                    next_hop=previous.next_hop,
                )
            )
            continue
        scenario = scenarios[index % len(scenarios)]
        factor = randomizer.randint(1, 3)
        start_offset = randomizer.randint(0, 4_000)
        duration = randomizer.choice((180, 420, 900, 1500, 2200))
        start_ms = BASE_TIME_MS + index * 12_000 + start_offset
        flows.append(
            GeneratedFlow(
                src=scenario.src,
                dst=scenario.dst,
                src_port=scenario.src_port,
                dst_port=scenario.dst_port,
                protocol=scenario.protocol,
                tcp_flags=scenario.tcp_flags,
                bytes=scenario.bytes * factor + randomizer.randint(0, 400),
                packets=max(
                    1, (scenario.packets * factor) // 2 + randomizer.randint(1, 4)
                ),
                start_ms=start_ms,
                end_ms=start_ms + duration,
                input_if=2 + (index % 3),
                output_if=10 + (index % 4),
                src_as=64500,
                dst_as=64496,
                tos=0x10 if scenario.protocol == 6 else 0,
                next_hop=(
                    "2001:db8::1" if is_ipv6(scenario.dst) else "192.0.2.1"
                ),
            )
        )
    return flows


def _pack_ip(address: str) -> bytes:
    """Pack an IPv4 or IPv6 address string to bytes."""
    family = socket.AF_INET6 if is_ipv6(address) else socket.AF_INET
    return socket.inet_pton(family, address)


def _value_bytes(value: bytes | int, length: int) -> bytes:
    """Encode one template field value to exactly ``length`` bytes."""
    if isinstance(value, bytes):
        if len(value) != length:
            raise ValueError(
                f"value has {len(value)} bytes but the template field wants {length}"
            )
        return value
    return int(value).to_bytes(length, "big")


def _padded_set(set_id: int, body: bytes) -> bytes:
    """Build one NetFlow v9 FlowSet or IPFIX Set with 4-byte padding."""
    padded = body + b"\x00" * ((4 - len(body) % 4) % 4)
    return struct.pack("!HH", set_id, 4 + len(padded)) + padded


# ---------------------------------------------------------------------------
# NetFlow v5
# ---------------------------------------------------------------------------

V5_HEADER = struct.Struct("!HHIIIIBBH")
V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")


def _uptime_for_epoch(epoch_ms: int) -> int:
    """Return the sysUpTime value corresponding to an epoch timestamp."""
    return (SYS_UPTIME_MS - (EXPORT_TIME_MS - epoch_ms)) & 0xFFFFFFFF


def encode_v5(
    flows: list[GeneratedFlow],
    *,
    sampling_interval: int = DEFAULT_SAMPLING_INTERVAL,
) -> bytes:
    """Encode synthetic flows as a single NetFlow v5 export."""
    if len(flows) > V5_MAX_RECORDS:
        raise ValueError(
            f"NetFlow v5 carries at most {V5_MAX_RECORDS} records per export"
        )
    for flow in flows:
        if flow.is_ipv6:
            raise ValueError("NetFlow v5 cannot carry IPv6 addresses")
    sampling_raw = (
        int(sampling_interval) & 0x3FFF if sampling_interval > 1 else 0
    )
    buffer = bytearray(
        V5_HEADER.pack(
            5,
            len(flows),
            SYS_UPTIME_MS,
            EXPORT_TIME_MS // 1000,
            (EXPORT_TIME_MS % 1000) * 1_000_000,
            V5_SEQUENCE,
            0,
            0,
            sampling_raw,
        )
    )
    for flow in flows:
        buffer += V5_RECORD.pack(
            _pack_ip(flow.src),
            _pack_ip(flow.dst),
            _pack_ip(flow.next_hop),
            flow.input_if,
            flow.output_if,
            flow.packets,
            flow.bytes,
            _uptime_for_epoch(flow.start_ms),
            _uptime_for_epoch(flow.end_ms),
            flow.src_port,
            flow.dst_port,
            0,
            flow.tcp_flags,
            flow.protocol,
            flow.tos,
            flow.src_as & 0xFFFF,
            flow.dst_as & 0xFFFF,
            0,
            0,
            0,
        )
    return bytes(buffer)


# ---------------------------------------------------------------------------
# NetFlow v9
# ---------------------------------------------------------------------------

V9_IPV4_TEMPLATE = 256
V9_IPV6_TEMPLATE = 257
V9_OPTIONS_TEMPLATE = 300
V9_IPV4_FIELDS = (
    (8, 4),
    (12, 4),
    (7, 2),
    (11, 2),
    (4, 1),
    (6, 1),
    (1, 4),
    (2, 4),
    (22, 4),
    (21, 4),
    (10, 2),
    (14, 2),
    (16, 4),
    (17, 4),
    (5, 1),
)
V9_IPV6_FIELDS = (
    (27, 16),
    (28, 16),
    (7, 2),
    (11, 2),
    (4, 1),
    (6, 1),
    (1, 4),
    (2, 4),
    (22, 4),
    (21, 4),
    (10, 2),
    (14, 2),
    (16, 4),
    (17, 4),
    (5, 1),
)
V9_OPTION_SCOPE_FIELDS = ((1, 4),)
V9_OPTION_FIELDS = ((34, 4), (35, 1))


def _template_body(template_id: int, fields: tuple[tuple[int, int], ...]) -> bytes:
    """Encode a template record (template id, field count, fields)."""
    body = struct.pack("!HH", template_id, len(fields))
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in fields)
    return body


def _options_template_body(
    template_id: int,
    scope_fields: tuple[tuple[int, int], ...],
    option_fields: tuple[tuple[int, int], ...],
) -> bytes:
    """Encode a NetFlow v9 options template record."""
    body = struct.pack("!HHH", template_id, len(scope_fields) * 4, len(option_fields) * 4)
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in scope_fields)
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in option_fields)
    return body


def _v9_record(flow: GeneratedFlow, *, ipv6: bool) -> bytes:
    """Encode one NetFlow v9 data record for the generated templates."""
    first_switched = _uptime_for_epoch(flow.start_ms)
    last_switched = _uptime_for_epoch(flow.end_ms)
    values: list[bytes | int] = [
        _pack_ip(flow.src),
        _pack_ip(flow.dst),
        flow.src_port,
        flow.dst_port,
        flow.protocol,
        flow.tcp_flags,
        flow.bytes,
        flow.packets,
        first_switched,
        last_switched,
        flow.input_if,
        flow.output_if,
        flow.src_as,
        flow.dst_as,
        flow.tos,
    ]
    fields = V9_IPV6_FIELDS if ipv6 else V9_IPV4_FIELDS
    return b"".join(
        _value_bytes(value, length) for value, (_field_id, length) in zip(values, fields)
    )


def _ordered_family_groups(
    flows: list[GeneratedFlow],
) -> list[tuple[bool, list[GeneratedFlow]]]:
    """Group flows by address family while preserving export order."""
    groups: list[tuple[bool, list[GeneratedFlow]]] = []
    for flow in flows:
        family = flow.is_ipv6
        if groups and groups[-1][0] == family:
            groups[-1][1].append(flow)
        else:
            groups.append((family, [flow]))
    return groups


def encode_v9(
    flows: list[GeneratedFlow],
    *,
    sampling_interval: int = DEFAULT_SAMPLING_INTERVAL,
    source_id: int = V9_SOURCE_ID,
) -> bytes:
    """Encode synthetic flows as a single NetFlow v9 export."""
    flowsets = [
        _padded_set(0, _template_body(V9_IPV4_TEMPLATE, V9_IPV4_FIELDS)),
        _padded_set(0, _template_body(V9_IPV6_TEMPLATE, V9_IPV6_FIELDS)),
        _padded_set(
            1,
            _options_template_body(
                V9_OPTIONS_TEMPLATE, V9_OPTION_SCOPE_FIELDS, V9_OPTION_FIELDS
            ),
        ),
    ]
    options_body = (
        struct.pack("!I", source_id)
        + struct.pack("!I", max(1, int(sampling_interval)))
        + b"\x00"
    )
    flowsets.append(_padded_set(V9_OPTIONS_TEMPLATE, options_body))
    for ipv6, group in _ordered_family_groups(flows):
        template_id = V9_IPV6_TEMPLATE if ipv6 else V9_IPV4_TEMPLATE
        flowsets.append(
            _padded_set(
                template_id,
                b"".join(_v9_record(flow, ipv6=ipv6) for flow in group),
            )
        )
    header = struct.pack(
        "!HHIIII",
        9,
        len(flows),
        SYS_UPTIME_MS,
        EXPORT_TIME_MS // 1000,
        V9_SEQUENCE,
        source_id,
    )
    return header + b"".join(flowsets)


# ---------------------------------------------------------------------------
# IPFIX
# ---------------------------------------------------------------------------

IPFIX_IPV4_TEMPLATE = 256
IPFIX_IPV6_TEMPLATE = 257
IPFIX_OPTIONS_TEMPLATE = 300
IPFIX_IPV4_FIELDS = (
    (8, 4),
    (12, 4),
    (7, 2),
    (11, 2),
    (4, 1),
    (6, 1),
    (1, 4),
    (2, 4),
    (152, 8),
    (153, 8),
    (10, 2),
    (14, 2),
    (16, 4),
    (17, 4),
    (5, 1),
)
IPFIX_IPV6_FIELDS = (
    (27, 16),
    (28, 16),
    (7, 2),
    (11, 2),
    (4, 1),
    (6, 1),
    (1, 4),
    (2, 4),
    (152, 8),
    (153, 8),
    (10, 2),
    (14, 2),
    (16, 4),
    (17, 4),
    (5, 1),
)
IPFIX_OPTION_SCOPE_FIELDS = ((149, 4),)
IPFIX_OPTION_FIELDS = ((34, 4), (35, 1))


def _ipfix_template_record(template_id: int, fields: tuple[tuple[int, int], ...]) -> bytes:
    """Encode one IPFIX template record (no enterprise fields)."""
    body = struct.pack("!HH", template_id, len(fields))
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in fields)
    return body


def _ipfix_options_template_record(
    template_id: int,
    scope_fields: tuple[tuple[int, int], ...],
    option_fields: tuple[tuple[int, int], ...],
) -> bytes:
    """Encode one IPFIX options template record."""
    fields = scope_fields + option_fields
    body = struct.pack("!HHH", template_id, len(fields), len(scope_fields))
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in fields)
    return body


def _ipfix_record(flow: GeneratedFlow, *, ipv6: bool) -> bytes:
    """Encode one IPFIX data record for the generated templates."""
    values: list[bytes | int] = [
        _pack_ip(flow.src),
        _pack_ip(flow.dst),
        flow.src_port,
        flow.dst_port,
        flow.protocol,
        flow.tcp_flags,
        flow.bytes,
        flow.packets,
        flow.start_ms,
        flow.end_ms,
        flow.input_if,
        flow.output_if,
        flow.src_as,
        flow.dst_as,
        flow.tos,
    ]
    fields = IPFIX_IPV6_FIELDS if ipv6 else IPFIX_IPV4_FIELDS
    return b"".join(
        _value_bytes(value, length) for value, (_field_id, length) in zip(values, fields)
    )


def encode_ipfix(
    flows: list[GeneratedFlow],
    *,
    sampling_interval: int = DEFAULT_SAMPLING_INTERVAL,
    observation_domain_id: int = IPFIX_OBSERVATION_DOMAIN,
) -> bytes:
    """Encode synthetic flows as a single IPFIX message."""
    template_set = _padded_set(
        2,
        _ipfix_template_record(IPFIX_IPV4_TEMPLATE, IPFIX_IPV4_FIELDS)
        + _ipfix_template_record(IPFIX_IPV6_TEMPLATE, IPFIX_IPV6_FIELDS),
    )
    options_template_set = _padded_set(
        3,
        _ipfix_options_template_record(
            IPFIX_OPTIONS_TEMPLATE, IPFIX_OPTION_SCOPE_FIELDS, IPFIX_OPTION_FIELDS
        ),
    )
    options_set = _padded_set(
        IPFIX_OPTIONS_TEMPLATE,
        struct.pack("!I", observation_domain_id)
        + struct.pack("!I", max(1, int(sampling_interval)))
        + b"\x00",
    )
    sets = [template_set, options_template_set, options_set]
    for ipv6, group in _ordered_family_groups(flows):
        template_id = IPFIX_IPV6_TEMPLATE if ipv6 else IPFIX_IPV4_TEMPLATE
        sets.append(
            _padded_set(
                template_id,
                b"".join(_ipfix_record(flow, ipv6=ipv6) for flow in group),
            )
        )
    body = b"".join(sets)
    header = struct.pack(
        "!HHIII",
        10,
        16 + len(body),
        EXPORT_TIME_MS // 1000,
        IPFIX_SEQUENCE,
        observation_domain_id,
    )
    return header + body


# ---------------------------------------------------------------------------
# Public generator API
# ---------------------------------------------------------------------------


def generate_bytes(
    export_format: str,
    *,
    flows: int = DEFAULT_FLOWS,
    seed: int = DEFAULT_SEED,
    sampling_interval: int = DEFAULT_SAMPLING_INTERVAL,
) -> bytes:
    """Generate one synthetic export of the requested format."""
    if sampling_interval < 1:
        raise ValueError("sampling interval must be at least 1")
    if export_format == FORMAT_V5:
        generated = build_flows(flows, seed, allow_ipv6=False)
        return encode_v5(generated, sampling_interval=sampling_interval)
    if export_format == FORMAT_V9:
        generated = build_flows(flows, seed, allow_ipv6=True)
        return encode_v9(generated, sampling_interval=sampling_interval)
    if export_format == FORMAT_IPFIX:
        generated = build_flows(flows, seed, allow_ipv6=True)
        return encode_ipfix(generated, sampling_interval=sampling_interval)
    raise ValueError(
        f"unsupported export format {export_format!r} "
        f"(choose from {', '.join(SUPPORTED_FORMATS)})"
    )


def write_export(
    path: str | Path,
    export_format: str,
    *,
    flows: int = DEFAULT_FLOWS,
    seed: int = DEFAULT_SEED,
    sampling_interval: int = DEFAULT_SAMPLING_INTERVAL,
) -> int:
    """Generate an export and write it to ``path``; return the byte size."""
    data = generate_bytes(
        export_format,
        flows=flows,
        seed=seed,
        sampling_interval=sampling_interval,
    )
    destination = Path(path)
    destination.write_bytes(data)
    return len(data)
