"""Handcrafted NetFlow/IPFIX fixtures for the flowanalyzer test suite.

Everything is packed with :mod:`struct` directly, independently of the package
code, so the tests validate the decoders against bytes built from the format
specifications.  Values are fixed to keep the suite deterministic.
"""

from __future__ import annotations

import socket
import struct

SYS_UPTIME = 3_600_000
UNIX_SECONDS = 1_700_000_000
V9_SOURCE_ID = 7


def ip4(text: str) -> bytes:
    """Pack an IPv4 address."""
    return socket.inet_pton(socket.AF_INET, text)


def ip6(text: str) -> bytes:
    """Pack an IPv6 address."""
    return socket.inet_pton(socket.AF_INET6, text)


def u8(value: int) -> bytes:
    """Pack an unsigned 8-bit value."""
    return struct.pack("!B", value)


def u16(value: int) -> bytes:
    """Pack an unsigned 16-bit value."""
    return struct.pack("!H", value)


def u32(value: int) -> bytes:
    """Pack an unsigned 32-bit value."""
    return struct.pack("!I", value)


def u64(value: int) -> bytes:
    """Pack an unsigned 64-bit value."""
    return struct.pack("!Q", value)


# ---------------------------------------------------------------------------
# NetFlow v5
# ---------------------------------------------------------------------------


def v5_header(
    count: int,
    *,
    sys_uptime: int = SYS_UPTIME,
    unix_secs: int = UNIX_SECONDS,
    unix_nsecs: int = 0,
    sequence: int = 1000,
    engine_type: int = 0,
    engine_id: int = 0,
    sampling: int = 0,
) -> bytes:
    """Build a NetFlow v5 header."""
    return struct.pack(
        "!HHIIIIBBH",
        5,
        count,
        sys_uptime,
        unix_secs,
        unix_nsecs,
        sequence,
        engine_type,
        engine_id,
        sampling,
    )


def v5_record(
    *,
    src: str = "192.0.2.10",
    dst: str = "198.51.100.10",
    next_hop: str = "192.0.2.1",
    input_if: int = 2,
    output_if: int = 10,
    packets: int = 5,
    octets: int = 1000,
    first_switched: int = 3_000_000,
    last_switched: int = 3_000_500,
    src_port: int = 49152,
    dst_port: int = 80,
    tcp_flags: int = 0x18,
    protocol: int = 6,
    tos: int = 0,
    src_as: int = 64500,
    dst_as: int = 64496,
    src_mask: int = 24,
    dst_mask: int = 24,
) -> bytes:
    """Build a 48-byte NetFlow v5 record."""
    return struct.pack(
        "!4s4s4sHHIIIIHHBBBBHHBBH",
        ip4(src),
        ip4(dst),
        ip4(next_hop),
        input_if,
        output_if,
        packets,
        octets,
        first_switched,
        last_switched,
        src_port,
        dst_port,
        0,
        tcp_flags,
        protocol,
        tos,
        src_as,
        dst_as,
        src_mask,
        dst_mask,
        0,
    )


def v5_export(
    records: list[bytes],
    *,
    count: int | None = None,
    **header_options: object,
) -> bytes:
    """Build a complete NetFlow v5 export."""
    declared = len(records) if count is None else count
    return v5_header(declared, **header_options) + b"".join(records)


# ---------------------------------------------------------------------------
# NetFlow v9
# ---------------------------------------------------------------------------


def v9_header(
    count: int,
    *,
    sys_uptime: int = SYS_UPTIME,
    unix_secs: int = UNIX_SECONDS,
    sequence: int = 42,
    source_id: int = V9_SOURCE_ID,
) -> bytes:
    """Build a NetFlow v9 header."""
    return struct.pack("!HHIIII", 9, count, sys_uptime, unix_secs, sequence, source_id)


def v9_flowset(flowset_id: int, body: bytes) -> bytes:
    """Build one NetFlow v9 FlowSet with 4-byte padding."""
    padded = body + b"\x00" * ((4 - len(body) % 4) % 4)
    return struct.pack("!HH", flowset_id, 4 + len(padded)) + padded


def v9_template_flowset(template_id: int, fields: tuple[tuple[int, int], ...]) -> bytes:
    """Build a template FlowSet containing one template."""
    body = struct.pack("!HH", template_id, len(fields))
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in fields)
    return v9_flowset(0, body)


def v9_options_template_flowset(
    template_id: int,
    scope_fields: tuple[tuple[int, int], ...],
    option_fields: tuple[tuple[int, int], ...],
) -> bytes:
    """Build an options template FlowSet containing one options template."""
    body = struct.pack("!HHH", template_id, len(scope_fields) * 4, len(option_fields) * 4)
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in scope_fields)
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in option_fields)
    return v9_flowset(1, body)


def v9_data_flowset(template_id: int, records: list[bytes]) -> bytes:
    """Build a data FlowSet for a template."""
    return v9_flowset(template_id, b"".join(records))


def v9_export(
    flowsets: list[bytes],
    *,
    count: int = 1,
    **header_options: object,
) -> bytes:
    """Build a NetFlow v9 message from FlowSets."""
    return v9_header(count, **header_options) + b"".join(flowsets)


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
)


def v9_ipv4_record(
    *,
    src: str = "192.0.2.10",
    dst: str = "198.51.100.10",
    src_port: int = 49152,
    dst_port: int = 80,
    protocol: int = 6,
    tcp_flags: int = 0x18,
    octets: int = 1000,
    packets: int = 5,
    first_switched: int = 3_000_000,
    last_switched: int = 3_000_500,
) -> bytes:
    """Build one data record matching :data:`V9_IPV4_FIELDS`."""
    return b"".join(
        (
            ip4(src),
            ip4(dst),
            u16(src_port),
            u16(dst_port),
            u8(protocol),
            u8(tcp_flags),
            u32(octets),
            u32(packets),
            u32(first_switched),
            u32(last_switched),
        )
    )


def v9_ipv6_record(
    *,
    src: str = "2001:db8::10",
    dst: str = "2001:db8:100::10",
    src_port: int = 52000,
    dst_port: int = 443,
    protocol: int = 6,
    tcp_flags: int = 0x18,
    octets: int = 2000,
    packets: int = 7,
    first_switched: int = 3_000_000,
    last_switched: int = 3_001_000,
) -> bytes:
    """Build one IPv6 data record matching :data:`V9_IPV6_FIELDS`."""
    return b"".join(
        (
            ip6(src),
            ip6(dst),
            u16(src_port),
            u16(dst_port),
            u8(protocol),
            u8(tcp_flags),
            u32(octets),
            u32(packets),
            u32(first_switched),
            u32(last_switched),
        )
    )


# ---------------------------------------------------------------------------
# IPFIX
# ---------------------------------------------------------------------------


def ipfix_header(
    length: int,
    *,
    export_time: int = UNIX_SECONDS,
    sequence: int = 77,
    domain: int = 99,
) -> bytes:
    """Build an IPFIX message header."""
    return struct.pack("!HHIII", 10, length, export_time, sequence, domain)


def ipfix_set(set_id: int, body: bytes) -> bytes:
    """Build one IPFIX Set with 4-byte padding."""
    padded = body + b"\x00" * ((4 - len(body) % 4) % 4)
    return struct.pack("!HH", set_id, 4 + len(padded)) + padded


def ipfix_field(field_id: int, length: int, *, enterprise: int | None = None) -> bytes:
    """Build one IPFIX template field specification."""
    if enterprise is None:
        return struct.pack("!HH", field_id, length)
    return struct.pack("!HIH", 0x8000 | field_id, enterprise, length)


def ipfix_template_record(
    template_id: int,
    fields: tuple[tuple[int, int], ...],
    *,
    enterprise: dict[int, int] | None = None,
) -> bytes:
    """Build one IPFIX template record."""
    enterprise = enterprise or {}
    body = struct.pack("!HH", template_id, len(fields))
    for field_id, length in fields:
        body += ipfix_field(field_id, length, enterprise=enterprise.get(field_id))
    return body


def ipfix_template_set(records: list[bytes]) -> bytes:
    """Build an IPFIX template set from template records."""
    return ipfix_set(2, b"".join(records))


def ipfix_options_template_record(
    template_id: int,
    scope_fields: tuple[tuple[int, int], ...],
    option_fields: tuple[tuple[int, int], ...],
) -> bytes:
    """Build one IPFIX options template record."""
    fields = scope_fields + option_fields
    body = struct.pack("!HHH", template_id, len(fields), len(scope_fields))
    body += b"".join(struct.pack("!HH", field_id, length) for field_id, length in fields)
    return body


def ipfix_options_template_set(records: list[bytes]) -> bytes:
    """Build an IPFIX options template set."""
    return ipfix_set(3, b"".join(records))


def ipfix_message(sets: list[bytes], **header_options: object) -> bytes:
    """Build an IPFIX message with a correct length field."""
    body = b"".join(sets)
    length = 16 + len(body)
    return ipfix_header(length, **header_options) + body


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
)


def ipfix_ipv4_record(
    *,
    src: str = "192.0.2.10",
    dst: str = "198.51.100.10",
    src_port: int = 49152,
    dst_port: int = 80,
    protocol: int = 6,
    tcp_flags: int = 0x18,
    octets: int = 1000,
    packets: int = 5,
    start_ms: int = 1_700_000_000_000,
    end_ms: int = 1_700_000_000_500,
) -> bytes:
    """Build one IPFIX data record matching :data:`IPFIX_IPV4_FIELDS`."""
    return b"".join(
        (
            ip4(src),
            ip4(dst),
            u16(src_port),
            u16(dst_port),
            u8(protocol),
            u8(tcp_flags),
            u32(octets),
            u32(packets),
            u64(start_ms),
            u64(end_ms),
        )
    )


def ipfix_ipv6_record(
    *,
    src: str = "2001:db8::10",
    dst: str = "2001:db8:100::10",
    src_port: int = 52000,
    dst_port: int = 443,
    protocol: int = 6,
    tcp_flags: int = 0x18,
    octets: int = 2000,
    packets: int = 7,
    start_ms: int = 1_700_000_000_000,
    end_ms: int = 1_700_000_001_000,
) -> bytes:
    """Build one IPv6 IPFIX data record matching :data:`IPFIX_IPV6_FIELDS`."""
    return b"".join(
        (
            ip6(src),
            ip6(dst),
            u16(src_port),
            u16(dst_port),
            u8(protocol),
            u8(tcp_flags),
            u32(octets),
            u32(packets),
            u64(start_ms),
            u64(end_ms),
        )
    )
