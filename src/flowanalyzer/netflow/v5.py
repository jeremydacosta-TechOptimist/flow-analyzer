"""NetFlow v5 decoder.

The v5 record layout is fixed: a 24-byte header followed by up to 30 records of
48 bytes.  Flow start/end times are exported as ``sysUpTime`` values and are
converted to epoch milliseconds using the header wall-clock time.
"""

from __future__ import annotations

import struct

from ..errors import FlowError
from ..model import FORMAT_V5, FlowExport, build_record
from ..sampling import sampling_from_v5_header
from .fields import decode_value

V5_HEADER = struct.Struct("!HHIIIIBBH")
V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")
HEADER_LENGTH = V5_HEADER.size
RECORD_LENGTH = V5_RECORD.size
MAX_RECORDS = 30
SAMPLING_MODE_TIME_BASED = 2


def decode_v5(data: bytes, exporter: str = "") -> FlowExport:
    """Decode one NetFlow v5 export."""
    if len(data) < HEADER_LENGTH:
        raise FlowError(
            f"truncated NetFlow v5 header: {len(data)} of {HEADER_LENGTH} bytes"
        )
    (
        version,
        count,
        sys_uptime_ms,
        unix_seconds,
        unix_nanoseconds,
        sequence,
        engine_type,
        engine_id,
        sampling_raw,
    ) = V5_HEADER.unpack_from(data, 0)
    if version != 5:
        raise FlowError(f"not a NetFlow v5 export (version field is {version})")

    warnings: list[str] = []
    truncated = False
    if count > MAX_RECORDS:
        warnings.append(
            f"header declares {count} records but NetFlow v5 allows at most {MAX_RECORDS}"
        )
    available = (len(data) - HEADER_LENGTH) // RECORD_LENGTH
    if count == 0:
        records_to_decode = available
        if available:
            warnings.append(
                f"header record count is 0 but {available} complete record(s) are present"
            )
    else:
        records_to_decode = min(count, available)
        if available < count:
            warnings.append(
                f"truncated NetFlow v5 export: header declares {count} records, "
                f"only {available} complete record(s) are present"
            )
            truncated = True
        elif available > count:
            warnings.append(
                f"{available - count} trailing record(s) after the {count} "
                "declared record(s) were ignored"
            )
    trailing_bytes = (len(data) - HEADER_LENGTH) % RECORD_LENGTH
    if trailing_bytes:
        warnings.append(
            f"{trailing_bytes} trailing byte(s) after the last complete record"
        )
        truncated = True

    export_time_ms = unix_seconds * 1000 + unix_nanoseconds // 1_000_000
    sampling_mode, sampling_interval = sampling_from_v5_header(sampling_raw)
    if sampling_interval < 1:
        sampling_interval = 1
    if sampling_mode == SAMPLING_MODE_TIME_BASED and sampling_interval > 1:
        warnings.append(
            "NetFlow v5 time-based sampling is reported but counters are not scaled"
        )
        scale_interval = 1
    else:
        scale_interval = sampling_interval

    header = {
        "sequence": sequence,
        "export_time_ms": export_time_ms,
        "sys_uptime_ms": sys_uptime_ms,
        "engine_type": engine_type,
        "engine_id": engine_id,
        "sampling_mode": sampling_mode,
        "sampling_interval": sampling_interval,
    }

    records = []
    for index in range(records_to_decode):
        unpacked = V5_RECORD.unpack_from(data, HEADER_LENGTH + index * RECORD_LENGTH)
        (
            src_address,
            dst_address,
            next_hop,
            input_if,
            output_if,
            packets,
            octets,
            first_switched,
            last_switched,
            src_port,
            dst_port,
            _pad1,
            tcp_flags,
            protocol,
            tos,
            src_as,
            dst_as,
            src_mask,
            dst_mask,
            _pad2,
        ) = unpacked
        fields = {
            "IPV4_SRC_ADDR": decode_value(src_address, "ipv4"),
            "IPV4_DST_ADDR": decode_value(dst_address, "ipv4"),
            "IPV4_NEXT_HOP": decode_value(next_hop, "ipv4"),
            "INPUT_SNMP": input_if,
            "OUTPUT_SNMP": output_if,
            "IN_PKTS": packets,
            "IN_BYTES": octets,
            "FIRST_SWITCHED": first_switched,
            "LAST_SWITCHED": last_switched,
            "SRC_PORT": src_port,
            "DST_PORT": dst_port,
            "TCP_FLAGS": tcp_flags,
            "PROTOCOL": protocol,
            "SRC_TOS": tos,
            "SRC_AS": src_as,
            "DST_AS": dst_as,
            "SRC_MASK": src_mask,
            "DST_MASK": dst_mask,
        }
        records.append(
            build_record(
                exporter=exporter,
                version=5,
                source_id=0,
                fields=fields,
                header=header,
                engine_type=engine_type,
                engine_id=engine_id,
                default_sampling=scale_interval,
            )
        )

    return FlowExport(
        format=FORMAT_V5,
        version=5,
        exporter=exporter,
        records=records,
        warnings=warnings,
        header=header,
        template_count=0,
        truncated=truncated,
    )
