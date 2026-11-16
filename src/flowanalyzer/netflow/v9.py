"""NetFlow v9 decoder (RFC 3954).

A v9 export is a sequence of FlowSets: template FlowSets (ID 0), options
template FlowSets (ID 1) and data FlowSets (ID >= 256).  Templates are scoped
by ``(source_id, template_id)`` and may be redefined during a capture.  Data
that arrives before its template is skipped with a warning because the record
layout is unknown at that point.
"""

from __future__ import annotations

import struct

from ..errors import FlowError
from ..model import FORMAT_V9, FlowExport, FlowRecord, build_record
from ..sampling import interval_from_fields
from .template import Template, decode_template_record, parse_template_fields

V9_HEADER = struct.Struct("!HHIIII")
HEADER_LENGTH = V9_HEADER.size
TEMPLATE_SET_ID = 0
OPTIONS_TEMPLATE_SET_ID = 1
DATA_SET_ID_MIN = 256


def decode_v9(data: bytes, exporter: str = "") -> FlowExport:
    """Decode one NetFlow v9 export."""
    if len(data) < HEADER_LENGTH:
        raise FlowError(
            f"truncated NetFlow v9 header: {len(data)} of {HEADER_LENGTH} bytes"
        )
    version, count, sys_uptime_ms, unix_seconds, sequence, source_id = (
        V9_HEADER.unpack_from(data, 0)
    )
    if version != 9:
        raise FlowError(f"not a NetFlow v9 export (version field is {version})")

    exporter_time_ms = unix_seconds * 1000
    header = {
        "sequence": sequence,
        "export_time_ms": exporter_time_ms,
        "sys_uptime_ms": sys_uptime_ms,
        "source_id": source_id,
        "declared_count": count,
    }
    templates: dict[tuple[int, int], Template] = {}
    records: list[FlowRecord] = []
    warnings: list[str] = []
    template_count = 0
    truncated = False
    sampling_interval = 1
    offset = HEADER_LENGTH

    while offset < len(data):
        remaining = len(data) - offset
        if remaining < 4:
            warnings.append(
                f"{remaining} trailing byte(s) after the last flowset were ignored"
            )
            break
        flowset_id, length = struct.unpack_from("!HH", data, offset)
        if length < 4:
            warnings.append(
                f"invalid flowset length {length} at offset {offset}; stopped decoding"
            )
            truncated = True
            break
        if length > remaining:
            warnings.append(
                f"truncated flowset {flowset_id} at offset {offset}: "
                f"declared {length} bytes, {remaining} available"
            )
            truncated = True
            break
        body = data[offset + 4 : offset + length]

        if flowset_id == TEMPLATE_SET_ID:
            parsed, template_warnings = _parse_template_flowset(
                body, source_id, templates, options=False
            )
            template_count += parsed
            warnings.extend(template_warnings)
        elif flowset_id == OPTIONS_TEMPLATE_SET_ID:
            parsed, template_warnings = _parse_template_flowset(
                body, source_id, templates, options=True
            )
            template_count += parsed
            warnings.extend(template_warnings)
        elif flowset_id >= DATA_SET_ID_MIN:
            template = templates.get((source_id, flowset_id))
            if template is None:
                warnings.append(
                    f"data flowset {flowset_id} at offset {offset} skipped: "
                    "its template was not received yet"
                )
            elif template.is_options:
                sampling_interval, option_warnings = _decode_options_flowset(
                    body, template
                )
                warnings.extend(option_warnings)
            else:
                decoded, data_warnings = _decode_data_flowset(
                    body,
                    template,
                    exporter=exporter,
                    source_id=source_id,
                    header=header,
                    sampling_interval=sampling_interval,
                )
                records.extend(decoded)
                warnings.extend(data_warnings)
        else:
            warnings.append(
                f"unknown flowset id {flowset_id} at offset {offset} skipped"
            )
        offset += length

    return FlowExport(
        format=FORMAT_V9,
        version=9,
        exporter=exporter,
        records=records,
        warnings=warnings,
        header=header,
        template_count=template_count,
        truncated=truncated,
    )


def _parse_template_flowset(
    body: bytes,
    source_id: int,
    templates: dict[tuple[int, int], Template],
    *,
    options: bool,
) -> tuple[int, list[str]]:
    """Parse a template or options-template flowset body."""
    warnings: list[str] = []
    parsed = 0
    position = 0
    while position < len(body):
        remaining = len(body) - position
        if remaining < 4:
            if any(body[position:]):
                warnings.append("template flowset has trailing non-zero bytes")
            break
        template_id = struct.unpack_from("!H", body, position)[0]
        if template_id == 0:
            if any(body[position:]):
                warnings.append("template flowset has trailing non-zero bytes")
            break
        if options:
            if remaining < 6:
                warnings.append(
                    f"truncated options template {template_id}: header is incomplete"
                )
                break
            template_id, scope_length, option_length = struct.unpack_from(
                "!HHH", body, position
            )
            position += 6
            if scope_length % 4:
                warnings.append(
                    f"options template {template_id} scope length {scope_length} "
                    "is not a multiple of 4"
                )
            scope_count = scope_length // 4
            field_count = scope_count + option_length // 4
            try:
                fields, position = parse_template_fields(body, position, field_count)
            except FlowError as exc:
                warnings.append(
                    f"truncated options template {template_id}: {exc}"
                )
                break
            templates[(source_id, template_id)] = Template(
                template_id=template_id,
                fields=fields,
                is_options=True,
                scope_field_count=scope_count,
            )
            parsed += 1
        else:
            template_id, field_count = struct.unpack_from("!HH", body, position)
            position += 4
            try:
                fields, position = parse_template_fields(body, position, field_count)
            except FlowError as exc:
                warnings.append(f"truncated template {template_id}: {exc}")
                break
            templates[(source_id, template_id)] = Template(
                template_id=template_id, fields=fields
            )
            parsed += 1
    return parsed, warnings


def _decode_data_flowset(
    body: bytes,
    template: Template,
    *,
    exporter: str,
    source_id: int,
    header: dict[str, object],
    sampling_interval: int,
) -> tuple[list[FlowRecord], list[str]]:
    """Decode every complete data record of one data flowset."""
    warnings: list[str] = []
    record_length = template.record_length
    if record_length <= 0:
        warnings.append(
            f"template {template.template_id} has a zero-length record; flowset skipped"
        )
        return [], warnings
    records: list[FlowRecord] = []
    position = 0
    while position + record_length <= len(body):
        values = decode_template_record(body[position : position + record_length], template)
        records.append(
            build_record(
                exporter=exporter,
                version=9,
                source_id=source_id,
                fields=values,
                header=header,
                default_sampling=sampling_interval,
            )
        )
        position += record_length
    remainder = body[position:]
    if any(remainder):
        warnings.append(
            f"data flowset {template.template_id} has {len(remainder)} trailing "
            "non-zero byte(s); the record layout may be invalid"
        )
    return records, warnings


def _decode_options_flowset(
    body: bytes, template: Template
) -> tuple[int, list[str]]:
    """Decode an options flowset and return the sampling interval it carries."""
    warnings: list[str] = []
    interval = 1
    record_length = template.record_length
    if record_length <= 0:
        warnings.append(
            f"options template {template.template_id} has a zero-length record; "
            "flowset skipped"
        )
        return interval, warnings
    position = 0
    while position + record_length <= len(body):
        values = decode_template_record(body[position : position + record_length], template)
        interval = interval_from_fields(values, default=interval)
        position += record_length
    remainder = body[position:]
    if any(remainder):
        warnings.append(
            f"options flowset {template.template_id} has {len(remainder)} trailing "
            "non-zero byte(s)"
        )
    return interval, warnings
