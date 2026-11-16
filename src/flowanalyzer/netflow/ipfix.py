"""IPFIX decoder (RFC 7011).

An IPFIX message starts with a 16-byte header followed by Sets.  Template Sets
(ID 2) and Options Template Sets (ID 3) define the record layout; Data Sets
(ID >= 256) carry the actual flow records.  Enterprise-specific fields are
decoded using the enterprise bit, and padding is ignored or reported
explicitly.
"""

from __future__ import annotations

import struct

from ..errors import FlowError
from ..model import FORMAT_IPFIX, FlowExport, FlowRecord, build_record
from ..sampling import interval_from_fields
from .template import Template, decode_template_record, parse_template_fields

IPFIX_HEADER = struct.Struct("!HHIII")
HEADER_LENGTH = IPFIX_HEADER.size
TEMPLATE_SET_ID = 2
OPTIONS_TEMPLATE_SET_ID = 3
DATA_SET_ID_MIN = 256
RESERVED_SET_IDS = frozenset({0, 1})


def decode_ipfix(data: bytes, exporter: str = "") -> FlowExport:
    """Decode one IPFIX message."""
    if len(data) < HEADER_LENGTH:
        raise FlowError(
            f"truncated IPFIX header: {len(data)} of {HEADER_LENGTH} bytes"
        )
    version, length, export_time, sequence, observation_domain_id = (
        IPFIX_HEADER.unpack_from(data, 0)
    )
    if version != 10:
        raise FlowError(f"not an IPFIX export (version field is {version})")
    if length < HEADER_LENGTH:
        raise FlowError(
            f"invalid IPFIX message length {length} (shorter than the {HEADER_LENGTH}-byte header)"
        )

    warnings: list[str] = []
    truncated = False
    if length > len(data):
        warnings.append(
            f"truncated IPFIX message: header declares {length} bytes, only "
            f"{len(data)} are present"
        )
        truncated = True
        end = len(data)
    else:
        end = length
        if length < len(data):
            warnings.append(
                f"{len(data) - length} trailing byte(s) after the IPFIX message "
                "were ignored"
            )
    if length % 4:
        warnings.append(f"IPFIX message length {length} is not a multiple of 4")

    header = {
        "sequence": sequence,
        "export_time_ms": export_time * 1000,
        "observation_domain_id": observation_domain_id,
        "length": length,
    }
    templates: dict[tuple[int, int], Template] = {}
    records: list[FlowRecord] = []
    template_count = 0
    sampling_interval = 1
    offset = HEADER_LENGTH

    while offset < end:
        remaining = end - offset
        if remaining < 4:
            warnings.append(
                f"{remaining} trailing byte(s) after the last set were ignored"
            )
            break
        set_id, set_length = struct.unpack_from("!HH", data, offset)
        if set_length < 4:
            warnings.append(
                f"invalid set length {set_length} for set {set_id} at offset "
                f"{offset}; stopped decoding"
            )
            truncated = True
            break
        if set_length > remaining:
            warnings.append(
                f"truncated set {set_id} at offset {offset}: declared "
                f"{set_length} bytes, {remaining} available"
            )
            truncated = True
            break
        if set_length % 4:
            warnings.append(
                f"set {set_id} length {set_length} is not a multiple of 4"
            )
        body = data[offset + 4 : offset + set_length]

        if set_id == TEMPLATE_SET_ID:
            parsed, set_warnings = _parse_template_set(
                body, observation_domain_id, templates, options=False
            )
            template_count += parsed
            warnings.extend(set_warnings)
        elif set_id == OPTIONS_TEMPLATE_SET_ID:
            parsed, set_warnings = _parse_template_set(
                body, observation_domain_id, templates, options=True
            )
            template_count += parsed
            warnings.extend(set_warnings)
        elif set_id >= DATA_SET_ID_MIN:
            template = templates.get((observation_domain_id, set_id))
            if template is None:
                warnings.append(
                    f"data set {set_id} at offset {offset} skipped: its template "
                    "was not received yet"
                )
            elif template.is_options:
                sampling_interval, set_warnings = _decode_options_set(body, template)
                warnings.extend(set_warnings)
            else:
                decoded, set_warnings = _decode_data_set(
                    body,
                    template,
                    exporter=exporter,
                    observation_domain_id=observation_domain_id,
                    header=header,
                    sampling_interval=sampling_interval,
                )
                records.extend(decoded)
                warnings.extend(set_warnings)
        elif set_id in RESERVED_SET_IDS:
            warnings.append(f"reserved set id {set_id} at offset {offset} skipped")
        else:
            warnings.append(f"unknown set id {set_id} at offset {offset} skipped")
        offset += set_length

    return FlowExport(
        format=FORMAT_IPFIX,
        version=10,
        exporter=exporter,
        records=records,
        warnings=warnings,
        header=header,
        template_count=template_count,
        truncated=truncated,
    )


def _parse_template_set(
    body: bytes,
    observation_domain_id: int,
    templates: dict[tuple[int, int], Template],
    *,
    options: bool,
) -> tuple[int, list[str]]:
    """Parse a template set or options template set body."""
    warnings: list[str] = []
    parsed = 0
    position = 0
    while position < len(body):
        remaining = len(body) - position
        if remaining < 4:
            if any(body[position:]):
                warnings.append("template set has trailing non-zero bytes")
            break
        template_id = struct.unpack_from("!H", body, position)[0]
        if template_id == 0:
            if any(body[position:]):
                warnings.append("template set contains a record with template id 0")
            break
        key = (observation_domain_id, template_id)
        if options:
            if remaining < 6:
                warnings.append(
                    f"truncated options template {template_id}: header is incomplete"
                )
                break
            template_id, field_count, scope_field_count = struct.unpack_from(
                "!HHH", body, position
            )
            position += 6
            if field_count == 0:
                templates.pop(key, None)
                warnings.append(f"options template {template_id} was withdrawn")
                parsed += 1
                continue
            if scope_field_count > field_count:
                warnings.append(
                    f"options template {template_id} declares {scope_field_count} "
                    f"scope fields but only {field_count} fields"
                )
                scope_field_count = field_count
            try:
                fields, position = parse_template_fields(
                    body, position, field_count, enterprise=True
                )
            except FlowError as exc:
                warnings.append(
                    f"truncated options template {template_id}: {exc}"
                )
                break
            templates[key] = Template(
                template_id=template_id,
                fields=fields,
                is_options=True,
                scope_field_count=scope_field_count,
            )
            parsed += 1
        else:
            template_id, field_count = struct.unpack_from("!HH", body, position)
            position += 4
            if field_count == 0:
                templates.pop(key, None)
                warnings.append(f"template {template_id} was withdrawn")
                parsed += 1
                continue
            try:
                fields, position = parse_template_fields(
                    body, position, field_count, enterprise=True
                )
            except FlowError as exc:
                warnings.append(f"truncated template {template_id}: {exc}")
                break
            templates[key] = Template(template_id=template_id, fields=fields)
            parsed += 1
    return parsed, warnings


def _decode_data_set(
    body: bytes,
    template: Template,
    *,
    exporter: str,
    observation_domain_id: int,
    header: dict[str, object],
    sampling_interval: int,
) -> tuple[list[FlowRecord], list[str]]:
    """Decode the complete data records of one IPFIX data set."""
    warnings: list[str] = []
    record_length = template.record_length
    if record_length <= 0:
        warnings.append(
            f"template {template.template_id} has a zero-length record; set skipped"
        )
        return [], warnings
    records: list[FlowRecord] = []
    position = 0
    while position + record_length <= len(body):
        values = decode_template_record(body[position : position + record_length], template)
        records.append(
            build_record(
                exporter=exporter,
                version=10,
                source_id=observation_domain_id,
                fields=values,
                header=header,
                default_sampling=sampling_interval,
            )
        )
        position += record_length
    remainder = body[position:]
    if any(remainder):
        warnings.append(
            f"data set {template.template_id} has {len(remainder)} trailing "
            "non-zero byte(s); the record layout may be invalid"
        )
    return records, warnings


def _decode_options_set(
    body: bytes, template: Template
) -> tuple[int, list[str]]:
    """Decode an options data set and return the sampling interval it carries."""
    warnings: list[str] = []
    interval = 1
    record_length = template.record_length
    if record_length <= 0:
        warnings.append(
            f"options template {template.template_id} has a zero-length record; "
            "set skipped"
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
            f"options set {template.template_id} has {len(remainder)} trailing "
            "non-zero byte(s)"
        )
    return interval, warnings
