"""Template handling shared by the NetFlow v9 and IPFIX decoders.

Templates describe the layout of the data records in an export.  They are
identified by a template ID and scoped to one observation domain (source ID in
NetFlow v9).  Templates may be redefined at runtime, and IPFIX allows
withdrawing them; the decoders keep the current definition in a dictionary.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from ..errors import FlowError
from .fields import decode_field


@dataclass(frozen=True)
class TemplateField:
    """One field inside a template record."""

    field_id: int
    length: int
    enterprise: int = 0

    def __post_init__(self) -> None:
        if self.length < 0:
            raise ValueError("template field length cannot be negative")


@dataclass(frozen=True)
class Template:
    """A parsed template record."""

    template_id: int
    fields: tuple[TemplateField, ...]
    is_options: bool = False
    scope_field_count: int = 0

    @property
    def record_length(self) -> int:
        """Return the total encoded length of one data record."""
        return sum(field.length for field in self.fields)

    @property
    def scope_fields(self) -> tuple[TemplateField, ...]:
        """Return the scope fields of an options template."""
        return self.fields[: self.scope_field_count]

    @property
    def option_fields(self) -> tuple[TemplateField, ...]:
        """Return the non-scope fields of an options template."""
        return self.fields[self.scope_field_count :]


def parse_template_fields(
    data: bytes,
    offset: int,
    count: int,
    *,
    enterprise: bool = False,
    limit: int | None = None,
) -> tuple[tuple[TemplateField, ...], int]:
    """Parse ``count`` template field specifications.

    ``enterprise`` enables the IPFIX enterprise-bit encoding (a 4-byte
    enterprise number follows a field ID with the top bit set).  Returns the
    fields and the offset after the last one.
    """
    end = len(data) if limit is None else min(len(data), limit)
    fields: list[TemplateField] = []
    position = offset
    for _ in range(count):
        if position + 2 > end:
            raise FlowError("truncated template: field specification is incomplete")
        raw_id = struct.unpack_from("!H", data, position)[0]
        position += 2
        enterprise_number = 0
        if enterprise and raw_id & 0x8000:
            if position + 4 > end:
                raise FlowError("truncated template: enterprise number is incomplete")
            enterprise_number = struct.unpack_from("!I", data, position)[0]
            position += 4
            field_id = raw_id & 0x7FFF
        else:
            field_id = raw_id
        if position + 2 > end:
            raise FlowError("truncated template: field length is incomplete")
        length = struct.unpack_from("!H", data, position)[0]
        position += 2
        fields.append(
            TemplateField(field_id=field_id, length=length, enterprise=enterprise_number)
        )
    return tuple(fields), position


def decode_template_record(data: bytes, template: Template) -> dict[str, Any]:
    """Decode one data record using the field layout of ``template``."""
    if len(data) < template.record_length:
        raise FlowError("data record is shorter than its template record")
    values: dict[str, Any] = {}
    position = 0
    for field in template.fields:
        raw = data[position : position + field.length]
        position += field.length
        name, value = decode_field(
            field.field_id, raw, enterprise=field.enterprise
        )
        values[name] = value
    return values


def template_summary(template: Template) -> str:
    """Return a short human description of a template."""
    kind = "options template" if template.is_options else "template"
    return (
        f"{kind} {template.template_id}: {len(template.fields)} "
        f"field(s), {template.record_length} bytes per record"
    )
