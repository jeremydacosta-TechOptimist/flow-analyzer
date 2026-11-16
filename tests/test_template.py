"""Tests for the shared template structures and record decoding."""

from __future__ import annotations

import unittest

import support

from flowanalyzer.errors import FlowError
from flowanalyzer.netflow.template import (
    Template,
    TemplateField,
    decode_template_record,
    parse_template_fields,
    template_summary,
)


class TemplateFieldTests(unittest.TestCase):
    """Template field and template data classes."""

    def test_template_record_length(self) -> None:
        template = Template(
            template_id=256,
            fields=(TemplateField(8, 4), TemplateField(7, 2), TemplateField(1, 4)),
        )
        self.assertEqual(template.record_length, 10)
        self.assertFalse(template.is_options)

    def test_scope_and_option_split(self) -> None:
        template = Template(
            template_id=300,
            fields=(
                TemplateField(1, 4),
                TemplateField(34, 4),
                TemplateField(35, 1),
            ),
            is_options=True,
            scope_field_count=1,
        )
        self.assertEqual(len(template.scope_fields), 1)
        self.assertEqual(len(template.option_fields), 2)
        self.assertEqual(template.record_length, 9)

    def test_negative_length_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            TemplateField(8, -1)


class ParseTemplateFieldsTests(unittest.TestCase):
    """Parsing field specifications from template bytes."""

    def test_parse_netflow_style_fields(self) -> None:
        data = support.u16(8) + support.u16(4) + support.u16(12) + support.u16(4)
        fields, offset = parse_template_fields(data, 0, 2)
        self.assertEqual(len(fields), 2)
        self.assertEqual(fields[0].field_id, 8)
        self.assertEqual(fields[0].length, 4)
        self.assertEqual(fields[1].field_id, 12)
        self.assertEqual(offset, len(data))

    def test_parse_enterprise_number(self) -> None:
        data = support.ipfix_field(42, 6, enterprise=4242)
        fields, offset = parse_template_fields(data, 0, 1, enterprise=True)
        self.assertEqual(len(fields), 1)
        self.assertEqual(fields[0].field_id, 42)
        self.assertEqual(fields[0].enterprise, 4242)
        self.assertEqual(fields[0].length, 6)
        self.assertEqual(offset, len(data))

    def test_parse_truncated_field_id(self) -> None:
        with self.assertRaises(FlowError):
            parse_template_fields(b"\x00", 0, 1)

    def test_parse_truncated_field_length(self) -> None:
        with self.assertRaises(FlowError):
            parse_template_fields(support.u16(8), 0, 1)

    def test_parse_truncated_enterprise_number(self) -> None:
        data = struct_high_id() + b"\x00\x00"
        with self.assertRaises(FlowError):
            parse_template_fields(data, 0, 1, enterprise=True)

    def test_parse_respects_limit(self) -> None:
        data = support.u16(8) + support.u16(4)
        with self.assertRaises(FlowError):
            parse_template_fields(data, 0, 2, limit=len(data))


def struct_high_id() -> bytes:
    """Return a field ID with the IPFIX enterprise bit set."""
    return support.u16(0x8000 | 42)


class DecodeTemplateRecordTests(unittest.TestCase):
    """Decoding data records using a template layout."""

    def test_decode_record(self) -> None:
        template = Template(
            template_id=256,
            fields=(
                TemplateField(8, 4),
                TemplateField(12, 4),
                TemplateField(7, 2),
                TemplateField(1, 4),
            ),
        )
        data = (
            support.ip4("192.0.2.10")
            + support.ip4("198.51.100.10")
            + support.u16(49152)
            + support.u32(900)
        )
        values = decode_template_record(data, template)
        self.assertEqual(values["IPV4_SRC_ADDR"], "192.0.2.10")
        self.assertEqual(values["IPV4_DST_ADDR"], "198.51.100.10")
        self.assertEqual(values["SRC_PORT"], 49152)
        self.assertEqual(values["IN_BYTES"], 900)

    def test_short_record_raises(self) -> None:
        template = Template(template_id=256, fields=(TemplateField(8, 4),))
        with self.assertRaises(FlowError):
            decode_template_record(b"\x00\x00", template)

    def test_unknown_field_does_not_break_decoding(self) -> None:
        template = Template(
            template_id=256,
            fields=(TemplateField(8, 4), TemplateField(999, 2)),
        )
        values = decode_template_record(
            support.ip4("192.0.2.10") + b"\xde\xad", template
        )
        self.assertEqual(values["IPV4_SRC_ADDR"], "192.0.2.10")
        self.assertEqual(values["FIELD_999"], b"\xde\xad")

    def test_template_summary(self) -> None:
        template = Template(template_id=256, fields=(TemplateField(8, 4),))
        summary = template_summary(template)
        self.assertIn("template 256", summary)
        self.assertIn("4 bytes", summary)
        options = Template(
            template_id=300,
            fields=(TemplateField(1, 4),),
            is_options=True,
            scope_field_count=1,
        )
        self.assertIn("options template 300", template_summary(options))


if __name__ == "__main__":
    unittest.main()
