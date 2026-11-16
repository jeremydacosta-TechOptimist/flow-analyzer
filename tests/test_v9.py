"""Tests for the NetFlow v9 decoder."""

from __future__ import annotations

import struct
import unittest

import support

from flowanalyzer.errors import FlowError
from flowanalyzer.netflow.v9 import decode_v9


def simple_export(
    records: list[bytes] | None = None,
    *,
    template_id: int = 256,
    fields: tuple[tuple[int, int], ...] = support.V9_IPV4_FIELDS,
    **header_options: object,
) -> bytes:
    """Build a template plus data export."""
    records = records if records is not None else [support.v9_ipv4_record()]
    return support.v9_export(
        [
            support.v9_template_flowset(template_id, fields),
            support.v9_data_flowset(template_id, records),
        ],
        count=len(records),
        **header_options,
    )


class V9HeaderTests(unittest.TestCase):
    """Header parsing."""

    def test_header_fields(self) -> None:
        export = decode_v9(simple_export(sequence=99, source_id=7), exporter="edge1.bin")
        self.assertEqual(export.format, "v9")
        self.assertEqual(export.version, 9)
        self.assertEqual(export.exporter, "edge1.bin")
        self.assertEqual(export.header["sequence"], 99)
        self.assertEqual(export.header["source_id"], 7)
        self.assertEqual(export.header["sys_uptime_ms"], support.SYS_UPTIME)
        self.assertEqual(export.header["export_time_ms"], support.UNIX_SECONDS * 1000)

    def test_truncated_header_raises(self) -> None:
        with self.assertRaises(FlowError):
            decode_v9(b"\x00\x09\x00\x01")

    def test_wrong_version_raises(self) -> None:
        with self.assertRaises(FlowError):
            decode_v9(support.v5_export([]))


class V9DecodingTests(unittest.TestCase):
    """Template and data FlowSet decoding."""

    def test_template_and_single_record(self) -> None:
        export = decode_v9(simple_export())
        self.assertEqual(len(export.records), 1)
        self.assertEqual(export.template_count, 1)
        self.assertEqual(export.warnings, [])
        record = export.records[0]
        self.assertEqual(record.src_ip, "192.0.2.10")
        self.assertEqual(record.dst_ip, "198.51.100.10")
        self.assertEqual(record.src_port, 49152)
        self.assertEqual(record.dst_port, 80)
        self.assertEqual(record.protocol_name, "TCP")
        self.assertEqual(record.bytes, 1000)
        self.assertEqual(record.packets, 5)
        self.assertEqual(record.source_id, support.V9_SOURCE_ID)

    def test_multiple_records_in_one_flowset(self) -> None:
        records = [
            support.v9_ipv4_record(octets=1000),
            support.v9_ipv4_record(octets=2000, dst_port=443),
            support.v9_ipv4_record(octets=3000),
        ]
        export = decode_v9(simple_export(records))
        self.assertEqual(len(export.records), 3)
        self.assertEqual([record.bytes for record in export.records], [1000, 2000, 3000])

    def test_timestamps_from_uptime(self) -> None:
        export = decode_v9(simple_export())
        record = export.records[0]
        self.assertEqual(record.start_ms, support.UNIX_SECONDS * 1000 - 600_000)
        self.assertEqual(record.duration_ms, 500)

    def test_ipv6_template(self) -> None:
        export = decode_v9(
            support.v9_export(
                [
                    support.v9_template_flowset(257, support.V9_IPV6_FIELDS),
                    support.v9_data_flowset(257, [support.v9_ipv6_record()]),
                ],
                count=1,
            )
        )
        self.assertEqual(len(export.records), 1)
        record = export.records[0]
        self.assertEqual(record.src_ip, "2001:db8::10")
        self.assertEqual(record.dst_ip, "2001:db8:100::10")
        self.assertEqual(record.src_port, 52000)

    def test_multiple_templates_in_one_flowset(self) -> None:
        body = struct.pack("!HH", 256, len(support.V9_IPV4_FIELDS))
        body += b"".join(
            struct.pack("!HH", field_id, length)
            for field_id, length in support.V9_IPV4_FIELDS
        )
        body += struct.pack("!HH", 257, len(support.V9_IPV6_FIELDS))
        body += b"".join(
            struct.pack("!HH", field_id, length)
            for field_id, length in support.V9_IPV6_FIELDS
        )
        export = decode_v9(
            support.v9_export(
                [
                    support.v9_flowset(0, body),
                    support.v9_data_flowset(256, [support.v9_ipv4_record()]),
                    support.v9_data_flowset(257, [support.v9_ipv6_record()]),
                ],
                count=2,
            )
        )
        self.assertEqual(export.template_count, 2)
        self.assertEqual(len(export.records), 2)

    def test_template_redefinition(self) -> None:
        new_fields = ((1, 4), (2, 4))
        export = decode_v9(
            support.v9_export(
                [
                    support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                    support.v9_data_flowset(256, [support.v9_ipv4_record(octets=1000)]),
                    support.v9_template_flowset(256, new_fields),
                    support.v9_data_flowset(256, [support.u32(7000) + support.u32(70)]),
                ],
                count=2,
            )
        )
        self.assertEqual(len(export.records), 2)
        self.assertEqual(export.records[0].bytes, 1000)
        self.assertEqual(export.records[1].bytes, 7000)
        self.assertEqual(export.records[1].packets, 70)
        self.assertEqual(export.records[1].src_ip, "")

    def test_template_count_tracks_definitions(self) -> None:
        export = decode_v9(
            support.v9_export(
                [
                    support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                    support.v9_template_flowset(257, support.V9_IPV6_FIELDS),
                ],
                count=0,
            )
        )
        self.assertEqual(export.template_count, 2)
        self.assertEqual(export.records, [])

    def test_padding_is_ignored(self) -> None:
        export = decode_v9(simple_export())
        self.assertEqual(export.warnings, [])


class V9WarningTests(unittest.TestCase):
    """Recoverable problems reported as warnings."""

    def test_data_before_template_is_skipped(self) -> None:
        data = support.v9_export(
            [
                support.v9_data_flowset(256, [support.v9_ipv4_record()]),
                support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
            ],
            count=1,
        )
        export = decode_v9(data)
        self.assertEqual(export.records, [])
        self.assertEqual(export.template_count, 1)
        self.assertTrue(any("not received yet" in warning for warning in export.warnings))

    def test_missing_template_is_skipped(self) -> None:
        export = decode_v9(
            support.v9_export(
                [support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                 support.v9_data_flowset(999, [support.v9_ipv4_record()])],
                count=1,
            )
        )
        self.assertEqual(len(export.records), 0)
        self.assertTrue(any("999" in warning for warning in export.warnings))

    def test_unknown_flowset_is_skipped(self) -> None:
        export = decode_v9(
            support.v9_export(
                [
                    support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                    support.v9_flowset(5, b"\x00\x00\x00\x00"),
                    support.v9_data_flowset(256, [support.v9_ipv4_record()]),
                ],
                count=1,
            )
        )
        self.assertEqual(len(export.records), 1)
        self.assertTrue(any("unknown flowset id 5" in warning for warning in export.warnings))

    def test_truncated_flowset_stops_decoding(self) -> None:
        good = support.v9_template_flowset(256, support.V9_IPV4_FIELDS)
        truncated_data = struct.pack("!HH", 256, 200) + b"\x00" * 20
        export = decode_v9(support.v9_header(1) + good + truncated_data)
        self.assertTrue(export.truncated)
        self.assertTrue(any("truncated flowset" in warning for warning in export.warnings))

    def test_invalid_flowset_length_stops_decoding(self) -> None:
        data = support.v9_header(0) + struct.pack("!HH", 0, 2) + b"\x00\x00"
        export = decode_v9(data)
        self.assertTrue(export.truncated)
        self.assertTrue(any("invalid flowset length" in warning for warning in export.warnings))

    def test_truncated_template_is_reported(self) -> None:
        body = struct.pack("!HH", 256, 5) + struct.pack("!HH", 8, 4)
        data = support.v9_header(0) + support.v9_flowset(0, body)
        export = decode_v9(data)
        self.assertEqual(export.records, [])
        self.assertTrue(any("truncated template 256" in warning for warning in export.warnings))

    def test_non_zero_trailing_data_warns(self) -> None:
        record = support.v9_ipv4_record()
        body = record + b"\xde"
        data = support.v9_export(
            [
                support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                support.v9_flowset(256, body),
            ],
            count=1,
        )
        export = decode_v9(data)
        self.assertEqual(len(export.records), 1)
        self.assertTrue(any("trailing non-zero" in warning for warning in export.warnings))

    def test_zero_trailing_bytes_are_padding(self) -> None:
        record = support.v9_ipv4_record()
        # The 30-byte record needs two padding bytes inside the FlowSet.
        self.assertEqual(len(record) % 4, 2)
        data = support.v9_export(
            [
                support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                support.v9_data_flowset(256, [record]),
            ],
            count=1,
        )
        export = decode_v9(data)
        self.assertEqual(export.warnings, [])


class V9OptionsTests(unittest.TestCase):
    """Options templates and sampling."""

    def test_options_template_records_scope_and_options(self) -> None:
        data = support.v9_export(
            [
                support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                support.v9_options_template_flowset(300, ((1, 4),), ((34, 4), (35, 1))),
            ],
            count=0,
        )
        export = decode_v9(data)
        self.assertEqual(export.template_count, 2)
        self.assertEqual(export.records, [])

    def test_options_sampling_scales_data_records(self) -> None:
        options_record = support.u32(support.V9_SOURCE_ID) + support.u32(10) + b"\x00"
        data = support.v9_export(
            [
                support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                support.v9_options_template_flowset(300, ((1, 4),), ((34, 4), (35, 1))),
                support.v9_data_flowset(300, [options_record]),
                support.v9_data_flowset(256, [support.v9_ipv4_record(octets=1000, packets=5)]),
            ],
            count=1,
        )
        export = decode_v9(data)
        self.assertEqual(len(export.records), 1)
        record = export.records[0]
        self.assertTrue(record.sampled)
        self.assertEqual(record.sample_interval, 10)
        self.assertEqual(record.bytes, 10_000)
        self.assertEqual(record.raw_bytes, 1000)

    def test_options_interval_one_does_not_scale(self) -> None:
        options_record = support.u32(support.V9_SOURCE_ID) + support.u32(1) + b"\x00"
        data = support.v9_export(
            [
                support.v9_template_flowset(256, support.V9_IPV4_FIELDS),
                support.v9_options_template_flowset(300, ((1, 4),), ((34, 4), (35, 1))),
                support.v9_data_flowset(300, [options_record]),
                support.v9_data_flowset(256, [support.v9_ipv4_record()]),
            ],
            count=1,
        )
        export = decode_v9(data)
        self.assertFalse(export.records[0].sampled)
        self.assertEqual(export.records[0].bytes, 1000)

    def test_zero_length_options_record_warns(self) -> None:
        data = support.v9_export(
            [
                support.v9_options_template_flowset(300, (), ()),
                support.v9_flowset(300, b""),
            ],
            count=0,
        )
        export = decode_v9(data)
        self.assertEqual(export.records, [])
        self.assertTrue(export.warnings)


if __name__ == "__main__":
    unittest.main()
