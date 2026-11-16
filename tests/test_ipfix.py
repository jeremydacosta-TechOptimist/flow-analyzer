"""Tests for the IPFIX (v10) decoder."""

from __future__ import annotations

import struct
import unittest

import support

from flowanalyzer.errors import FlowError
from flowanalyzer.netflow.ipfix import decode_ipfix

START_MS = 1_700_000_000_000


def simple_message(records: list[bytes] | None = None, **options: object) -> bytes:
    """Build an IPFIX message with an IPv4 template and one data set."""
    records = records if records is not None else [support.ipfix_ipv4_record()]
    return support.ipfix_message(
        [
            support.ipfix_template_set(
                [support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)]
            ),
            support.ipfix_set(256, b"".join(records)),
        ],
        **options,
    )


class IpfixHeaderTests(unittest.TestCase):
    """Message header parsing."""

    def test_header_fields(self) -> None:
        export = decode_ipfix(
            simple_message(export_time=1_700_000_005, sequence=77, domain=99),
            exporter="collector.bin",
        )
        self.assertEqual(export.format, "ipfix")
        self.assertEqual(export.version, 10)
        self.assertEqual(export.exporter, "collector.bin")
        self.assertEqual(export.header["sequence"], 77)
        self.assertEqual(export.header["observation_domain_id"], 99)
        self.assertEqual(export.header["export_time_ms"], 1_700_000_005_000)
        self.assertEqual(export.header["length"], len(simple_message()))

    def test_truncated_header_raises(self) -> None:
        with self.assertRaises(FlowError):
            decode_ipfix(b"\x00\x0a\x00\x00")

    def test_wrong_version_raises(self) -> None:
        with self.assertRaises(FlowError):
            decode_ipfix(support.v9_export([]))

    def test_invalid_length_raises(self) -> None:
        data = support.ipfix_header(4) + b"\x00" * 8
        with self.assertRaises(FlowError):
            decode_ipfix(data)

    def test_truncated_message_is_reported(self) -> None:
        data = simple_message()
        export = decode_ipfix(data[:-6])
        self.assertTrue(export.truncated)
        self.assertTrue(any("truncated IPFIX message" in warning for warning in export.warnings))

    def test_trailing_bytes_after_message_warn(self) -> None:
        export = decode_ipfix(simple_message() + b"\x00\x00\x00\x00")
        self.assertEqual(len(export.records), 1)
        self.assertFalse(export.truncated)
        self.assertTrue(any("trailing byte" in warning for warning in export.warnings))

    def test_message_length_not_multiple_of_four_warns(self) -> None:
        data = support.ipfix_header(21) + struct.pack("!HH", 0, 5) + b"\x01"
        export = decode_ipfix(data)
        self.assertTrue(any("multiple of 4" in warning for warning in export.warnings))


class IpfixDecodingTests(unittest.TestCase):
    """Template and data set decoding."""

    def test_template_and_record(self) -> None:
        export = decode_ipfix(simple_message())
        self.assertEqual(export.template_count, 1)
        self.assertEqual(len(export.records), 1)
        self.assertEqual(export.warnings, [])
        record = export.records[0]
        self.assertEqual(record.src_ip, "192.0.2.10")
        self.assertEqual(record.dst_ip, "198.51.100.10")
        self.assertEqual(record.src_port, 49152)
        self.assertEqual(record.dst_port, 80)
        self.assertEqual(record.bytes, 1000)
        self.assertEqual(record.packets, 5)
        self.assertEqual(record.source_id, 99)

    def test_absolute_millisecond_timestamps(self) -> None:
        export = decode_ipfix(
            simple_message([support.ipfix_ipv4_record(start_ms=START_MS, end_ms=START_MS + 1500)])
        )
        record = export.records[0]
        self.assertEqual(record.start_ms, START_MS)
        self.assertEqual(record.end_ms, START_MS + 1500)
        self.assertEqual(record.duration_ms, 1500)

    def test_multiple_records(self) -> None:
        records = [
            support.ipfix_ipv4_record(octets=100),
            support.ipfix_ipv4_record(octets=200, dst_port=443),
            support.ipfix_ipv4_record(octets=300),
        ]
        export = decode_ipfix(simple_message(records))
        self.assertEqual(len(export.records), 3)
        self.assertEqual([record.bytes for record in export.records], [100, 200, 300])

    def test_ipv6_template(self) -> None:
        message = support.ipfix_message(
            [
                support.ipfix_template_set(
                    [support.ipfix_template_record(257, support.IPFIX_IPV6_FIELDS)]
                ),
                support.ipfix_set(257, support.ipfix_ipv6_record()),
            ]
        )
        export = decode_ipfix(message)
        self.assertEqual(len(export.records), 1)
        self.assertEqual(export.records[0].src_ip, "2001:db8::10")
        self.assertEqual(export.records[0].dst_ip, "2001:db8:100::10")

    def test_padding_is_ignored(self) -> None:
        export = decode_ipfix(simple_message())
        self.assertEqual(export.warnings, [])

    def test_enterprise_field_is_ignored_but_kept_out_of_the_record(self) -> None:
        message = support.ipfix_message(
            [
                support.ipfix_template_set(
                    [
                        support.ipfix_template_record(
                            256,
                            ((8, 4), (12, 4), (1000, 4)),
                            enterprise={1000: 4242},
                        )
                    ]
                ),
                support.ipfix_set(
                    256,
                    support.ip4("192.0.2.10")
                    + support.ip4("198.51.100.10")
                    + support.u32(7),
                ),
            ]
        )
        export = decode_ipfix(message)
        self.assertEqual(len(export.records), 1)
        self.assertEqual(export.records[0].src_ip, "192.0.2.10")
        self.assertEqual(export.records[0].bytes, 0)

    def test_template_redefinition(self) -> None:
        first = support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)
        second = support.ipfix_template_record(256, ((1, 4), (2, 4)))
        message = support.ipfix_message(
            [
                support.ipfix_template_set([first]),
                support.ipfix_set(256, support.ipfix_ipv4_record(octets=1000)),
                support.ipfix_template_set([second]),
                support.ipfix_set(256, support.u32(6000) + support.u32(60)),
            ]
        )
        export = decode_ipfix(message)
        self.assertEqual(len(export.records), 2)
        self.assertEqual(export.records[0].bytes, 1000)
        self.assertEqual(export.records[1].bytes, 6000)
        self.assertEqual(export.records[1].packets, 60)

    def test_template_withdrawal(self) -> None:
        withdrawal = support.ipfix_template_set([struct.pack("!HH", 256, 0)])
        message = support.ipfix_message(
            [
                support.ipfix_template_set(
                    [support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)]
                ),
                withdrawal,
                support.ipfix_set(256, support.ipfix_ipv4_record()),
            ]
        )
        export = decode_ipfix(message)
        self.assertEqual(export.records, [])
        self.assertTrue(any("withdrawn" in warning for warning in export.warnings))
        self.assertTrue(any("not received yet" in warning for warning in export.warnings))


class IpfixWarningTests(unittest.TestCase):
    """Recoverable problems reported as warnings."""

    def test_data_before_template_is_skipped(self) -> None:
        message = support.ipfix_message(
            [
                support.ipfix_set(256, support.ipfix_ipv4_record()),
                support.ipfix_template_set(
                    [support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)]
                ),
            ]
        )
        export = decode_ipfix(message)
        self.assertEqual(export.records, [])
        self.assertEqual(export.template_count, 1)
        self.assertTrue(any("not received yet" in warning for warning in export.warnings))

    def test_truncated_set_stops_decoding(self) -> None:
        body = support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)
        good = support.ipfix_set(2, body)
        bad = struct.pack("!HH", 256, 200) + b"\x00" * 20
        data = support.ipfix_header(16 + len(good) + len(bad)) + good + bad
        export = decode_ipfix(data)
        self.assertTrue(export.truncated)
        self.assertTrue(any("truncated set 256" in warning for warning in export.warnings))

    def test_invalid_set_length_stops_decoding(self) -> None:
        data = support.ipfix_header(16 + 8) + struct.pack("!HH", 2, 2) + b"\x00" * 4
        export = decode_ipfix(data)
        self.assertTrue(export.truncated)
        self.assertTrue(any("invalid set length" in warning for warning in export.warnings))

    def test_reserved_set_id_warns(self) -> None:
        message = support.ipfix_message(
            [support.ipfix_template_set(
                [support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)]
            ),
             support.ipfix_set(0, b"\x00\x00\x00\x00"),
             support.ipfix_set(256, support.ipfix_ipv4_record())]
        )
        export = decode_ipfix(message)
        self.assertEqual(len(export.records), 1)
        self.assertTrue(any("reserved set id 0" in warning for warning in export.warnings))

    def test_unknown_set_id_warns(self) -> None:
        message = support.ipfix_message([support.ipfix_set(5, b"\x00\x00\x00\x00")])
        export = decode_ipfix(message)
        self.assertTrue(any("unknown set id 5" in warning for warning in export.warnings))

    def test_non_zero_trailing_bytes_warn(self) -> None:
        message = support.ipfix_message(
            [
                support.ipfix_template_set(
                    [support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)]
                ),
                support.ipfix_set(256, support.ipfix_ipv4_record() + b"\xde"),
            ]
        )
        export = decode_ipfix(message)
        self.assertEqual(len(export.records), 1)
        self.assertTrue(any("trailing non-zero" in warning for warning in export.warnings))

    def test_template_with_bad_scope_count_warns(self) -> None:
        record = struct.pack("!HHH", 300, 2, 3) + struct.pack("!HH", 34, 4) + struct.pack("!HH", 35, 1)
        message = support.ipfix_message([support.ipfix_options_template_set([record])])
        export = decode_ipfix(message)
        self.assertTrue(any("scope fields" in warning for warning in export.warnings))


class IpfixOptionsTests(unittest.TestCase):
    """Options templates and sampling."""

    def test_options_sampling_scales_data_records(self) -> None:
        options_record = (
            support.u32(99) + support.u32(10) + b"\x00"
        )
        message = support.ipfix_message(
            [
                support.ipfix_template_set(
                    [support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)]
                ),
                support.ipfix_options_template_set(
                    [
                        support.ipfix_options_template_record(
                            300, ((149, 4),), ((34, 4), (35, 1))
                        )
                    ]
                ),
                support.ipfix_set(300, options_record),
                support.ipfix_set(256, support.ipfix_ipv4_record(octets=1000, packets=5)),
            ]
        )
        export = decode_ipfix(message)
        self.assertEqual(len(export.records), 1)
        record = export.records[0]
        self.assertTrue(record.sampled)
        self.assertEqual(record.sample_interval, 10)
        self.assertEqual(record.bytes, 10_000)
        self.assertEqual(record.raw_packets, 5)

    def test_options_interval_one_does_not_scale(self) -> None:
        options_record = support.u32(99) + support.u32(1) + b"\x00"
        message = support.ipfix_message(
            [
                support.ipfix_template_set(
                    [support.ipfix_template_record(256, support.IPFIX_IPV4_FIELDS)]
                ),
                support.ipfix_options_template_set(
                    [
                        support.ipfix_options_template_record(
                            300, ((149, 4),), ((34, 4), (35, 1))
                        )
                    ]
                ),
                support.ipfix_set(300, options_record),
                support.ipfix_set(256, support.ipfix_ipv4_record()),
            ]
        )
        export = decode_ipfix(message)
        self.assertFalse(export.records[0].sampled)

    def test_zero_length_options_record_warns(self) -> None:
        message = support.ipfix_message(
            [
                support.ipfix_options_template_set(
                    [support.ipfix_options_template_record(300, (), ())]
                ),
                support.ipfix_set(300, b""),
            ]
        )
        export = decode_ipfix(message)
        self.assertEqual(export.records, [])
        self.assertTrue(export.warnings)


if __name__ == "__main__":
    unittest.main()
