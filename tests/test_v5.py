"""Tests for the NetFlow v5 decoder."""

from __future__ import annotations

import unittest

import support

from flowanalyzer.errors import FlowError
from flowanalyzer.netflow.v5 import MAX_RECORDS, decode_v5

EXPORT_MS = support.UNIX_SECONDS * 1000


class V5HeaderTests(unittest.TestCase):
    """Header parsing and count handling."""

    def test_minimal_export(self) -> None:
        export = decode_v5(support.v5_export([], count=0), exporter="r1.bin")
        self.assertEqual(export.format, "v5")
        self.assertEqual(export.version, 5)
        self.assertEqual(export.exporter, "r1.bin")
        self.assertEqual(export.records, [])
        self.assertEqual(export.warnings, [])
        self.assertFalse(export.truncated)

    def test_header_fields(self) -> None:
        export = decode_v5(
            support.v5_export(
                [support.v5_record()],
                unix_secs=1_700_000_000,
                unix_nsecs=500_000_000,
                sequence=1234,
                engine_type=1,
                engine_id=7,
            )
        )
        self.assertEqual(export.header["sequence"], 1234)
        self.assertEqual(export.header["engine_type"], 1)
        self.assertEqual(export.header["engine_id"], 7)
        self.assertEqual(export.header["export_time_ms"], 1_700_000_000_500)

    def test_count_zero_with_records_warns(self) -> None:
        export = decode_v5(support.v5_export([support.v5_record()], count=0))
        self.assertEqual(len(export.records), 1)
        self.assertTrue(any("record count is 0" in warning for warning in export.warnings))

    def test_count_larger_than_available_is_truncated(self) -> None:
        export = decode_v5(support.v5_export([support.v5_record()], count=3))
        self.assertEqual(len(export.records), 1)
        self.assertTrue(export.truncated)
        self.assertTrue(any("truncated NetFlow v5 export" in warning for warning in export.warnings))

    def test_count_smaller_than_available_warns(self) -> None:
        export = decode_v5(
            support.v5_export(
                [support.v5_record(), support.v5_record(dst_port=443)], count=1
            )
        )
        self.assertEqual(len(export.records), 1)
        self.assertTrue(any("trailing record" in warning for warning in export.warnings))

    def test_trailing_bytes_are_reported(self) -> None:
        data = support.v5_export([support.v5_record()]) + b"\x00\x00"
        export = decode_v5(data)
        self.assertEqual(len(export.records), 1)
        self.assertTrue(export.truncated)
        self.assertTrue(any("trailing byte" in warning for warning in export.warnings))

    def test_truncated_header_raises(self) -> None:
        with self.assertRaises(FlowError):
            decode_v5(b"\x00\x05\x00\x01")

    def test_wrong_version_raises(self) -> None:
        with self.assertRaises(FlowError):
            decode_v5(support.v9_export([]))

    def test_count_above_format_limit_warns(self) -> None:
        export = decode_v5(support.v5_export([support.v5_record()], count=MAX_RECORDS + 1))
        self.assertTrue(any("at most 30" in warning for warning in export.warnings))
        self.assertEqual(len(export.records), 1)


class V5RecordTests(unittest.TestCase):
    """Record decoding and timestamp conversion."""

    def test_record_fields(self) -> None:
        export = decode_v5(
            support.v5_export(
                [
                    support.v5_record(
                        src="192.0.2.10",
                        dst="198.51.100.10",
                        next_hop="192.0.2.1",
                        input_if=2,
                        output_if=10,
                        packets=5,
                        octets=1000,
                        src_port=49152,
                        dst_port=80,
                        tcp_flags=0x18,
                        protocol=6,
                        tos=16,
                        src_as=64500,
                        dst_as=64496,
                        src_mask=24,
                        dst_mask=24,
                    )
                ]
            )
        )
        record = export.records[0]
        self.assertEqual(record.src_ip, "192.0.2.10")
        self.assertEqual(record.dst_ip, "198.51.100.10")
        self.assertEqual(record.next_hop, "192.0.2.1")
        self.assertEqual(record.src_port, 49152)
        self.assertEqual(record.dst_port, 80)
        self.assertEqual(record.protocol, 6)
        self.assertEqual(record.protocol_name, "TCP")
        self.assertEqual(record.tcp_flags, 0x18)
        self.assertEqual(record.bytes, 1000)
        self.assertEqual(record.packets, 5)
        self.assertEqual(record.input_if, 2)
        self.assertEqual(record.output_if, 10)
        self.assertEqual(record.src_as, 64500)
        self.assertEqual(record.dst_as, 64496)
        self.assertEqual(record.tos, 16)
        self.assertEqual(record.src_mask, 24)

    def test_uptime_timestamps_are_converted(self) -> None:
        export = decode_v5(
            support.v5_export(
                [support.v5_record(first_switched=3_000_000, last_switched=3_000_500)]
            )
        )
        record = export.records[0]
        self.assertEqual(record.start_ms, EXPORT_MS - 600_000)
        self.assertEqual(record.end_ms, EXPORT_MS - 600_000 + 500)
        self.assertEqual(record.duration_ms, 500)

    def test_uptime_wraparound(self) -> None:
        export = decode_v5(
            support.v5_export(
                [support.v5_record(first_switched=0xFFFFFFFF - 10, last_switched=20)],
                sys_uptime=10,
                unix_secs=support.UNIX_SECONDS,
            )
        )
        record = export.records[0]
        self.assertGreater(record.end_ms, record.start_ms)

    def test_icmp_flow_has_no_ports(self) -> None:
        export = decode_v5(
            support.v5_export(
                [support.v5_record(protocol=1, src_port=0, dst_port=0)]
            )
        )
        record = export.records[0]
        self.assertEqual(record.protocol_name, "ICMP")
        self.assertNotIn(":", record.endpoint_source)

    def test_record_to_dict(self) -> None:
        export = decode_v5(support.v5_export([support.v5_record()]))
        payload = export.records[0].to_dict()
        self.assertEqual(payload["src_ip"], "192.0.2.10")
        self.assertEqual(payload["duration_ms"], 500)
        self.assertFalse(payload["sampled"])
        self.assertNotIn("raw_bytes", payload)


class V5SamplingTests(unittest.TestCase):
    """Header sampling interval handling."""

    def test_interval_scales_counters_and_keeps_raw(self) -> None:
        export = decode_v5(
            support.v5_export([support.v5_record(octets=1000, packets=5)], sampling=10)
        )
        record = export.records[0]
        self.assertTrue(record.sampled)
        self.assertEqual(record.sample_interval, 10)
        self.assertEqual(record.bytes, 10_000)
        self.assertEqual(record.packets, 50)
        self.assertEqual(record.raw_bytes, 1000)
        self.assertEqual(record.raw_packets, 5)
        payload = record.to_dict()
        self.assertEqual(payload["raw_bytes"], 1000)

    def test_interval_one_means_not_sampled(self) -> None:
        export = decode_v5(support.v5_export([support.v5_record()], sampling=1))
        record = export.records[0]
        self.assertFalse(record.sampled)
        self.assertEqual(record.bytes, 1000)

    def test_time_based_sampling_does_not_scale(self) -> None:
        export = decode_v5(
            support.v5_export([support.v5_record()], sampling=(2 << 14) | 10)
        )
        record = export.records[0]
        self.assertEqual(export.header["sampling_mode"], 2)
        self.assertEqual(record.sample_interval, 1)
        self.assertFalse(record.sampled)
        self.assertFalse(record.sampled)
        self.assertTrue(any("time-based sampling" in warning for warning in export.warnings))


if __name__ == "__main__":
    unittest.main()
