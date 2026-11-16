"""Tests for the deterministic synthetic export generator."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from flowanalyzer.generate import (
    BASE_TIME_MS,
    SCENARIOS,
    build_flows,
    encode_v5,
    generate_bytes,
    write_export,
)
from flowanalyzer.netflow.reader import decode_export

ALLOWED_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "2001:db8")


def decoded_records(export_format: str, **options: object) -> list[dict[str, object]]:
    """Generate an export and return the decoded records as dictionaries."""
    export = decode_export(generate_bytes(export_format, **options))
    return [record.to_dict() for record in export.records]


class BuildFlowsTests(unittest.TestCase):
    """Synthetic flow construction."""

    def test_deterministic_for_the_same_seed(self) -> None:
        first = build_flows(12, seed=7)
        second = build_flows(12, seed=7)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 12)

    def test_different_seeds_produce_different_traffic(self) -> None:
        first = build_flows(12, seed=7)
        second = build_flows(12, seed=8)
        self.assertNotEqual(
            [(flow.bytes, flow.packets) for flow in first],
            [(flow.bytes, flow.packets) for flow in second],
        )

    def test_flow_count(self) -> None:
        self.assertEqual(len(build_flows(5)), 5)
        self.assertEqual(len(build_flows(1)), 1)

    def test_invalid_count_raises(self) -> None:
        with self.assertRaises(ValueError):
            build_flows(0)

    def test_reverse_direction_flows_are_generated(self) -> None:
        flows = build_flows(8, seed=7)
        reverse = flows[3]
        previous = flows[2]
        self.assertEqual(reverse.src, previous.dst)
        self.assertEqual(reverse.dst, previous.src)
        self.assertEqual(reverse.src_port, previous.dst_port)
        self.assertEqual(reverse.dst_port, previous.src_port)

    def test_ipv6_flows_can_be_excluded(self) -> None:
        flows = build_flows(12, seed=7, allow_ipv6=False)
        self.assertTrue(all(not flow.is_ipv6 for flow in flows))
        with_ipv6 = build_flows(12, seed=7, allow_ipv6=True)
        self.assertTrue(any(flow.is_ipv6 for flow in with_ipv6))

    def test_all_addresses_are_documentation_ranges(self) -> None:
        for flow in build_flows(12, seed=7):
            for address in (flow.src, flow.dst, flow.next_hop):
                self.assertTrue(
                    address.startswith(ALLOWED_PREFIXES),
                    f"unexpected address {address}",
                )

    def test_scenario_identifiers_are_unique(self) -> None:
        names = [scenario.name for scenario in SCENARIOS]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 8)


class EncodeDecodeRoundTripTests(unittest.TestCase):
    """Generated exports decode back to the flows that were encoded."""

    def test_v5_round_trip(self) -> None:
        flows = build_flows(12, seed=7, allow_ipv6=False)
        export = decode_export(generate_bytes("v5", flows=12, seed=7))
        self.assertEqual(export.format, "v5")
        self.assertEqual(export.warnings, [])
        self.assertEqual(len(export.records), 12)
        for expected, record in zip(flows, export.records):
            self.assertEqual(record.src_ip, expected.src)
            self.assertEqual(record.dst_ip, expected.dst)
            self.assertEqual(record.src_port, expected.src_port)
            self.assertEqual(record.dst_port, expected.dst_port)
            self.assertEqual(record.bytes, expected.bytes)
            self.assertEqual(record.packets, expected.packets)
            self.assertEqual(record.start_ms, expected.start_ms)
            self.assertEqual(record.end_ms, expected.end_ms)

    def test_v9_round_trip(self) -> None:
        flows = build_flows(12, seed=7)
        export = decode_export(generate_bytes("v9", flows=12, seed=7))
        self.assertEqual(export.format, "v9")
        self.assertEqual(export.warnings, [])
        self.assertEqual(export.template_count, 3)
        self.assertEqual(len(export.records), 12)
        self.assertEqual(export.records[0].start_ms, flows[0].start_ms)
        self.assertEqual(export.records[0].input_if, flows[0].input_if)
        self.assertEqual(export.records[0].src_as, 64500)

    def test_ipfix_round_trip(self) -> None:
        flows = build_flows(12, seed=7)
        export = decode_export(generate_bytes("ipfix", flows=12, seed=7))
        self.assertEqual(export.format, "ipfix")
        self.assertEqual(export.warnings, [])
        self.assertEqual(export.template_count, 3)
        self.assertEqual(len(export.records), 12)
        self.assertEqual(export.records[0].start_ms, flows[0].start_ms)
        self.assertEqual(export.records[0].next_hop, None)

    def test_v9_and_ipfix_carry_the_same_flows(self) -> None:
        v9 = decoded_records("v9", flows=12, seed=7)
        ipfix = decoded_records("ipfix", flows=12, seed=7)
        for first, second in zip(v9, ipfix):
            self.assertEqual(first["src_ip"], second["src_ip"])
            self.assertEqual(first["dst_ip"], second["dst_ip"])
            self.assertEqual(first["bytes"], second["bytes"])
            self.assertEqual(first["start_ms"], second["start_ms"])
            self.assertEqual(first["end_ms"], second["end_ms"])


class SamplingTests(unittest.TestCase):
    """Sampling intervals encoded in generated exports."""

    def test_v5_sampling_scales_counters(self) -> None:
        export = decode_export(generate_bytes("v5", flows=12, seed=7, sampling_interval=10))
        record = export.records[0]
        expected = build_flows(12, seed=7, allow_ipv6=False)[0]
        self.assertTrue(record.sampled)
        self.assertEqual(record.sample_interval, 10)
        self.assertEqual(record.bytes, expected.bytes * 10)
        self.assertEqual(record.raw_bytes, expected.bytes)

    def test_v9_sampling_scales_counters(self) -> None:
        export = decode_export(generate_bytes("v9", flows=12, seed=7, sampling_interval=5))
        record = export.records[0]
        expected = build_flows(12, seed=7)[0]
        self.assertTrue(record.sampled)
        self.assertEqual(record.sample_interval, 5)
        self.assertEqual(record.bytes, expected.bytes * 5)
        self.assertEqual(record.raw_packets, expected.packets)

    def test_ipfix_sampling_scales_counters(self) -> None:
        export = decode_export(generate_bytes("ipfix", flows=6, seed=7, sampling_interval=2))
        record = export.records[0]
        expected = build_flows(6, seed=7)[0]
        self.assertTrue(record.sampled)
        self.assertEqual(record.bytes, expected.bytes * 2)


class EncodingGuardTests(unittest.TestCase):
    """Invalid generator inputs are rejected with clear errors."""

    def test_v5_cannot_encode_ipv6(self) -> None:
        with self.assertRaises(ValueError):
            encode_v5(build_flows(12, seed=7, allow_ipv6=True))

    def test_v5_cannot_exceed_record_limit(self) -> None:
        with self.assertRaises(ValueError):
            encode_v5(build_flows(31, seed=7, allow_ipv6=False))

    def test_unsupported_format_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_bytes("netflow-v1")

    def test_invalid_sampling_interval_raises(self) -> None:
        with self.assertRaises(ValueError):
            generate_bytes("v9", sampling_interval=0)


class WriterTests(unittest.TestCase):
    """Writing generated exports to disk."""

    def test_write_export(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows-v9.bin"
            size = write_export(path, "v9", flows=12, seed=7)
            self.assertTrue(path.exists())
            self.assertEqual(path.stat().st_size, size)
            self.assertEqual(size, len(generate_bytes("v9", flows=12, seed=7)))
            export = decode_export(path.read_bytes())
        self.assertEqual(len(export.records), 12)

    def test_v5_export_size_matches_header_and_records(self) -> None:
        data = generate_bytes("v5", flows=12, seed=7)
        self.assertEqual(len(data), 24 + 12 * 48)

    def test_generated_sizes_are_small(self) -> None:
        for export_format in ("v5", "v9", "ipfix"):
            data = generate_bytes(export_format, flows=12, seed=7)
            self.assertLess(len(data), 10_000)
            self.assertGreater(len(data), 100)

    def test_base_time_is_stable(self) -> None:
        self.assertEqual(BASE_TIME_MS, 1768467600000)
        self.assertTrue(build_flows(1, seed=7)[0].start_ms >= BASE_TIME_MS)


if __name__ == "__main__":
    unittest.main()
