"""Tests for traffic aggregation: talkers, conversations, protocols, timeline."""

from __future__ import annotations

import unittest

from flowanalyzer.aggregate import (
    FlowAnalysis,
    analyze,
    endpoint_of,
    service_name,
)
from flowanalyzer.model import FlowExport, FlowRecord

BASE_MS = 1_700_000_000_000


def record(
    *,
    src: str = "192.0.2.10",
    dst: str = "198.51.100.10",
    src_port: int = 49876,
    dst_port: int = 80,
    protocol: int = 6,
    bytes: int = 1000,
    packets: int = 10,
    start_ms: int = BASE_MS,
    end_ms: int = BASE_MS + 1000,
    exporter: str = "r1",
) -> FlowRecord:
    """Build a flow record for aggregation tests."""
    return FlowRecord(
        exporter=exporter,
        version=9,
        source_id=7,
        src_ip=src,
        dst_ip=dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        bytes=bytes,
        packets=packets,
        start_ms=start_ms,
        end_ms=end_ms,
    )


class EndpointTests(unittest.TestCase):
    """Endpoint and service helpers."""

    def test_endpoint_of(self) -> None:
        flow = record()
        self.assertEqual(endpoint_of(flow, source=True).label, "192.0.2.10:49876")
        self.assertEqual(endpoint_of(flow, source=False).label, "198.51.100.10:80")

    def test_endpoint_ordering(self) -> None:
        first = endpoint_of(record(src="192.0.2.10"), source=True)
        second = endpoint_of(record(dst="198.51.100.10"), source=False)
        self.assertLess(first, second)

    def test_service_name(self) -> None:
        self.assertEqual(service_name(6, 49152, 80), "http")
        self.assertEqual(service_name(6, 443, 49152), "https")
        self.assertEqual(service_name(17, 5353, 53), "dns")
        self.assertEqual(service_name(6, 49152, 22), "ssh")
        self.assertEqual(service_name(6, 40000, 41000), "unknown")


class TalkerTests(unittest.TestCase):
    """Top source and destination aggregation."""

    def test_top_sources_aggregate_bytes_and_packets(self) -> None:
        analysis = FlowAnalysis(
            [
                record(src="192.0.2.10", bytes=1000, packets=10),
                record(src="192.0.2.10", bytes=2000, packets=20),
                record(src="198.51.100.5", bytes=500, packets=5),
            ]
        )
        sources = analysis.top_sources()
        self.assertEqual(len(sources), 2)
        self.assertEqual(sources[0].address, "192.0.2.10")
        self.assertEqual(sources[0].bytes, 3000)
        self.assertEqual(sources[0].packets, 30)
        self.assertEqual(sources[0].records, 2)
        self.assertEqual(sources[1].bytes, 500)

    def test_top_destinations(self) -> None:
        analysis = FlowAnalysis(
            [
                record(dst="198.51.100.10", bytes=1000),
                record(dst="203.0.113.5", bytes=9000),
            ]
        )
        destinations = analysis.top_destinations()
        self.assertEqual(destinations[0].address, "203.0.113.5")
        self.assertEqual(destinations[0].bytes, 9000)

    def test_ties_are_broken_by_address(self) -> None:
        analysis = FlowAnalysis(
            [
                record(src="198.51.100.20", bytes=100),
                record(src="192.0.2.10", bytes=100),
            ]
        )
        addresses = [talker.address for talker in analysis.top_sources()]
        self.assertEqual(addresses, ["192.0.2.10", "198.51.100.20"])

    def test_limits(self) -> None:
        analysis = FlowAnalysis([record(src=f"192.0.2.{index}", bytes=index) for index in range(1, 5)])
        self.assertEqual(len(analysis.top_sources(2)), 2)
        self.assertEqual(len(analysis.top_sources(0)), 4)


class ConversationTests(unittest.TestCase):
    """Bidirectional conversation merging."""

    def test_two_directions_merge(self) -> None:
        analysis = FlowAnalysis(
            [
                record(src="192.0.2.10", dst="198.51.100.10", src_port=49876, dst_port=80, bytes=1000),
                record(src="198.51.100.10", dst="192.0.2.10", src_port=80, dst_port=49876, bytes=400),
            ]
        )
        conversations = analysis.conversations()
        self.assertEqual(len(conversations), 1)
        conversation = conversations[0]
        self.assertEqual(conversation.records, 2)
        self.assertEqual(conversation.bytes_total, 1400)
        self.assertEqual(conversation.bytes_a_to_b, 1000)
        self.assertEqual(conversation.bytes_b_to_a, 400)

    def test_orientation_independence(self) -> None:
        forward = record(bytes=1000, start_ms=BASE_MS, end_ms=BASE_MS + 500)
        reverse = record(
            src="198.51.100.10",
            dst="192.0.2.10",
            src_port=80,
            dst_port=49876,
            bytes=400,
            start_ms=BASE_MS + 500,
            end_ms=BASE_MS + 800,
        )
        first = FlowAnalysis([forward, reverse]).conversations()[0]
        second = FlowAnalysis([reverse, forward]).conversations()[0]
        self.assertEqual(first.endpoint_a, second.endpoint_a)
        self.assertEqual(first.bytes_a_to_b, second.bytes_a_to_b)
        self.assertEqual(first.bytes_b_to_a, second.bytes_b_to_a)
        self.assertEqual(first.start_ms, BASE_MS)

    def test_different_protocols_are_different_conversations(self) -> None:
        analysis = FlowAnalysis(
            [
                record(protocol=6, dst_port=80),
                record(protocol=17, dst_port=53, src_port=53),
            ]
        )
        self.assertEqual(len(analysis.conversations()), 2)

    def test_service_is_derived_from_ports(self) -> None:
        analysis = FlowAnalysis(
            [
                record(src_port=49876, dst_port=80),
                record(src_port=53, dst_port=53, protocol=17),
                record(src_port=51422, dst_port=443),
            ]
        )
        services = {conversation.service for conversation in analysis.conversations()}
        self.assertEqual(services, {"http", "dns", "https"})

    def test_ipv6_endpoints_are_bracketed(self) -> None:
        analysis = FlowAnalysis(
            [
                record(
                    src="2001:db8::10",
                    dst="2001:db8::53",
                    src_port=5353,
                    dst_port=53,
                    protocol=17,
                )
            ]
        )
        conversation = analysis.conversations()[0]
        labels = {conversation.endpoint_a.label, conversation.endpoint_b.label}
        self.assertEqual(labels, {"[2001:db8::10]:5353", "[2001:db8::53]:53"})

    def test_conversation_ordering_by_bytes(self) -> None:
        analysis = FlowAnalysis(
            [
                record(dst_port=80, bytes=100),
                record(dst_port=443, bytes=900),
            ]
        )
        conversations = analysis.conversations()
        self.assertEqual(conversations[0].service, "https")
        self.assertGreater(conversations[0].bytes_total, conversations[1].bytes_total)

    def test_duration_and_timestamps(self) -> None:
        analysis = FlowAnalysis(
            [
                record(start_ms=BASE_MS, end_ms=BASE_MS + 200),
                record(
                    src="198.51.100.10",
                    dst="192.0.2.10",
                    src_port=80,
                    dst_port=49876,
                    start_ms=BASE_MS + 300,
                    end_ms=BASE_MS + 900,
                ),
            ]
        )
        conversation = analysis.conversations()[0]
        self.assertEqual(conversation.start_ms, BASE_MS)
        self.assertEqual(conversation.end_ms, BASE_MS + 900)
        self.assertEqual(conversation.duration_ms, 900)


class ProtocolAndTimelineTests(unittest.TestCase):
    """Protocol distribution and time bucketing."""

    def test_protocol_distribution(self) -> None:
        analysis = FlowAnalysis(
            [
                record(protocol=6, bytes=1000),
                record(protocol=6, bytes=500),
                record(protocol=17, bytes=2000),
                record(protocol=1, bytes=100),
            ]
        )
        stats = analysis.protocol_distribution()
        self.assertEqual([stat.name for stat in stats], ["UDP", "TCP", "ICMP"])
        self.assertEqual(stats[0].bytes, 2000)
        self.assertEqual(stats[1].bytes, 1500)
        self.assertEqual(stats[1].records, 2)
        self.assertEqual(stats[2].bytes, 100)

    def test_timeline_covers_min_start_to_max_end(self) -> None:
        analysis = FlowAnalysis(
            [
                record(start_ms=BASE_MS, end_ms=BASE_MS + 10_000),
                record(start_ms=BASE_MS + 90_000, end_ms=BASE_MS + 100_000),
            ],
            bucket_seconds=60,
        )
        buckets = analysis.timeline()
        self.assertEqual(len(buckets), 2)
        self.assertEqual(buckets[0].start_ms, BASE_MS)
        self.assertEqual(buckets[0].records, 1)
        self.assertEqual(buckets[1].records, 1)

    def test_custom_bucket_size(self) -> None:
        analysis = FlowAnalysis(
            [
                record(start_ms=BASE_MS, end_ms=BASE_MS + 10_000),
                record(start_ms=BASE_MS + 30_000, end_ms=BASE_MS + 40_000),
            ],
            bucket_seconds=15,
        )
        buckets = analysis.timeline()
        self.assertEqual(len(buckets), 3)
        self.assertEqual(buckets[0].bytes, 1000)
        self.assertEqual(buckets[2].bytes, 1000)

    def test_bucket_size_validation(self) -> None:
        with self.assertRaises(ValueError):
            FlowAnalysis([], bucket_seconds=0)

    def test_records_are_counted_in_one_bucket(self) -> None:
        analysis = FlowAnalysis(
            [record(start_ms=BASE_MS + 500, end_ms=BASE_MS + 600)]
        )
        buckets = analysis.timeline()
        self.assertEqual(len(buckets), 1)
        self.assertEqual(buckets[0].records, 1)


class SummaryTests(unittest.TestCase):
    """Summary arithmetic and serialisation."""

    def test_summary_totals_and_rates(self) -> None:
        analysis = FlowAnalysis(
            [
                record(bytes=1000, packets=10, start_ms=BASE_MS, end_ms=BASE_MS + 1000),
                record(bytes=3000, packets=30, start_ms=BASE_MS + 1000, end_ms=BASE_MS + 2000),
            ]
        )
        summary = analysis.summary
        self.assertEqual(summary.records, 2)
        self.assertEqual(summary.bytes, 4000)
        self.assertEqual(summary.packets, 40)
        self.assertEqual(summary.duration_ms, 2000)
        self.assertAlmostEqual(summary.avg_bytes_per_second, 2000.0)
        self.assertAlmostEqual(summary.avg_packets_per_second, 20.0)
        self.assertEqual(summary.exporters, ["r1"])

    def test_single_record_has_zero_rate(self) -> None:
        summary = FlowAnalysis([record(end_ms=record().start_ms)]).summary
        self.assertEqual(summary.duration_ms, 0)
        self.assertEqual(summary.avg_bytes_per_second, 0.0)
        self.assertEqual(summary.avg_packets_per_second, 0.0)

    def test_empty_analysis(self) -> None:
        analysis = FlowAnalysis([])
        summary = analysis.summary
        self.assertEqual(summary.records, 0)
        self.assertIsNone(summary.start_ms)
        self.assertEqual(analysis.top_sources(), [])
        self.assertEqual(analysis.top_destinations(), [])
        self.assertEqual(analysis.conversations(), [])
        self.assertEqual(analysis.protocol_distribution(), [])
        self.assertEqual(analysis.timeline(), [])

    def test_exporters_are_sorted_and_unique(self) -> None:
        analysis = FlowAnalysis(
            [record(exporter="r2"), record(exporter="r1"), record(exporter="r2")]
        )
        self.assertEqual(analysis.summary.exporters, ["r1", "r2"])

    def test_analyze_accepts_export_object(self) -> None:
        export = FlowExport(
            format="v9",
            version=9,
            exporter="r1",
            records=[record()],
        )
        analysis = analyze(export)
        self.assertEqual(analysis.summary.records, 1)

    def test_analyze_accepts_record_list(self) -> None:
        analysis = analyze([record(), record()])
        self.assertEqual(analysis.summary.records, 2)

    def test_analysis_to_dict_shape(self) -> None:
        payload = FlowAnalysis([record()]).to_dict(top=5)
        self.assertEqual(
            sorted(payload),
            [
                "conversations",
                "protocols",
                "summary",
                "timeline",
                "top_destinations",
                "top_sources",
            ],
        )
        self.assertEqual(payload["summary"]["records"], 1)
        self.assertEqual(payload["top_sources"][0]["address"], "192.0.2.10")

    def test_to_dict_top_limit(self) -> None:
        analysis = FlowAnalysis([record(dst=f"198.51.100.{index}") for index in range(1, 6)])
        payload = analysis.to_dict(top=2)
        self.assertEqual(len(payload["conversations"]), 2)
        self.assertEqual(len(payload["top_destinations"]), 2)

    def test_bytes_are_conserved_across_views(self) -> None:
        analysis = FlowAnalysis(
            [
                record(bytes=1000),
                record(src="203.0.113.5", bytes=2000),
                record(dst="2001:db8::10", bytes=4000),
            ]
        )
        total = analysis.summary.bytes
        self.assertEqual(sum(talker.bytes for talker in analysis.top_sources(0)), total)
        self.assertEqual(sum(stat.bytes for stat in analysis.protocol_distribution()), total)


if __name__ == "__main__":
    unittest.main()
