"""Tests for the flow record model and the sampling helpers."""

from __future__ import annotations

import unittest

from flowanalyzer.model import (
    FlowRecord,
    format_endpoint,
    protocol_name,
    uptime_to_epoch_ms,
    build_record,
)
from flowanalyzer.sampling import (
    SamplingConfig,
    interval_from_fields,
    normalize_interval,
    sampling_from_v5_header,
)

EXPORT_MS = 1_700_000_000_000
HEADER = {"export_time_ms": EXPORT_MS, "sys_uptime_ms": 3_600_000}


def make_record(**overrides: object) -> FlowRecord:
    """Build a minimal record with sensible defaults."""
    values: dict[str, object] = {
        "exporter": "r1",
        "version": 9,
        "source_id": 7,
        "src_ip": "192.0.2.10",
        "dst_ip": "198.51.100.10",
        "src_port": 49876,
        "dst_port": 80,
        "protocol": 6,
        "bytes": 1000,
        "packets": 10,
        "start_ms": 1_700_000_000_000,
        "end_ms": 1_700_000_001_500,
    }
    values.update(overrides)
    return FlowRecord(**values)


def build(fields: dict, header: dict | None = None, **overrides: object):
    """Call build_record with defaults suitable for the tests."""
    options: dict[str, object] = {
        "exporter": "r1",
        "version": 9,
        "source_id": 7,
        "fields": fields,
        "header": dict(HEADER if header is None else header),
    }
    options.update(overrides)
    return build_record(**options)


class FlowRecordTests(unittest.TestCase):
    """FlowRecord helpers and serialisation."""

    def test_defaults(self) -> None:
        record = FlowRecord(exporter="", version=5, source_id=0, src_ip="", dst_ip="")
        self.assertEqual(record.bytes, 0)
        self.assertEqual(record.sample_interval, 1)
        self.assertFalse(record.sampled)
        self.assertIsNone(record.raw_bytes)

    def test_duration_is_clamped(self) -> None:
        record = make_record(start_ms=2000, end_ms=1000)
        self.assertEqual(record.duration_ms, 0)
        self.assertEqual(make_record().duration_ms, 1500)

    def test_protocol_names(self) -> None:
        self.assertEqual(protocol_name(6), "TCP")
        self.assertEqual(protocol_name(17), "UDP")
        self.assertEqual(protocol_name(1), "ICMP")
        self.assertEqual(protocol_name(250), "protocol 250")
        self.assertEqual(make_record().protocol_name, "TCP")

    def test_endpoint_formatting(self) -> None:
        self.assertEqual(format_endpoint("192.0.2.10", 80), "192.0.2.10:80")
        self.assertEqual(format_endpoint("2001:db8::10", 443), "[2001:db8::10]:443")
        self.assertEqual(format_endpoint("192.0.2.10", 0), "192.0.2.10")
        self.assertEqual(format_endpoint("", 0), "-")

    def test_to_dict_keeps_raw_values_hidden_when_not_sampled(self) -> None:
        payload = make_record().to_dict()
        self.assertEqual(payload["protocol_name"], "TCP")
        self.assertEqual(payload["duration_ms"], 1500)
        self.assertNotIn("raw_bytes", payload)
        self.assertFalse(payload["sampled"])

    def test_to_dict_includes_raw_values_when_sampled(self) -> None:
        record = make_record(sampled=True, sample_interval=10, raw_bytes=100, raw_packets=1)
        payload = record.to_dict()
        self.assertEqual(payload["raw_bytes"], 100)
        self.assertEqual(payload["raw_packets"], 1)
        self.assertTrue(payload["sampled"])

    def test_uptime_conversion_with_wraparound(self) -> None:
        self.assertEqual(uptime_to_epoch_ms(EXPORT_MS, 3_600_000, 3_000_000), EXPORT_MS - 600_000)
        self.assertEqual(uptime_to_epoch_ms(EXPORT_MS, 10, 20), EXPORT_MS + 10)


class BuildRecordTests(unittest.TestCase):
    """Normalisation of decoded fields into a FlowRecord."""

    def test_basic_fields(self) -> None:
        record = build(
            {
                "IPV4_SRC_ADDR": "192.0.2.10",
                "IPV4_DST_ADDR": "198.51.100.10",
                "SRC_PORT": 49876,
                "DST_PORT": 80,
                "PROTOCOL": 6,
                "TCP_FLAGS": 0x18,
                "IN_BYTES": 900,
                "IN_PKTS": 9,
                "INPUT_SNMP": 2,
                "OUTPUT_SNMP": 10,
                "SRC_AS": 64500,
                "DST_AS": 64496,
                "SRC_TOS": 16,
                "SRC_MASK": 24,
                "DST_MASK": 24,
                "IPV4_NEXT_HOP": "192.0.2.1",
            }
        )
        self.assertEqual(record.src_ip, "192.0.2.10")
        self.assertEqual(record.dst_ip, "198.51.100.10")
        self.assertEqual(record.src_port, 49876)
        self.assertEqual(record.tcp_flags, 0x18)
        self.assertEqual(record.bytes, 900)
        self.assertEqual(record.packets, 9)
        self.assertEqual(record.input_if, 2)
        self.assertEqual(record.src_as, 64500)
        self.assertEqual(record.tos, 16)
        self.assertEqual(record.next_hop, "192.0.2.1")

    def test_ipv6_address_fields(self) -> None:
        record = build({"IPV6_SRC_ADDR": "2001:db8::10", "IPV6_DST_ADDR": "2001:db8::53"})
        self.assertEqual(record.src_ip, "2001:db8::10")
        self.assertEqual(record.dst_ip, "2001:db8::53")

    def test_octet_delta_aliases_are_used(self) -> None:
        record = build({"OCTET_DELTA": 1234, "PACKET_DELTA": 12})
        self.assertEqual(record.bytes, 1234)
        self.assertEqual(record.packets, 12)

    def test_absolute_millisecond_timestamps(self) -> None:
        record = build({"FLOW_START_MS": 1_700_000_000_123, "FLOW_END_MS": 1_700_000_001_000})
        self.assertEqual(record.start_ms, 1_700_000_000_123)
        self.assertEqual(record.end_ms, 1_700_000_001_000)

    def test_second_timestamps_are_converted(self) -> None:
        record = build({"FLOW_START_SECONDS": 1_700_000_000, "FLOW_END_SECONDS": 1_700_000_001})
        self.assertEqual(record.start_ms, 1_700_000_000_000)
        self.assertEqual(record.end_ms, 1_700_000_001_000)

    def test_ntp_timestamps_are_already_milliseconds(self) -> None:
        record = build({"FLOW_START_US": 1_700_000_000_123, "FLOW_END_US": 1_700_000_000_999})
        self.assertEqual(record.start_ms, 1_700_000_000_123)
        self.assertEqual(record.end_ms, 1_700_000_000_999)

    def test_uptime_switched_fields_use_the_export_time(self) -> None:
        record = build({"FIRST_SWITCHED": 3_000_000, "LAST_SWITCHED": 3_000_500})
        self.assertEqual(record.start_ms, EXPORT_MS - 600_000)
        self.assertEqual(record.end_ms, EXPORT_MS - 599_500)

    def test_system_init_time_converts_uptime(self) -> None:
        header = {"export_time_ms": EXPORT_MS, "sys_uptime_ms": 3_600_000, "system_init_ms": 1_700_000_000_000}
        record = build({"FIRST_SWITCHED": 2_000, "LAST_SWITCHED": 3_000}, header)
        self.assertEqual(record.start_ms, 1_700_000_002_000)
        self.assertEqual(record.end_ms, 1_700_000_003_000)

    def test_missing_addresses_become_empty_strings(self) -> None:
        record = build({"IN_BYTES": 10})
        self.assertEqual(record.src_ip, "")
        self.assertEqual(record.dst_ip, "")
        self.assertEqual(record.endpoint_source, "-")

    def test_end_before_start_is_clamped(self) -> None:
        record = build({"FLOW_START_MS": 2000, "FLOW_END_MS": 1000})
        self.assertEqual(record.duration_ms, 0)

    def test_default_sampling_scales_counters(self) -> None:
        record = build({"IN_BYTES": 100, "IN_PKTS": 1}, default_sampling=10)
        self.assertTrue(record.sampled)
        self.assertEqual(record.sample_interval, 10)
        self.assertEqual(record.bytes, 1000)
        self.assertEqual(record.raw_bytes, 100)

    def test_record_sampling_field_overrides_default(self) -> None:
        record = build({"IN_BYTES": 100, "SAMPLING_INTERVAL": 5}, default_sampling=10)
        self.assertEqual(record.sample_interval, 5)
        self.assertEqual(record.bytes, 500)


class SamplingHelperTests(unittest.TestCase):
    """Sampling helper functions."""

    def test_normalize_interval(self) -> None:
        self.assertEqual(normalize_interval(None), 1)
        self.assertEqual(normalize_interval(0), 1)
        self.assertEqual(normalize_interval(1), 1)
        self.assertEqual(normalize_interval(10), 10)

    def test_sampling_config_scale(self) -> None:
        config = SamplingConfig(interval=1)
        self.assertFalse(config.active)
        self.assertEqual(config.scale(100, 2), (100, 2))
        sampled = SamplingConfig(interval=10)
        self.assertTrue(sampled.active)
        self.assertEqual(sampled.scale(100, 2), (1000, 20))

    def test_sampling_from_v5_header(self) -> None:
        mode, interval = sampling_from_v5_header(10)
        self.assertEqual(mode, 0)
        self.assertEqual(interval, 10)
        mode, interval = sampling_from_v5_header((2 << 14) | 5)
        self.assertEqual(mode, 2)
        self.assertEqual(interval, 5)

    def test_interval_from_fields(self) -> None:
        self.assertEqual(interval_from_fields({"SAMPLING_INTERVAL": 10}), 10)
        self.assertEqual(interval_from_fields({"SAMPLING_PACKET_INTERVAL": 8}), 8)
        self.assertEqual(interval_from_fields({}, default=4), 4)
        self.assertEqual(interval_from_fields({"SAMPLING_INTERVAL": 0}, default=7), 1)


if __name__ == "__main__":
    unittest.main()
