"""Tests for the NetFlow/IPFIX field registry and value codecs."""

from __future__ import annotations

import struct
import unittest

import support

from flowanalyzer.netflow import fields


class FieldRegistryTests(unittest.TestCase):
    """Registry metadata and name resolution."""

    def test_core_fields_are_registered(self) -> None:
        self.assertEqual(fields.get_field_name(8), "IPV4_SRC_ADDR")
        self.assertEqual(fields.get_field_name(12), "IPV4_DST_ADDR")
        self.assertEqual(fields.get_field_name(27), "IPV6_SRC_ADDR")
        self.assertEqual(fields.get_field_name(152), "FLOW_START_MS")

    def test_field_specs_carry_codecs(self) -> None:
        spec = fields.get_field_spec(8)
        self.assertEqual(spec.codec, "ipv4")
        self.assertTrue(spec.description)
        self.assertEqual(fields.get_field_spec(34).codec, "uint")

    def test_unknown_field_gets_synthetic_spec(self) -> None:
        spec = fields.get_field_spec(999)
        self.assertEqual(spec.name, "FIELD_999")
        self.assertEqual(spec.codec, "octets")

    def test_enterprise_field_name(self) -> None:
        self.assertEqual(
            fields.get_field_name(42, enterprise=9), "ENTERPRISE_9_FIELD_42"
        )

    def test_registry_is_non_empty_and_consistent(self) -> None:
        self.assertGreater(len(fields.FIELD_REGISTRY), 30)
        for field_id, spec in fields.FIELD_REGISTRY.items():
            self.assertEqual(spec.field_id, field_id)


class FieldCodecTests(unittest.TestCase):
    """Decoding of raw field bytes into Python values."""

    def test_decode_uint(self) -> None:
        self.assertEqual(fields.decode_value(b"\x01\x02", "uint"), 258)
        self.assertEqual(fields.decode_value(b"", "uint"), 0)
        self.assertEqual(
            fields.decode_value(b"\x00\x00\x01\x00", "uint"), 256
        )

    def test_decode_ipv4(self) -> None:
        self.assertEqual(
            fields.decode_value(support.ip4("192.0.2.10"), "ipv4"), "192.0.2.10"
        )
        self.assertEqual(
            fields.decode_value(support.ip4("198.51.100.53"), "ipv4"), "198.51.100.53"
        )

    def test_decode_ipv4_wrong_length_falls_back_to_hex(self) -> None:
        self.assertEqual(fields.decode_value(b"\x01\x02\x03", "ipv4"), "010203")

    def test_decode_ipv6(self) -> None:
        self.assertEqual(
            fields.decode_value(support.ip6("2001:db8::10"), "ipv6"), "2001:db8::10"
        )

    def test_decode_ipv6_wrong_length_falls_back_to_hex(self) -> None:
        self.assertEqual(fields.decode_value(b"\x00" * 15, "ipv6"), "00" * 15)

    def test_decode_mac(self) -> None:
        self.assertEqual(
            fields.decode_value(bytes.fromhex("020000000001"), "mac"),
            "02:00:00:00:00:01",
        )

    def test_decode_datetime_ms(self) -> None:
        raw = struct.pack("!Q", 1_700_000_000_123)
        self.assertEqual(fields.decode_value(raw, "datetime_ms"), 1_700_000_000_123)

    def test_decode_datetime_sec(self) -> None:
        raw = struct.pack("!I", 1_700_000_000)
        self.assertEqual(fields.decode_value(raw, "datetime_sec"), 1_700_000_000_000)

    def test_decode_datetime_ntp(self) -> None:
        seconds = 1_700_000_000 + fields.NTP_EPOCH_OFFSET_SECONDS
        raw = struct.pack("!II", seconds, 0x80000000)
        self.assertEqual(fields.decode_value(raw, "datetime_ntp"), 1_700_000_000_500)
        self.assertEqual(fields.decode_value(b"\x00" * 4, "datetime_ntp"), 0)

    def test_decode_octets_returns_bytes(self) -> None:
        self.assertEqual(fields.decode_value(b"\xde\xad", "octets"), b"\xde\xad")

    def test_unknown_codec_raises(self) -> None:
        with self.assertRaises(ValueError):
            fields.decode_value(b"\x00", "no-such-codec")

    def test_decode_field_known(self) -> None:
        name, value = fields.decode_field(12, support.ip4("198.51.100.10"))
        self.assertEqual(name, "IPV4_DST_ADDR")
        self.assertEqual(value, "198.51.100.10")

    def test_decode_field_unknown_keeps_raw_bytes(self) -> None:
        name, value = fields.decode_field(999, b"\x01\x02")
        self.assertEqual(name, "FIELD_999")
        self.assertEqual(value, b"\x01\x02")

    def test_decode_field_enterprise_keeps_raw_bytes(self) -> None:
        name, value = fields.decode_field(10, b"\x00\x00", enterprise=4242)
        self.assertEqual(name, "ENTERPRISE_4242_FIELD_10")
        self.assertEqual(value, b"\x00\x00")

    def test_format_value(self) -> None:
        self.assertEqual(fields.format_value(42), "42")
        self.assertEqual(fields.format_value("text"), "text")
        self.assertEqual(fields.format_value(b"\xde\xad"), "0xdead")
        self.assertEqual(fields.format_value(b""), "0x")


if __name__ == "__main__":
    unittest.main()
