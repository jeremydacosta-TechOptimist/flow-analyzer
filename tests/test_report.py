"""Tests for the HTML and text report renderers."""

from __future__ import annotations

import unittest

from flowanalyzer.aggregate import FlowAnalysis
from flowanalyzer.model import FlowRecord
from flowanalyzer.report import (
    format_bit_rate,
    format_bytes,
    format_count,
    format_duration_ms,
    format_timestamp_ms,
    iso_timestamp_ms,
    render_html,
    render_text,
)

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
    end_ms: int = BASE_MS + 500,
    exporter: str = "flows-v9.bin",
) -> FlowRecord:
    """Build a flow record for report tests."""
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


def sample_analysis() -> FlowAnalysis:
    """Build a small but varied analysis."""
    return FlowAnalysis(
        [
            record(bytes=8000, packets=20),
            record(
                src="198.51.100.10",
                dst="192.0.2.10",
                src_port=80,
                dst_port=49876,
                bytes=4000,
                packets=12,
                start_ms=BASE_MS + 500,
                end_ms=BASE_MS + 900,
            ),
            record(
                src="192.0.2.10",
                dst="198.51.100.20",
                src_port=53523,
                dst_port=53,
                protocol=17,
                bytes=300,
                packets=1,
                start_ms=BASE_MS + 90_000,
                end_ms=BASE_MS + 90_200,
            ),
            record(
                src="2001:db8::10",
                dst="2001:db8::53",
                src_port=5353,
                dst_port=53,
                protocol=17,
                bytes=200,
                packets=1,
                start_ms=BASE_MS + 95_000,
                end_ms=BASE_MS + 95_100,
            ),
        ]
    )


class HtmlReportTests(unittest.TestCase):
    """The standalone HTML report."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.analysis = sample_analysis()
        cls.html = render_html(cls.analysis, source="flows-v9.bin")

    def test_doctype_and_title(self) -> None:
        self.assertTrue(self.html.startswith("<!DOCTYPE html>"))
        self.assertIn('<html lang="en">', self.html)
        self.assertIn("<title>flowanalyzer report - flows-v9.bin</title>", self.html)
        self.assertTrue(self.html.rstrip().endswith("</html>"))

    def test_required_sections(self) -> None:
        for heading in (
            "<h2>Summary</h2>",
            "<h2>Top sources</h2>",
            "<h2>Top destinations</h2>",
            "<h2>Conversations</h2>",
            "<h2>Protocol mix</h2>",
            "<h2>Timeline</h2>",
            "<h2>Decoder notes</h2>",
        ):
            self.assertIn(heading, self.html)

    def test_no_external_assets_or_scripts(self) -> None:
        self.assertNotIn("<script", self.html)
        self.assertNotIn("http://", self.html)
        self.assertNotIn("https://", self.html)
        self.assertNotIn("<link", self.html)

    def test_css_bar_charts(self) -> None:
        self.assertIn('class="bar-row"', self.html)
        self.assertIn('class="bar-fill"', self.html)
        self.assertIn("bar-track", self.html)
        self.assertIn("width:", self.html)

    def test_capture_values_are_present(self) -> None:
        self.assertIn("192.0.2.10", self.html)
        self.assertIn("198.51.100.10", self.html)
        self.assertIn("TCP", self.html)
        self.assertIn("http", self.html)
        self.assertIn("4", self.html)

    def test_hostile_strings_are_escaped(self) -> None:
        hostile = record()
        hostile.src_ip = "<script>alert(1)</script>"
        analysis = FlowAnalysis([hostile])
        rendered = render_html(analysis, source="<bad>.bin")
        self.assertIn("&lt;script&gt;", rendered)
        self.assertNotIn("<script>alert", rendered)
        self.assertIn("&lt;bad&gt;", rendered)

    def test_custom_title(self) -> None:
        rendered = render_html(self.analysis, source="x.bin", title="Lab traffic")
        self.assertIn("<title>Lab traffic</title>", rendered)

    def test_top_limit_note(self) -> None:
        rendered = render_html(self.analysis, source="x.bin", top=1)
        self.assertIn("Showing the 1 busiest of 3 conversations.", rendered)
        self.assertIn("Showing the first 1 of 2 buckets", rendered)

    def test_empty_analysis_placeholders(self) -> None:
        rendered = render_html(FlowAnalysis([]), source="empty.bin")
        self.assertIn("No records.", rendered)
        self.assertIn("empty.bin", rendered)
        self.assertIn("No decoder warnings were reported.", rendered)

    def test_decoder_warnings_are_listed(self) -> None:
        rendered = render_html(
            self.analysis,
            source="x.bin",
            warnings=["data flowset 999 <skipped>"],
        )
        self.assertIn("data flowset 999 &lt;skipped&gt;", rendered)


class TextReportTests(unittest.TestCase):
    """Plain-text analysis output."""

    def test_sections_and_tables(self) -> None:
        report = render_text(sample_analysis(), source="flows-v9.bin", format_label="NetFlow v9")
        self.assertIn("Source: flows-v9.bin (NetFlow v9)", report)
        self.assertIn("Top sources", report)
        self.assertIn("Top destinations", report)
        self.assertIn("Top conversations", report)
        self.assertIn("Protocol mix", report)
        self.assertIn("Timeline (60 s buckets)", report)
        self.assertIn("192.0.2.10", report)
        self.assertIn("192.0.2.10:49876", report)
        self.assertIn("198.51.100.10:80", report)

    def test_empty_report(self) -> None:
        report = render_text(FlowAnalysis([]), source="empty.bin", format_label="IPFIX v10")
        self.assertIn("Source: empty.bin (IPFIX v10)", report)
        self.assertIn("Records: 0", report)
        self.assertIn("Top sources", report)

    def test_warnings_section(self) -> None:
        report = render_text(
            sample_analysis(),
            source="x.bin",
            format_label="NetFlow v9",
            warnings=["truncated set"],
        )
        self.assertIn("Decoder warnings", report)
        self.assertIn("- truncated set", report)

    def test_limited_top(self) -> None:
        report = render_text(sample_analysis(), source="x.bin", format_label="v9", top=1)
        self.assertIn("Top sources", report)
        self.assertNotIn("198.51.100.20", report)
        self.assertNotIn("2001:db8::53", report)


class FormattingTests(unittest.TestCase):
    """Formatting helpers used by both renderers."""

    def test_format_count(self) -> None:
        self.assertEqual(format_count(1234567), "1,234,567")
        self.assertEqual(format_count(0), "0")

    def test_format_bytes(self) -> None:
        self.assertEqual(format_bytes(512), "512 B")
        self.assertIn("KiB", format_bytes(2048))
        self.assertIn("MiB", format_bytes(3 * 1024 * 1024))

    def test_format_bit_rate(self) -> None:
        self.assertIn("bit/s", format_bit_rate(500))
        self.assertIn("kbit/s", format_bit_rate(15_000))
        self.assertIn("Mbit/s", format_bit_rate(3_500_000))
        self.assertIn("Gbit/s", format_bit_rate(2_000_000_000))

    def test_format_duration(self) -> None:
        self.assertEqual(format_duration_ms(500), "500 ms")
        self.assertEqual(format_duration_ms(1500), "1.500 s")

    def test_format_timestamp(self) -> None:
        self.assertEqual(
            format_timestamp_ms(1_700_000_000_123), "2023-11-14 22:13:20.123 UTC"
        )
        self.assertEqual(
            iso_timestamp_ms(1_700_000_000_123), "2023-11-14T22:13:20.123Z"
        )


if __name__ == "__main__":
    unittest.main()
