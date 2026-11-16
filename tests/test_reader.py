"""Tests for the unified export reader and format detection."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import support

from flowanalyzer.errors import FlowError
from flowanalyzer.netflow.reader import (
    SUPPORTED_VERSIONS,
    decode_export,
    detect_version,
    read_export,
)


class DetectionTests(unittest.TestCase):
    """Version detection and format dispatch."""

    def test_supported_versions(self) -> None:
        self.assertEqual(SUPPORTED_VERSIONS, (5, 9, 10))

    def test_detect_version(self) -> None:
        self.assertEqual(detect_version(support.v5_header(0)), 5)
        self.assertEqual(detect_version(support.v9_header(0)), 9)
        self.assertEqual(detect_version(support.ipfix_header(16)), 10)

    def test_detect_version_too_short_raises(self) -> None:
        with self.assertRaises(FlowError):
            detect_version(b"\x00")

    def test_unsupported_version_raises(self) -> None:
        with self.assertRaises(FlowError):
            decode_export(b"\x00\x63" + b"\x00" * 20)

    def test_dispatch_v5(self) -> None:
        export = decode_export(support.v5_export([support.v5_record()]))
        self.assertEqual(export.format, "v5")
        self.assertEqual(export.version, 5)

    def test_dispatch_v9(self) -> None:
        export = decode_export(
            support.v9_export(
                [support.v9_template_flowset(256, support.V9_IPV4_FIELDS)], count=0
            )
        )
        self.assertEqual(export.format, "v9")
        self.assertEqual(export.version, 9)

    def test_dispatch_ipfix(self) -> None:
        export = decode_export(
            support.ipfix_message([support.ipfix_set(2, b"")])
        )
        self.assertEqual(export.format, "ipfix")
        self.assertEqual(export.version, 10)

    def test_exporter_label_is_passed_through(self) -> None:
        export = decode_export(support.v5_export([support.v5_record()]), exporter="edge-1")
        self.assertEqual(export.exporter, "edge-1")
        self.assertEqual(export.records[0].exporter, "edge-1")


class ReadExportTests(unittest.TestCase):
    """Reading exports from disk."""

    def test_read_export_uses_file_name_as_exporter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows-v5.bin"
            path.write_bytes(support.v5_export([support.v5_record()]))
            export = read_export(path)
        self.assertEqual(export.exporter, "flows-v5.bin")
        self.assertEqual(len(export.records), 1)

    def test_read_export_custom_exporter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows.bin"
            path.write_bytes(support.v5_export([support.v5_record()]))
            export = read_export(path, exporter="router-a")
        self.assertEqual(export.exporter, "router-a")

    def test_read_export_missing_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FlowError):
                read_export(Path(directory) / "missing.bin")

    def test_flow_export_to_dict(self) -> None:
        export = decode_export(
            support.v5_export([support.v5_record()]), exporter="r1"
        )
        payload = export.to_dict()
        self.assertEqual(payload["format"], "v5")
        self.assertEqual(payload["exporter"], "r1")
        self.assertEqual(payload["records"], 1)
        self.assertEqual(len(payload["records_detail"]), 1)
        self.assertFalse(payload["truncated"])

    def test_read_committed_examples(self) -> None:
        root = Path(__file__).resolve().parents[1]
        expected = {
            "flows-v5.bin": 5,
            "flows-v9.bin": 9,
            "flows-ipfix.bin": 10,
        }
        for file_name, version in expected.items():
            with self.subTest(file=file_name):
                export = read_export(root / "examples" / file_name)
                self.assertEqual(export.version, version)
                self.assertEqual(len(export.records), 12)
                self.assertEqual(export.warnings, [])


if __name__ == "__main__":
    unittest.main()
