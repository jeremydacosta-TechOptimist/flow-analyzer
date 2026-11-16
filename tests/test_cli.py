"""End-to-end tests for the flowanalyzer command line interface.

The CLI handlers are exercised in-process with redirected stdout/stderr so both
the pytest and unittest runners see the real exit codes and messages.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from flowanalyzer.cli import main
from flowanalyzer.version import __version__


def run_cli(*arguments: str) -> tuple[int, str, str]:
    """Run the CLI in-process and capture ``(code, stdout, stderr)``."""
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = main(list(arguments))
        except SystemExit as error:
            code = error.code if isinstance(error.code, int) else 1
    return code, stdout.getvalue(), stderr.getvalue()


class CliBase(unittest.TestCase):
    """Provide a temporary directory with generated example exports."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self.directory = Path(self._directory.name)
        for export_format, name in (
            ("v5", "flows-v5.bin"),
            ("v9", "flows-v9.bin"),
            ("ipfix", "flows-ipfix.bin"),
        ):
            code, _stdout, stderr = run_cli(
                "generate", "--format", export_format, "--out", str(self.directory / name)
            )
            self.assertEqual(code, 0, stderr)

    def tearDown(self) -> None:
        self._directory.cleanup()


class UsageTests(unittest.TestCase):
    """Help, version and usage errors."""

    def test_version_subcommand(self) -> None:
        code, stdout, stderr = run_cli("version")
        self.assertEqual(code, 0)
        self.assertEqual(stdout.strip(), f"flowanalyzer {__version__}")
        self.assertEqual(stderr, "")

    def test_version_flag(self) -> None:
        code, stdout, _stderr = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn("flowanalyzer 1.0.0", stdout)

    def test_help_lists_subcommands(self) -> None:
        code, stdout, _stderr = run_cli("--help")
        self.assertEqual(code, 0)
        for command in ("generate", "decode", "analyze", "report", "version"):
            self.assertIn(command, stdout)

    def test_no_command_exits_with_usage_error(self) -> None:
        code, _stdout, stderr = run_cli()
        self.assertEqual(code, 2)
        self.assertIn("COMMAND", stderr)

    def test_unknown_command_exits_with_usage_error(self) -> None:
        code, _stdout, stderr = run_cli("explode")
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", stderr)

    def test_generate_requires_format_and_out(self) -> None:
        code, _stdout, _stderr = run_cli("generate")
        self.assertEqual(code, 2)

    def test_generate_rejects_unknown_format(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _stdout, _stderr = run_cli(
                "generate", "--format", "netflow7", "--out", str(Path(directory) / "x.bin")
            )
        self.assertEqual(code, 2)

    def test_report_requires_out(self) -> None:
        code, _stdout, _stderr = run_cli("report", "file.bin")
        self.assertEqual(code, 2)

    def test_decode_rejects_negative_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x.bin"
            path.write_bytes(b"\x00\x05")
            code, _stdout, _stderr = run_cli("decode", str(path), "--limit", "-1")
        self.assertEqual(code, 2)

    def test_generate_rejects_zero_flows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _stdout, _stderr = run_cli(
                "generate",
                "--format",
                "v9",
                "--out",
                str(Path(directory) / "x.bin"),
                "--flows",
                "0",
            )
        self.assertEqual(code, 2)


class GenerateTests(CliBase):
    """The generate subcommand."""

    def test_generate_v5_creates_a_decodable_file(self) -> None:
        path = self.directory / "flows-v5.bin"
        self.assertTrue(path.exists())
        code, stdout, stderr = run_cli("decode", str(path))
        self.assertEqual(code, 0, stderr)
        self.assertIn("NetFlow v5", stdout)
        self.assertIn("12 record(s)", stdout)

    def test_generate_v9_creates_a_decodable_file(self) -> None:
        code, stdout, stderr = run_cli("decode", str(self.directory / "flows-v9.bin"))
        self.assertEqual(code, 0, stderr)
        self.assertIn("NetFlow v9", stdout)
        self.assertIn("3 template(s)", stdout)

    def test_generate_ipfix_creates_a_decodable_file(self) -> None:
        code, stdout, stderr = run_cli("decode", str(self.directory / "flows-ipfix.bin"))
        self.assertEqual(code, 0, stderr)
        self.assertIn("IPFIX v10", stdout)

    def test_generate_prints_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "flows-v9.bin"
            code, stdout, stderr = run_cli(
                "generate", "--format", "v9", "--out", str(output), "--flows", "5"
            )
            self.assertEqual(code, 0, stderr)
            self.assertIn("Wrote", stdout)
            self.assertIn("5 flow records", stdout)
            self.assertIn("NetFlow v9", stdout)
            self.assertTrue(output.exists())

    def test_generate_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.bin"
            second = Path(directory) / "second.bin"
            run_cli("generate", "--format", "ipfix", "--out", str(first), "--flows", "6")
            run_cli("generate", "--format", "ipfix", "--out", str(second), "--flows", "6")
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_generate_v5_rejects_too_many_flows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            code, _stdout, stderr = run_cli(
                "generate",
                "--format",
                "v5",
                "--out",
                str(Path(directory) / "x.bin"),
                "--flows",
                "31",
            )
        self.assertEqual(code, 2)
        self.assertIn("at most 30", stderr)

    def test_generate_with_sampling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sampled.bin"
            code, _stdout, stderr = run_cli(
                "generate",
                "--format",
                "v9",
                "--out",
                str(path),
                "--sampling-interval",
                "10",
            )
            self.assertEqual(code, 0, stderr)
            code, stdout, _stderr = run_cli("decode", str(path), "--json", "--limit", "1")
            self.assertEqual(code, 0)
            payload = json.loads(stdout)
            record = payload["records"][0]
            self.assertTrue(record["sampled"])
            self.assertEqual(record["sample_interval"], 10)


class DecodeTests(CliBase):
    """The decode subcommand."""

    def test_text_output(self) -> None:
        code, stdout, stderr = run_cli("decode", str(self.directory / "flows-v5.bin"))
        self.assertEqual(code, 0, stderr)
        self.assertIn("File: flows-v5.bin", stdout)
        self.assertIn("Format: NetFlow v5", stdout)
        self.assertIn("Records: 12 record(s)", stdout)
        self.assertIn("192.0.2.10", stdout)
        self.assertIn("TCP", stdout)

    def test_json_output(self) -> None:
        code, stdout, stderr = run_cli(
            "decode", str(self.directory / "flows-v5.bin"), "--json"
        )
        self.assertEqual(code, 0, stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["generator"], f"flowanalyzer {__version__}")
        self.assertEqual(payload["export"]["format"], "v5")
        self.assertEqual(payload["export"]["record_count"], 12)
        self.assertEqual(len(payload["records"]), 12)
        self.assertEqual(payload["records"][0]["protocol_name"], "TCP")

    def test_limit_truncates_the_listing(self) -> None:
        code, stdout, _stderr = run_cli(
            "decode", str(self.directory / "flows-v5.bin"), "--limit", "2"
        )
        self.assertEqual(code, 0)
        self.assertIn("... 10 more record(s)", stdout)

    def test_limit_zero_lists_all_records(self) -> None:
        code, stdout, _stderr = run_cli(
            "decode", str(self.directory / "flows-v5.bin"), "--limit", "0"
        )
        self.assertEqual(code, 0)
        self.assertNotIn("more record(s)", stdout)
        self.assertEqual(stdout.count("2026-01-15"), 12)

    def test_exporter_override(self) -> None:
        code, stdout, stderr = run_cli(
            "decode", str(self.directory / "flows-v5.bin"), "--exporter", "edge-router"
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("File: edge-router", stdout)

    def test_missing_file_exits_one(self) -> None:
        code, _stdout, stderr = run_cli("decode", str(self.directory / "missing.bin"))
        self.assertEqual(code, 1)
        self.assertIn("flowanalyzer: error:", stderr)

    def test_invalid_file_exits_one(self) -> None:
        path = self.directory / "junk.bin"
        path.write_bytes(b"not a flow export at all")
        code, _stdout, stderr = run_cli("decode", str(path))
        self.assertEqual(code, 1)
        self.assertIn("unsupported export format", stderr)

    def test_truncated_export_exits_one_but_prints_records(self) -> None:
        path = self.directory / "truncated-v5.bin"
        data = (self.directory / "flows-v5.bin").read_bytes()
        path.write_bytes(data[:-7])
        code, stdout, stderr = run_cli("decode", str(path))
        self.assertEqual(code, 1)
        self.assertIn("truncated", stderr)
        self.assertIn("NetFlow v5", stdout)


class AnalyzeTests(CliBase):
    """The analyze subcommand."""

    def test_text_output(self) -> None:
        code, stdout, stderr = run_cli("analyze", str(self.directory / "flows-v9.bin"))
        self.assertEqual(code, 0, stderr)
        for heading in (
            "Top sources",
            "Top destinations",
            "Top conversations",
            "Protocol mix",
            "Timeline",
        ):
            self.assertIn(heading, stdout)
        self.assertIn("Source: flows-v9.bin", stdout)

    def test_json_output(self) -> None:
        code, stdout, stderr = run_cli(
            "analyze", str(self.directory / "flows-ipfix.bin"), "--json"
        )
        self.assertEqual(code, 0, stderr)
        payload = json.loads(stdout)
        self.assertEqual(payload["export"]["format"], "ipfix")
        self.assertEqual(payload["analysis"]["summary"]["records"], 12)
        self.assertEqual(len(payload["analysis"]["conversations"]), 8)
        self.assertTrue(payload["analysis"]["timeline"])

    def test_top_limit_is_applied(self) -> None:
        code, stdout, _stderr = run_cli(
            "analyze", str(self.directory / "flows-v9.bin"), "--json", "--top", "2"
        )
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(len(payload["analysis"]["conversations"]), 2)
        self.assertEqual(len(payload["analysis"]["top_sources"]), 2)

    def test_bucket_size_is_applied(self) -> None:
        code, stdout, _stderr = run_cli(
            "analyze", str(self.directory / "flows-v9.bin"), "--json", "--bucket", "30"
        )
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["analysis"]["summary"]["bucket_seconds"], 30)
        self.assertGreaterEqual(len(payload["analysis"]["timeline"]), 3)

    def test_missing_file_exits_one(self) -> None:
        code, _stdout, stderr = run_cli("analyze", str(self.directory / "missing.bin"))
        self.assertEqual(code, 1)
        self.assertIn("flowanalyzer: error:", stderr)


class ReportTests(CliBase):
    """The report subcommand."""

    def test_html_report_is_written(self) -> None:
        output = self.directory / "report.html"
        code, stdout, stderr = run_cli(
            "report", str(self.directory / "flows-v9.bin"), "--out", str(output)
        )
        self.assertEqual(code, 0, stderr)
        self.assertTrue(output.exists())
        content = output.read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("<h2>Top sources</h2>", content)
        self.assertIn("<h2>Conversations</h2>", content)
        self.assertNotIn("<script", content)
        self.assertIn("Wrote HTML report", stdout)

    def test_custom_title(self) -> None:
        output = self.directory / "titled.html"
        code, _stdout, _stderr = run_cli(
            "report",
            str(self.directory / "flows-ipfix.bin"),
            "--out",
            str(output),
            "--title",
            "Lab flow review",
        )
        self.assertEqual(code, 0)
        self.assertIn("<title>Lab flow review</title>", output.read_text(encoding="utf-8"))

    def test_report_with_sampling_warns_on_stderr(self) -> None:
        sampled = self.directory / "sampled.bin"
        run_cli(
            "generate", "--format", "v9", "--out", str(sampled), "--sampling-interval", "10"
        )
        output = self.directory / "sampled.html"
        code, _stdout, stderr = run_cli("report", str(sampled), "--out", str(output))
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()
