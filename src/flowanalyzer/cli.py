"""Command line interface for flowanalyzer.

Exit codes: 0 for success, 2 for bad command-line usage (argparse) and 1 for a
runtime failure such as a malformed, truncated or unreadable export.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .aggregate import analyze
from .errors import FlowError
from .generate import (
    DEFAULT_FLOWS,
    DEFAULT_SEED,
    DEFAULT_SAMPLING_INTERVAL,
    SUPPORTED_FORMATS,
    V5_MAX_RECORDS,
    write_export,
)
from .model import FlowExport
from .netflow.reader import read_export
from .report import (
    format_bytes,
    format_count,
    format_duration_ms,
    format_timestamp_ms,
    render_html,
    render_text,
)
from .version import __version__

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

FORMAT_LABELS = {
    "v5": "NetFlow v5",
    "v9": "NetFlow v9",
    "ipfix": "IPFIX v10",
}


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse command tree."""
    parser = argparse.ArgumentParser(
        prog="flowanalyzer",
        description=(
            "Offline NetFlow v5/v9 and IPFIX decoder and traffic analyzer. "
            "Decodes binary flow exports, aggregates top talkers, bidirectional "
            "conversations, protocol mix and a traffic timeline, and renders "
            "JSON or a standalone HTML report."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"flowanalyzer {__version__}"
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, metavar="COMMAND"
    )

    generate = subparsers.add_parser(
        "generate",
        help="generate a deterministic synthetic export",
        description=(
            "Generate a deterministic lab export with RFC 5737 and 2001:db8::/32 "
            "addresses; used for demos and round-trip tests."
        ),
    )
    generate.add_argument(
        "--format",
        dest="export_format",
        choices=list(SUPPORTED_FORMATS),
        required=True,
        help="export format to generate",
    )
    generate.add_argument("--out", required=True, metavar="FILE", help="output file")
    generate.add_argument(
        "--flows",
        type=_positive_int,
        default=DEFAULT_FLOWS,
        metavar="N",
        help=f"number of flow records (default: {DEFAULT_FLOWS})",
    )
    generate.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        metavar="S",
        help=f"random seed for deterministic traffic (default: {DEFAULT_SEED})",
    )
    generate.add_argument(
        "--sampling-interval",
        type=_positive_int,
        default=DEFAULT_SAMPLING_INTERVAL,
        metavar="N",
        help="sampling interval encoded in the export (default: 1, no sampling)",
    )
    generate.set_defaults(handler=_handle_generate)

    decode = subparsers.add_parser(
        "decode",
        help="decode an export and print every flow record",
        description=(
            "Decode one NetFlow v5/v9 or IPFIX export and print the header, "
            "templates and flow records; use --json for machine-readable output."
        ),
    )
    decode.add_argument("file", metavar="FILE", help="binary flow export")
    decode.add_argument(
        "--limit",
        type=_non_negative_int,
        default=20,
        metavar="N",
        help="maximum records to list; 0 lists all (default: 20)",
    )
    decode.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="print machine-readable JSON",
    )
    decode.add_argument(
        "--exporter",
        default=None,
        metavar="NAME",
        help="exporter label for the records (default: file name)",
    )
    decode.set_defaults(handler=_handle_decode)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="aggregate top talkers, conversations, protocols and timeline",
        description=(
            "Decode an export and print the traffic summary, top talkers, "
            "bidirectional conversations, protocol mix and time buckets."
        ),
    )
    analyze_parser.add_argument("file", metavar="FILE", help="binary flow export")
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="print machine-readable JSON",
    )
    analyze_parser.add_argument(
        "--top",
        type=_non_negative_int,
        default=10,
        metavar="N",
        help="entries per table; 0 shows all (default: 10)",
    )
    analyze_parser.add_argument(
        "--bucket",
        type=_positive_int,
        default=60,
        metavar="SECONDS",
        help="timeline bucket size in seconds (default: 60)",
    )
    analyze_parser.add_argument(
        "--exporter",
        default=None,
        metavar="NAME",
        help="exporter label for the records (default: file name)",
    )
    analyze_parser.set_defaults(handler=_handle_analyze)

    report = subparsers.add_parser(
        "report",
        help="render a standalone HTML report",
        description=(
            "Render a self-contained HTML report with inline CSS bars and tables; "
            "no external assets and no scripts."
        ),
    )
    report.add_argument("file", metavar="FILE", help="binary flow export")
    report.add_argument(
        "--out", required=True, metavar="FILE.html", help="output HTML file"
    )
    report.add_argument(
        "--title", default=None, metavar="TEXT", help="report title override"
    )
    report.add_argument(
        "--top",
        type=_non_negative_int,
        default=10,
        metavar="N",
        help="entries per table; 0 shows all (default: 10)",
    )
    report.add_argument(
        "--bucket",
        type=_positive_int,
        default=60,
        metavar="SECONDS",
        help="timeline bucket size in seconds (default: 60)",
    )
    report.add_argument(
        "--exporter",
        default=None,
        metavar="NAME",
        help="exporter label for the records (default: file name)",
    )
    report.set_defaults(handler=_handle_report)

    version = subparsers.add_parser(
        "version", help="print the flowanalyzer version"
    )
    version.set_defaults(handler=_handle_version)
    return parser


def _positive_int(text: str) -> int:
    """Argparse type for an integer greater than zero."""
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from exc
    if value < 1:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return value


def _non_negative_int(text: str) -> int:
    """Argparse type for a non-negative integer."""
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from exc
    if value < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return value


def _format_label(export: FlowExport) -> str:
    """Return the human label of an export format."""
    return FORMAT_LABELS.get(export.format, export.format)


def _load_export(path: str, exporter: str | None) -> FlowExport:
    """Read an export and normalise all failure modes to FlowError."""
    return read_export(path, exporter=exporter)


def _emit_warnings(export: FlowExport) -> int:
    """Print decoder warnings and return the matching exit code."""
    for warning in export.warnings:
        print(f"flowanalyzer: warning: {warning}", file=sys.stderr)
    if export.truncated:
        print(
            "flowanalyzer: error: truncated export; only complete records were "
            "decoded",
            file=sys.stderr,
        )
        return EXIT_ERROR
    return EXIT_OK


def _handle_generate(args: argparse.Namespace) -> int:
    if args.export_format == "v5" and args.flows > V5_MAX_RECORDS:
        print(
            f"flowanalyzer: error: NetFlow v5 carries at most {V5_MAX_RECORDS} "
            "flow records per export",
            file=sys.stderr,
        )
        return EXIT_USAGE
    size = write_export(
        args.out,
        args.export_format,
        flows=args.flows,
        seed=args.seed,
        sampling_interval=args.sampling_interval,
    )
    label = FORMAT_LABELS[args.export_format]
    print(
        f"Wrote {args.out}: {format_count(args.flows)} flow records, "
        f"{format_bytes(size)} ({label}, seed {args.seed})"
    )
    return EXIT_OK


def _print_decode(export: FlowExport, records: list) -> None:
    """Print a debug-friendly text view of a decoded export."""
    print(f"File: {export.exporter}")
    print(f"Format: {_format_label(export)} (version {export.version})")
    if export.header:
        header_text = ", ".join(
            f"{key}={value}" for key, value in export.header.items()
        )
        print(f"Header: {header_text}")
    status = (
        f"{format_count(len(export.records))} record(s), "
        f"{format_count(export.template_count)} template(s), "
        f"{format_count(len(export.warnings))} warning(s)"
    )
    if export.truncated:
        status += ", truncated"
    print(f"Records: {status}")
    print()
    if not records:
        print("No flow records decoded.")
        return
    print(
        f"  {'#':>3}  {'Start (UTC)':<23} {'Duration':>10}  {'Proto':<7}"
        f"{'Endpoints':<56}{'Bytes':>12}{'Packets':>9}"
    )
    for index, record in enumerate(records, start=1):
        endpoints = f"{record.endpoint_source} -> {record.endpoint_destination}"
        print(
            f"  {index:>3}  {format_timestamp_ms(record.start_ms):<23} "
            f"{format_duration_ms(record.duration_ms):>10}  "
            f"{record.protocol_name:<7}{endpoints:<56}"
            f"{format_count(record.bytes):>12}{format_count(record.packets):>9}"
        )
    hidden = len(export.records) - len(records)
    if hidden > 0:
        print(
            f"  ... {format_count(hidden)} more record(s); use --limit 0 to list "
            "them all"
        )


def _handle_decode(args: argparse.Namespace) -> int:
    export = _load_export(args.file, args.exporter)
    records = export.records if args.limit == 0 else export.records[: args.limit]
    if args.as_json:
        payload = {
            "generator": f"flowanalyzer {__version__}",
            "export": {
                "format": export.format,
                "version": export.version,
                "exporter": export.exporter,
                "header": dict(export.header),
                "templates": export.template_count,
                "record_count": len(export.records),
                "truncated": export.truncated,
                "warnings": list(export.warnings),
            },
            "records": [record.to_dict() for record in records],
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_decode(export, records)
    return _emit_warnings(export)


def _handle_analyze(args: argparse.Namespace) -> int:
    export = _load_export(args.file, args.exporter)
    analysis = analyze(export, bucket_seconds=args.bucket)
    if args.as_json:
        payload = {
            "generator": f"flowanalyzer {__version__}",
            "source": export.exporter,
            "export": {
                "format": export.format,
                "version": export.version,
                "header": dict(export.header),
                "record_count": len(export.records),
                "truncated": export.truncated,
                "warnings": list(export.warnings),
            },
            "analysis": analysis.to_dict(top=args.top),
        }
        print(json.dumps(payload, indent=2))
    else:
        print(
            render_text(
                analysis,
                source=export.exporter,
                format_label=_format_label(export),
                top=args.top,
            ),
            end="",
        )
    return _emit_warnings(export)


def _handle_report(args: argparse.Namespace) -> int:
    export = _load_export(args.file, args.exporter)
    analysis = analyze(export, bucket_seconds=args.bucket)
    content = render_html(
        analysis,
        source=export.exporter,
        title=args.title,
        warnings=export.warnings,
        top=args.top,
    )
    try:
        Path(args.out).write_text(content, encoding="utf-8")
    except OSError as exc:
        raise FlowError(f"cannot write {args.out}: {exc}") from exc
    print(
        f"Wrote HTML report to {args.out} "
        f"({format_count(len(export.records))} records, "
        f"{format_count(len(analysis.conversations()))} conversations, "
        f"{format_bytes(len(content))})"
    )
    return _emit_warnings(export)


def _handle_version(args: argparse.Namespace) -> int:
    print(f"flowanalyzer {__version__}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Entry point used by ``python -m flowanalyzer`` and the console script."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except FlowError as exc:
        print(f"flowanalyzer: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"flowanalyzer: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
