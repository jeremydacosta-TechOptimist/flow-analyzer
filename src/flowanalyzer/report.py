"""Standalone HTML report and text formatting for flow analysis.

The HTML report is a single file: the styles are inline and the charts are
plain CSS bars, so it opens offline in any browser with no external assets and
no scripts.  Every value taken from the export is HTML-escaped.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .aggregate import FlowAnalysis
from .version import __version__

_STYLES = """
:root {
  color-scheme: light;
  --ink: #111827;
  --muted: #6b7280;
  --line: #e5e7eb;
  --panel: #f9fafb;
  --accent: #0f766e;
  --accent-soft: #ccfbf1;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
  color: var(--ink);
  background: #ffffff;
  line-height: 1.5;
}
header.page, main, footer { max-width: 1040px; margin: 0 auto; padding: 0 24px; }
header.page { padding-top: 40px; }
h1 { font-size: 1.7rem; margin: 0 0 6px; }
h2 { font-size: 1.2rem; margin: 0 0 14px; }
.subtitle, .muted { color: var(--muted); }
.subtitle { margin: 0 0 8px; }
code { background: var(--panel); border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; }
section { margin: 34px 0; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
.card .label { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
.card .value { font-size: 1.15rem; font-weight: 600; margin-top: 3px; overflow-wrap: anywhere; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.92rem; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); }
th { background: var(--panel); font-weight: 600; color: var(--muted); white-space: nowrap; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr:last-child td { border-bottom: none; }
.bar-row { display: grid; grid-template-columns: minmax(150px, 240px) 1fr minmax(90px, auto); gap: 10px; align-items: center; margin: 5px 0; font-size: 0.9rem; }
.bar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-track { background: var(--panel); border-radius: 4px; height: 15px; overflow: hidden; }
.bar-fill { background: var(--accent); height: 100%; border-radius: 4px; min-width: 2px; }
.bar-fill.alt { background: #0d9488; }
.bar-value { text-align: right; font-variant-numeric: tabular-nums; color: var(--muted); }
.notes { margin: 6px 0; padding-left: 22px; }
footer { color: var(--muted); font-size: 0.85rem; padding: 26px 24px 42px; border-top: 1px solid var(--line); margin-top: 40px; }
@media (max-width: 620px) { .cards { grid-template-columns: repeat(2, 1fr); } }
""".strip()


def format_count(value: int) -> str:
    """Format an integer with thousands separators."""
    return f"{value:,}"


def format_bytes(value: int) -> str:
    """Format a byte count with KiB/MiB suffixes."""
    if value < 1024:
        return f"{value} B"
    scaled = float(value)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        scaled /= 1024.0
        if scaled < 1024.0:
            return f"{scaled:.1f} {unit}"
    return f"{scaled:.1f} PiB"


def format_bit_rate(rate: float) -> str:
    """Format a bit rate with SI prefixes, the network convention."""
    bits = rate
    if bits < 1_000:
        return f"{bits:.0f} bit/s"
    if bits < 1_000_000:
        return f"{bits / 1_000:.1f} kbit/s"
    if bits < 1_000_000_000:
        return f"{bits / 1_000_000:.2f} Mbit/s"
    return f"{bits / 1_000_000_000:.2f} Gbit/s"


def format_duration_ms(duration_ms: int) -> str:
    """Format a millisecond duration with a readable unit."""
    if duration_ms >= 1000:
        return f"{duration_ms / 1000:.3f} s"
    return f"{duration_ms} ms"


def _utc_datetime(timestamp_ms: int) -> datetime:
    seconds, milliseconds = divmod(timestamp_ms, 1000)
    return datetime.fromtimestamp(seconds, timezone.utc).replace(
        microsecond=milliseconds * 1000
    )


def format_timestamp_ms(timestamp_ms: int) -> str:
    """Format an epoch-millisecond timestamp in UTC."""
    return _utc_datetime(timestamp_ms).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def iso_timestamp_ms(timestamp_ms: int) -> str:
    """Format an epoch-millisecond timestamp as an ISO 8601 UTC instant."""
    return _utc_datetime(timestamp_ms).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _bar_row(label: str, value: int, maximum: int, text: str, *, alt: bool = False) -> str:
    """Render one CSS bar row."""
    width = 0.0 if maximum <= 0 else max(1.0, value / maximum * 100.0)
    fill_class = "bar-fill alt" if alt else "bar-fill"
    return (
        '<div class="bar-row">'
        f'<span class="bar-label">{html.escape(label)}</span>'
        f'<div class="bar-track"><div class="{fill_class}" style="width:{width:.1f}%"></div></div>'
        f'<span class="bar-value">{html.escape(text)}</span>'
        "</div>"
    )


def _table(headers: list[str], rows: list[list[str]], *, numeric: set[int] | None = None) -> str:
    """Render an HTML table; cells are treated as pre-escaped text."""
    numeric = numeric or set()
    header_cells = "".join(
        f'<th class="num">{html.escape(header)}</th>'
        if index in numeric
        else f"<th>{html.escape(header)}</th>"
        for index, header in enumerate(headers)
    )
    body = []
    for row in rows:
        cells = "".join(
            f'<td class="num">{cell}</td>' if index in numeric else f"<td>{cell}</td>"
            for index, cell in enumerate(row)
        )
        body.append(f"<tr>{cells}</tr>")
    return (
        "<table><tr>" + header_cells + "</tr>" + "".join(body) + "</table>"
    )


def render_html(
    analysis: FlowAnalysis,
    *,
    source: str,
    title: str | None = None,
    warnings: list[str] | None = None,
    top: int = 10,
) -> str:
    """Render a complete standalone HTML report."""
    page_title = title or f"flowanalyzer report - {source}"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    summary = analysis.summary
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{html.escape(page_title)}</title>",
        f"<style>{_STYLES}</style>",
        "</head>",
        "<body>",
        '<header class="page">',
        "<h1>flowanalyzer traffic report</h1>",
        '<p class="subtitle">'
        f"Source: <code>{html.escape(source)}</code> &middot; generated "
        f"{html.escape(generated)} by flowanalyzer {__version__}"
        "</p>",
        "</header>",
        "<main>",
        _render_summary(summary),
        _render_sources(analysis, top),
        _render_destinations(analysis, top),
        _render_conversations(analysis, top),
        _render_protocols(analysis, top),
        _render_timeline(analysis, top),
        _render_notes(warnings or []),
        "</main>",
        "<footer>",
        f"<p>Generated locally by flowanalyzer {__version__}. "
        "Self-contained report: no external assets, no scripts.</p>",
        "</footer>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts) + "\n"


def _render_summary(summary) -> str:
    cards = [
        ("Flow records", format_count(summary.records)),
        ("Bytes", format_bytes(summary.bytes)),
        ("Packets", format_count(summary.packets)),
        ("Duration", format_duration_ms(summary.duration_ms)),
        ("Average throughput", format_bit_rate(summary.avg_bytes_per_second * 8)),
        ("Exporters", format_count(len(summary.exporters))),
    ]
    card_html = "".join(
        f'<div class="card"><div class="label">{html.escape(label)}</div>'
        f'<div class="value">{html.escape(value)}</div></div>'
        for label, value in cards
    )
    time_span = (
        f"{format_timestamp_ms(summary.start_ms)} to {format_timestamp_ms(summary.end_ms)}"
        if summary.start_ms is not None and summary.end_ms is not None
        else "no records"
    )
    details = (
        "<table>"
        f"<tr><th>Time span</th><td>{html.escape(time_span)}</td></tr>"
        f"<tr><th>Average packet rate</th><td>{summary.avg_packets_per_second:.1f} pkt/s</td></tr>"
        f"<tr><th>Timeline bucket</th><td>{summary.bucket_seconds} s</td></tr>"
        f"<tr><th>Exporters</th><td>{html.escape(', '.join(summary.exporters) or 'none')}</td></tr>"
        "</table>"
    )
    return (
        '<section id="summary"><h2>Summary</h2>'
        f'<div class="cards">{card_html}</div>{details}</section>'
    )


def _render_sources(analysis: FlowAnalysis, top: int) -> str:
    talkers = analysis.top_sources(top)
    if not talkers:
        return (
            '<section id="sources"><h2>Top sources</h2>'
            '<p class="muted">No records.</p></section>'
        )
    maximum = max(talker.bytes for talker in talkers) or 1
    bars = "".join(
        _bar_row(
            talker.address,
            talker.bytes,
            maximum,
            f"{format_bytes(talker.bytes)} / {format_count(talker.packets)} pkt",
            alt=index % 2 == 1,
        )
        for index, talker in enumerate(talkers)
    )
    rows = [
        [
            f"<code>{html.escape(talker.address)}</code>",
            format_count(talker.bytes),
            format_count(talker.packets),
            format_count(talker.records),
        ]
        for talker in talkers
    ]
    table = _table(["Source address", "Bytes", "Packets", "Records"], rows, numeric={1, 2, 3})
    return f'<section id="sources"><h2>Top sources</h2>{bars}{table}</section>'


def _render_destinations(analysis: FlowAnalysis, top: int) -> str:
    talkers = analysis.top_destinations(top)
    if not talkers:
        return (
            '<section id="destinations"><h2>Top destinations</h2>'
            '<p class="muted">No records.</p></section>'
        )
    maximum = max(talker.bytes for talker in talkers) or 1
    bars = "".join(
        _bar_row(
            talker.address,
            talker.bytes,
            maximum,
            f"{format_bytes(talker.bytes)} / {format_count(talker.packets)} pkt",
            alt=index % 2 == 1,
        )
        for index, talker in enumerate(talkers)
    )
    rows = [
        [
            f"<code>{html.escape(talker.address)}</code>",
            format_count(talker.bytes),
            format_count(talker.packets),
            format_count(talker.records),
        ]
        for talker in talkers
    ]
    table = _table(
        ["Destination address", "Bytes", "Packets", "Records"], rows, numeric={1, 2, 3}
    )
    return f'<section id="destinations"><h2>Top destinations</h2>{bars}{table}</section>'


def _render_conversations(analysis: FlowAnalysis, top: int) -> str:
    conversations = analysis.conversations(top)
    if not conversations:
        return (
            '<section id="conversations"><h2>Conversations</h2>'
            '<p class="muted">No records.</p></section>'
        )
    rows = [
        [
            html.escape(item.protocol_name),
            html.escape(item.service),
            f"<code>{html.escape(item.endpoint_a.label)}</code>",
            f"<code>{html.escape(item.endpoint_b.label)}</code>",
            format_count(item.bytes_total),
            format_count(item.packets_total),
            format_duration_ms(item.duration_ms),
        ]
        for item in conversations
    ]
    table = _table(
        ["Protocol", "Service", "Endpoint A", "Endpoint B", "Bytes", "Packets", "Duration"],
        rows,
        numeric={4, 5, 6},
    )
    hidden = len(analysis.conversations()) - len(conversations)
    note = (
        f'<p class="muted">Showing the {len(conversations)} busiest of '
        f"{len(analysis.conversations())} conversations.</p>"
        if hidden > 0
        else ""
    )
    return f'<section id="conversations"><h2>Conversations</h2>{note}{table}</section>'


def _render_protocols(analysis: FlowAnalysis, top: int) -> str:
    stats = analysis.protocol_distribution()
    if not stats:
        return (
            '<section id="protocols"><h2>Protocol mix</h2>'
            '<p class="muted">No records.</p></section>'
        )
    shown = stats[:top]
    maximum = max(stat.bytes for stat in shown) or 1
    bars = "".join(
        _bar_row(
            stat.name,
            stat.bytes,
            maximum,
            f"{format_bytes(stat.bytes)} / {format_count(stat.records)} rec",
            alt=index % 2 == 1,
        )
        for index, stat in enumerate(shown)
    )
    return f'<section id="protocols"><h2>Protocol mix</h2>{bars}</section>'


def _render_timeline(analysis: FlowAnalysis, top: int) -> str:
    buckets = analysis.timeline()
    if not buckets:
        return (
            '<section id="timeline"><h2>Timeline</h2>'
            '<p class="muted">No records.</p></section>'
        )
    shown = buckets[:top]
    maximum = max(bucket.bytes for bucket in shown) or 1
    bars = "".join(
        _bar_row(
            iso_timestamp_ms(bucket.start_ms),
            bucket.bytes,
            maximum,
            f"{format_bytes(bucket.bytes)} / {format_count(bucket.records)} rec",
            alt=index % 2 == 1,
        )
        for index, bucket in enumerate(shown)
    )
    hidden = len(buckets) - len(shown)
    note = (
        f'<p class="muted">Showing the first {len(shown)} of {len(buckets)} '
        f"buckets of {analysis.bucket_seconds} s.</p>"
        if hidden > 0
        else ""
    )
    return f'<section id="timeline"><h2>Timeline</h2>{note}{bars}</section>'


def _render_notes(warnings: list[str]) -> str:
    items = [html.escape(warning) for warning in warnings]
    if not items:
        items.append("No decoder warnings were reported.")
    return (
        '<section id="notes"><h2>Decoder notes</h2>'
        f'<ul class="notes">{"".join(f"<li>{item}</li>" for item in items)}</ul>'
        "</section>"
    )


def render_text(
    analysis: FlowAnalysis,
    *,
    source: str,
    format_label: str,
    warnings: list[str] | None = None,
    top: int = 10,
) -> str:
    """Render the analysis as plain text tables."""
    summary = analysis.summary
    lines = [
        f"Source: {source} ({format_label})",
        f"Records: {format_count(summary.records)}, bytes: {format_count(summary.bytes)}, "
        f"packets: {format_count(summary.packets)}, "
        f"duration: {format_duration_ms(summary.duration_ms)}",
        f"Average throughput: {format_bit_rate(summary.avg_bytes_per_second * 8)}, "
        f"{summary.avg_packets_per_second:.1f} pkt/s",
        f"Exporters: {', '.join(summary.exporters) or 'none'}",
        "",
        "Top sources",
        f"{'Address':<40}{'Bytes':>12}{'Packets':>10}{'Records':>9}",
        "-" * 71,
    ]
    if summary.start_ms is not None and summary.end_ms is not None:
        lines.insert(
            2,
            f"Time span: {format_timestamp_ms(summary.start_ms)} to "
            f"{format_timestamp_ms(summary.end_ms)}",
        )
    for talker in analysis.top_sources(top):
        lines.append(
            f"{talker.address:<40}{format_count(talker.bytes):>12}"
            f"{format_count(talker.packets):>10}{format_count(talker.records):>9}"
        )
    lines.extend(
        [
            "",
            "Top destinations",
            f"{'Address':<40}{'Bytes':>12}{'Packets':>10}{'Records':>9}",
            "-" * 71,
        ]
    )
    for talker in analysis.top_destinations(top):
        lines.append(
            f"{talker.address:<40}{format_count(talker.bytes):>12}"
            f"{format_count(talker.packets):>10}{format_count(talker.records):>9}"
        )
    lines.extend(
        [
            "",
            "Top conversations",
            f"{'Protocol':<9}{'Service':<10}{'Endpoint A':<26}{'Endpoint B':<26}"
            f"{'Bytes':>11}{'Packets':>9}",
            "-" * 93,
        ]
    )
    for conversation in analysis.conversations(top):
        lines.append(
            f"{conversation.protocol_name:<9}{conversation.service:<10}"
            f"{conversation.endpoint_a.label:<26}{conversation.endpoint_b.label:<26}"
            f"{format_count(conversation.bytes_total):>11}"
            f"{format_count(conversation.packets_total):>9}"
        )
    lines.extend(["", "Protocol mix", f"{'Protocol':<14}{'Bytes':>12}{'Records':>9}", "-" * 35])
    for stat in analysis.protocol_distribution():
        lines.append(
            f"{stat.name:<14}{format_count(stat.bytes):>12}{format_count(stat.records):>9}"
        )
    lines.extend(
        [
            "",
            f"Timeline ({analysis.bucket_seconds} s buckets)",
            f"{'Bucket start (UTC)':<26}{'Bytes':>12}{'Packets':>10}{'Records':>9}",
            "-" * 57,
        ]
    )
    for bucket in analysis.timeline():
        lines.append(
            f"{format_timestamp_ms(bucket.start_ms):<26}"
            f"{format_count(bucket.bytes):>12}{format_count(bucket.packets):>10}"
            f"{format_count(bucket.records):>9}"
        )
    if warnings:
        lines.extend(["", "Decoder warnings"])
        lines.extend(f"- {warning}" for warning in warnings)
    return "\n".join(lines) + "\n"
