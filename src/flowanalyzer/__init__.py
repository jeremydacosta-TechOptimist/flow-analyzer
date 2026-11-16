"""flowanalyzer - offline NetFlow v5/v9 and IPFIX decoder and traffic analyzer.

Public API summary::

    from flowanalyzer import read_export, analyze, render_html

    export = read_export("export.bin")
    analysis = analyze(export)
    print(analysis.summary.bytes)

The package has no third-party runtime dependencies; every decoder is
implemented with the Python standard library.
"""

from .aggregate import FlowAnalysis, analyze
from .errors import FlowError
from .generate import generate_bytes, write_export
from .model import FlowExport, FlowRecord
from .netflow.reader import decode_export, read_export
from .report import render_html, render_text
from .sampling import SamplingConfig, normalize_interval
from .version import __version__

__all__ = [
    "FlowAnalysis",
    "FlowError",
    "FlowExport",
    "FlowRecord",
    "SamplingConfig",
    "__version__",
    "analyze",
    "decode_export",
    "generate_bytes",
    "normalize_interval",
    "read_export",
    "render_html",
    "render_text",
    "write_export",
]
