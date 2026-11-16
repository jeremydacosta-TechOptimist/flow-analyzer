"""Exceptions raised by flowanalyzer.

The decoders raise :class:`FlowError` for exports that cannot be decoded at
all (bad header, unknown version).  Recoverable problems such as a truncated
data flowset are reported in ``FlowExport.warnings`` instead.
"""


class FlowError(Exception):
    """Raised when a flow export cannot be read or understood."""
