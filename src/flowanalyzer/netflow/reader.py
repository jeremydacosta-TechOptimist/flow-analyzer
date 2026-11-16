"""Format detection and unified reading of NetFlow/IPFIX exports."""

from __future__ import annotations

from pathlib import Path

from ..errors import FlowError
from ..model import FlowExport
from .ipfix import decode_ipfix
from .v5 import decode_v5
from .v9 import decode_v9

DECODERS = {5: decode_v5, 9: decode_v9, 10: decode_ipfix}
SUPPORTED_VERSIONS = tuple(sorted(DECODERS))


def detect_version(data: bytes) -> int:
    """Return the format version from the first two bytes of an export."""
    if len(data) < 2:
        raise FlowError("export is too short to contain a version field")
    return int.from_bytes(data[:2], "big")


def decode_export(data: bytes, exporter: str = "") -> FlowExport:
    """Decode a NetFlow v5, NetFlow v9 or IPFIX v10 export."""
    version = detect_version(data)
    decoder = DECODERS.get(version)
    if decoder is None:
        raise FlowError(
            f"unsupported export format: version {version} "
            "(supported: NetFlow v5, NetFlow v9 and IPFIX v10)"
        )
    return decoder(data, exporter=exporter)


def read_export(path: str | Path, exporter: str | None = None) -> FlowExport:
    """Read and decode one export file.

    ``exporter`` labels the records in the output and defaults to the file name.
    """
    source = Path(path)
    try:
        data = source.read_bytes()
    except OSError as exc:
        raise FlowError(f"cannot read {source.name}: {exc}") from exc
    return decode_export(data, exporter=source.name if exporter is None else exporter)
