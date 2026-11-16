"""Sampling helpers shared by the NetFlow v5, v9 and IPFIX decoders.

Sampling lets an exporter report only every Nth packet (or a subset of traffic).
The decoders keep the counters exactly as exported and additionally store the
raw values, so consumers can decide whether to use sampled or estimated
numbers.
"""

from __future__ import annotations

from dataclasses import dataclass

V5_SAMPLING_MODE_MASK = 0xC000
V5_SAMPLING_INTERVAL_MASK = 0x3FFF


@dataclass(frozen=True)
class SamplingConfig:
    """Sampling information attached to an export or a single record."""

    interval: int = 1
    algorithm: int = 0

    @property
    def active(self) -> bool:
        """Return whether the configuration actually scales counters."""
        return self.interval > 1

    def scale(self, raw_bytes: int, raw_packets: int) -> tuple[int, int]:
        """Return the sampled-and-scaled ``(bytes, packets)`` pair."""
        if not self.active:
            return raw_bytes, raw_packets
        return raw_bytes * self.interval, raw_packets * self.interval


def normalize_interval(value: int | None) -> int:
    """Normalise a sampling interval: anything below 2 means "not sampled"."""
    if value is None or value < 2:
        return 1
    return int(value)


def sampling_from_v5_header(raw: int) -> tuple[int, int]:
    """Split the NetFlow v5 header sampling field into ``(mode, interval)``."""
    mode = (raw & V5_SAMPLING_MODE_MASK) >> 14
    interval = raw & V5_SAMPLING_INTERVAL_MASK
    return mode, interval


def interval_from_fields(fields: dict[str, object], default: int = 1) -> int:
    """Return the sampling interval carried by decoded option/data fields."""
    for name in ("SAMPLING_INTERVAL", "SAMPLING_PACKET_INTERVAL"):
        value = fields.get(name)
        if isinstance(value, int):
            return normalize_interval(value)
    return normalize_interval(default)
