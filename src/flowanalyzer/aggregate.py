"""Traffic aggregation for decoded flow records.

The analysis groups records by source, by destination, by bidirectional
conversation, by protocol and by time bucket.  Conversations are canonical: the
two endpoints are sorted, so both directions of the same 5-tuple merge into one
entry regardless of the order in which records were exported.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .model import FlowExport, FlowRecord, protocol_name

DEFAULT_BUCKET_SECONDS = 60

SERVICE_PORTS: dict[int, str] = {
    22: "ssh",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    389: "ldap",
    443: "https",
    445: "smb",
    514: "syslog",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5432: "postgresql",
    8080: "http-alt",
    8443: "https-alt",
}


def service_name(protocol: int, src_port: int, dst_port: int) -> str:
    """Return the service name for a flow, preferring the well-known port."""
    for port in (dst_port, src_port):
        name = SERVICE_PORTS.get(port)
        if name is not None:
            return name
    return "unknown"


@dataclass(frozen=True, order=True)
class Endpoint:
    """One conversation endpoint (address plus port)."""

    address: str
    port: int

    @property
    def label(self) -> str:
        """Return the endpoint as a display string."""
        if not self.address:
            return "-"
        if ":" in self.address:
            return f"[{self.address}]:{self.port}"
        return f"{self.address}:{self.port}"


def endpoint_of(record: FlowRecord, *, source: bool) -> Endpoint:
    """Return the source or destination endpoint of a record."""
    if source:
        return Endpoint(record.src_ip, record.src_port)
    return Endpoint(record.dst_ip, record.dst_port)


@dataclass
class Talker:
    """Aggregated traffic for one IP address."""

    address: str
    bytes: int = 0
    packets: int = 0
    records: int = 0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return {
            "address": self.address,
            "bytes": self.bytes,
            "packets": self.packets,
            "records": self.records,
        }


@dataclass
class Conversation:
    """A bidirectional 5-tuple conversation."""

    protocol: int
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    records: int = 0
    start_ms: int = 0
    end_ms: int = 0

    @property
    def protocol_name(self) -> str:
        """Return the human name of the IP protocol."""
        return protocol_name(self.protocol)

    @property
    def service(self) -> str:
        """Return the service name derived from the well-known ports."""
        return service_name(self.protocol, self.endpoint_a.port, self.endpoint_b.port)

    @property
    def bytes_total(self) -> int:
        """Return the bytes exchanged in both directions."""
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def packets_total(self) -> int:
        """Return the packets exchanged in both directions."""
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def duration_ms(self) -> int:
        """Return the conversation duration in milliseconds."""
        return max(0, self.end_ms - self.start_ms)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return {
            "protocol": self.protocol,
            "protocol_name": self.protocol_name,
            "service": self.service,
            "endpoint_a": self.endpoint_a.label,
            "endpoint_b": self.endpoint_b.label,
            "bytes_a_to_b": self.bytes_a_to_b,
            "bytes_b_to_a": self.bytes_b_to_a,
            "bytes_total": self.bytes_total,
            "packets_a_to_b": self.packets_a_to_b,
            "packets_b_to_a": self.packets_b_to_a,
            "packets_total": self.packets_total,
            "records": self.records,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "duration_ms": self.duration_ms,
        }


@dataclass
class ProtocolStat:
    """Aggregated traffic for one IP protocol number."""

    protocol: int
    name: str
    bytes: int = 0
    packets: int = 0
    records: int = 0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return {
            "protocol": self.protocol,
            "name": self.name,
            "bytes": self.bytes,
            "packets": self.packets,
            "records": self.records,
        }


@dataclass
class TimeBucket:
    """Traffic totals inside one time bucket of the timeline."""

    start_ms: int
    end_ms: int
    bytes: int = 0
    packets: int = 0
    records: int = 0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return {
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "bytes": self.bytes,
            "packets": self.packets,
            "records": self.records,
        }


@dataclass
class TrafficSummary:
    """Aggregate statistics for one set of flow records."""

    records: int
    exporters: list[str]
    bytes: int
    packets: int
    start_ms: int | None
    end_ms: int | None
    duration_ms: int
    bucket_seconds: int
    avg_bytes_per_second: float
    avg_packets_per_second: float

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return {
            "records": self.records,
            "exporters": list(self.exporters),
            "bytes": self.bytes,
            "packets": self.packets,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "duration_ms": self.duration_ms,
            "bucket_seconds": self.bucket_seconds,
            "avg_bytes_per_second": self.avg_bytes_per_second,
            "avg_packets_per_second": self.avg_packets_per_second,
        }


def _limit(items: list, limit: int | None) -> list:
    """Apply ``limit`` where 0 or None means "everything"."""
    if not limit:
        return list(items)
    return list(items[:limit])


class FlowAnalysis:
    """Everything derived from a list of decoded flow records."""

    def __init__(
        self,
        records: Iterable[FlowRecord],
        *,
        bucket_seconds: int = DEFAULT_BUCKET_SECONDS,
    ) -> None:
        if bucket_seconds < 1:
            raise ValueError("bucket_seconds must be at least 1")
        self.records: list[FlowRecord] = list(records)
        self.bucket_seconds = bucket_seconds
        self._sources = self._aggregate_addresses(source=True)
        self._destinations = self._aggregate_addresses(source=False)
        self._conversations = self._build_conversations()
        self._protocols = self._build_protocols()
        self._timeline = self._build_timeline()
        self.summary = self._build_summary()

    def _aggregate_addresses(self, *, source: bool) -> list[Talker]:
        """Aggregate bytes and packets per source or destination address."""
        talkers: dict[str, Talker] = {}
        for record in self.records:
            endpoint = endpoint_of(record, source=source)
            talker = talkers.get(endpoint.address)
            if talker is None:
                talker = talkers[endpoint.address] = Talker(address=endpoint.address)
            talker.bytes += record.bytes
            talker.packets += record.packets
            talker.records += 1
        return sorted(talkers.values(), key=lambda item: (-item.bytes, -item.packets, item.address))

    def _build_conversations(self) -> list[Conversation]:
        """Merge records into canonical bidirectional conversations."""
        conversations: dict[tuple[int, Endpoint, Endpoint], Conversation] = {}
        for record in self.records:
            source = endpoint_of(record, source=True)
            destination = endpoint_of(record, source=False)
            endpoint_a, endpoint_b = sorted((source, destination))
            key = (record.protocol, endpoint_a, endpoint_b)
            conversation = conversations.get(key)
            if conversation is None:
                conversation = conversations[key] = Conversation(
                    protocol=record.protocol,
                    endpoint_a=endpoint_a,
                    endpoint_b=endpoint_b,
                    start_ms=record.start_ms,
                    end_ms=record.end_ms,
                )
            conversation.records += 1
            if source == endpoint_a:
                conversation.bytes_a_to_b += record.bytes
                conversation.packets_a_to_b += record.packets
            else:
                conversation.bytes_b_to_a += record.bytes
                conversation.packets_b_to_a += record.packets
            conversation.start_ms = min(conversation.start_ms, record.start_ms)
            conversation.end_ms = max(conversation.end_ms, record.end_ms)
        return sorted(
            conversations.values(),
            key=lambda item: (
                -item.bytes_total,
                -item.packets_total,
                item.protocol,
                item.endpoint_a.label,
                item.endpoint_b.label,
            ),
        )

    def _build_protocols(self) -> list[ProtocolStat]:
        """Aggregate traffic per IP protocol number."""
        stats: dict[int, ProtocolStat] = {}
        for record in self.records:
            stat = stats.get(record.protocol)
            if stat is None:
                stat = stats[record.protocol] = ProtocolStat(
                    protocol=record.protocol,
                    name=protocol_name(record.protocol),
                )
            stat.bytes += record.bytes
            stat.packets += record.packets
            stat.records += 1
        return sorted(
            stats.values(),
            key=lambda item: (-item.bytes, -item.records, item.protocol),
        )

    def _build_timeline(self) -> list[TimeBucket]:
        """Bucket records by their start time, covering min start to max end."""
        if not self.records:
            return []
        bucket_ms = self.bucket_seconds * 1000
        first_start = min(record.start_ms for record in self.records)
        last_end = max(record.end_ms for record in self.records)
        bucket_count = (last_end - first_start) // bucket_ms + 1
        buckets = [
            TimeBucket(
                start_ms=first_start + index * bucket_ms,
                end_ms=first_start + (index + 1) * bucket_ms,
            )
            for index in range(bucket_count)
        ]
        for record in self.records:
            index = (record.start_ms - first_start) // bucket_ms
            bucket = buckets[index]
            bucket.bytes += record.bytes
            bucket.packets += record.packets
            bucket.records += 1
        return buckets

    def _build_summary(self) -> TrafficSummary:
        """Compute the overall summary."""
        total_bytes = sum(record.bytes for record in self.records)
        total_packets = sum(record.packets for record in self.records)
        starts = [record.start_ms for record in self.records]
        ends = [record.end_ms for record in self.records]
        start_ms = min(starts) if starts else None
        end_ms = max(ends) if ends else None
        duration_ms = (end_ms - start_ms) if start_ms is not None and end_ms is not None else 0
        duration_seconds = duration_ms / 1000
        exporters = sorted({record.exporter for record in self.records})
        return TrafficSummary(
            records=len(self.records),
            exporters=exporters,
            bytes=total_bytes,
            packets=total_packets,
            start_ms=start_ms,
            end_ms=end_ms,
            duration_ms=duration_ms,
            bucket_seconds=self.bucket_seconds,
            avg_bytes_per_second=(
                total_bytes / duration_seconds if duration_seconds > 0 else 0.0
            ),
            avg_packets_per_second=(
                total_packets / duration_seconds if duration_seconds > 0 else 0.0
            ),
        )

    def top_sources(self, limit: int = 10) -> list[Talker]:
        """Return the busiest source addresses."""
        return _limit(self._sources, limit)

    def top_destinations(self, limit: int = 10) -> list[Talker]:
        """Return the busiest destination addresses."""
        return _limit(self._destinations, limit)

    def conversations(self, limit: int | None = None) -> list[Conversation]:
        """Return conversations sorted by total bytes."""
        return _limit(self._conversations, limit)

    def protocol_distribution(self) -> list[ProtocolStat]:
        """Return per-protocol totals sorted by bytes."""
        return list(self._protocols)

    def timeline(self) -> list[TimeBucket]:
        """Return the time buckets covering the capture window."""
        return list(self._timeline)

    def to_dict(self, *, top: int = 10) -> dict[str, object]:
        """Return a JSON-friendly analysis document."""
        return {
            "summary": self.summary.to_dict(),
            "top_sources": [item.to_dict() for item in self.top_sources(top)],
            "top_destinations": [item.to_dict() for item in self.top_destinations(top)],
            "conversations": [item.to_dict() for item in self.conversations(top)],
            "protocols": [item.to_dict() for item in self.protocol_distribution()],
            "timeline": [item.to_dict() for item in self.timeline()],
        }


def analyze(
    source: FlowExport | Iterable[FlowRecord],
    *,
    bucket_seconds: int = DEFAULT_BUCKET_SECONDS,
) -> FlowAnalysis:
    """Analyse a decoded export or a list of flow records."""
    if isinstance(source, FlowExport):
        return FlowAnalysis(source.records, bucket_seconds=bucket_seconds)
    return FlowAnalysis(source, bucket_seconds=bucket_seconds)
