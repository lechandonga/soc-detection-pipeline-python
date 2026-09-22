"""Core domain data models.

Timestamps inside the pipeline are always UTC epoch seconds (``float``).
Raw payloads are converted to normalized :class:`Event` instances once, at
intake, so every downstream component can trust the field set.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# ----------------------------------------------------------------- constants
# The normalized schema every event is mapped onto. Rules may only reference
# fields from this set (plus the ``raw`` map of source-specific extras).
EVENT_FIELDS: frozenset[str] = frozenset({
    "id", "source", "event_type", "severity", "ts",
    "src_ip", "dst_ip", "user", "host", "action",
})

# Recognized ingestion sources. Events whose source is not in this set are
# rejected with ``unknown_source`` rather than silently accepted.
KNOWN_SOURCES: frozenset[str] = frozenset({
    "firewall", "ids", "edr", "auth", "webproxy", "anti_virus",
})

VALID_SEVERITIES: frozenset[str] = frozenset(
    {"info", "low", "medium", "high", "critical"})


class IngestStatus(str, Enum):
    """Deterministic conclusion for every intake attempt."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    # The event was valid but arrived beyond the allowed lateness horizon; it
    # is journaled for an auditable, reproducible conclusion but never changes
    # any detection conclusion.
    TOO_LATE = "too_late"


@dataclass(frozen=True)
class Event:
    """A normalized security event.

    ``seq`` is the monotonic ingestion sequence number, used as the total
    tie-breaker (together with ``ts`` and ``id``) so that detection is
    independent of thread scheduling.
    """

    id: str
    source: str
    event_type: str
    severity: str
    ts: float
    seq: int = -1
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    host: str | None = None
    action: str | None = None
    raw: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | float | None:
        """Read a normalized field (or a raw extra) by name."""
        if name in EVENT_FIELDS:
            return getattr(self, name)
        return self.raw.get(name)

    def to_dict(self) -> dict:
        data = {
            "id": self.id,
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity,
            "ts": self.ts,
            "seq": self.seq,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "user": self.user,
            "host": self.host,
            "action": self.action,
        }
        if self.raw:
            data["raw"] = dict(self.raw)
        return data
