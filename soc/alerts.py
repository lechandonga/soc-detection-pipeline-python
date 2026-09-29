"""Alert model, lifecycle state machine and suppression config.

Lifecycle::

    OPEN ──acknowledge──▶ ACKNOWLEDGED ──resolve──▶ RESOLVED
      │                      │                        │
      │                   unack                    reopen
      ▼                      ▼                        ▼
    OPEN ◀──────────────────┘                      OPEN
      └──suppress──▶ SUPPRESSED ──unsuppress──▶ OPEN
      └──resolve──▶ RESOLVED ──reopen──▶ OPEN
    any non-RESOLVED ──close──▶ CLOSED
    RESOLVED ──close──▶ CLOSED
    CLOSED is terminal.

Illegal transitions raise :class:`InvalidStateTransitionError` with a
distinct reason; repeated recovery (resolve) / close of the same alert is
idempotent so replaying an event stream never produces contradictory state.

Rule retirement
---------------
Deleting a rule or flipping its ``enabled`` flag off *retires* it. Every
alert the retired rule ever produced is then concluded with the
``rule_retire`` action into CLOSED with reason ``rule_retired``; the
history detail distinguishes ``deleted`` from ``disabled``. This is a
retirement conclusion, not a human close, and the two stay distinguishable
in the audit trail. It is terminal/idempotent and never reopens or appends
duplicate records; alerts a human already closed stay exactly as they were.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from soc.errors import InvalidRuleError, InvalidStateTransitionError
from soc.rules import Filter


class AlertState(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    CLOSED = "closed"


# action -> states from which the action is legal
TRANSITIONS: dict[str, frozenset[AlertState]] = {
    "acknowledge": frozenset({AlertState.OPEN}),
    "unacknowledge": frozenset({AlertState.ACKNOWLEDGED}),
    "resolve": frozenset({AlertState.OPEN, AlertState.ACKNOWLEDGED}),
    "reopen": frozenset({AlertState.RESOLVED}),
    "suppress": frozenset({AlertState.OPEN, AlertState.ACKNOWLEDGED}),
    "unsuppress": frozenset({AlertState.SUPPRESSED}),
    "close": frozenset({AlertState.OPEN, AlertState.ACKNOWLEDGED,
                        AlertState.SUPPRESSED, AlertState.RESOLVED}),
    # System action emitted when the producing rule is retired.
    "rule_retire": frozenset({AlertState.OPEN, AlertState.ACKNOWLEDGED,
                              AlertState.SUPPRESSED, AlertState.RESOLVED}),
}

# Stable reason recorded on retirement conclusions, kept distinct from a
# human-entered close reason.
RETIRE_REASON = "rule_retired"


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    rule_version: int
    group_key: str
    window_seconds: float
    event_ids: tuple[str, ...]
    # sorted (ts, seq) of the participating events: reproducible basis
    basis: tuple[tuple[float, int], ...]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "group_key": self.group_key,
            "window_seconds": self.window_seconds,
            "event_ids": list(self.event_ids),
            "basis": [[ts, seq] for ts, seq in self.basis],
        }


@dataclass(frozen=True)
class Suppression:
    """When ``when`` filters all match, matching alerts are suppressed."""

    id: str
    when: tuple[Filter, ...]

    @classmethod
    def from_dict(cls, data: Any) -> "Suppression":
        if not isinstance(data, dict) or "id" not in data:
            raise InvalidRuleError("suppression requires an id")
        raw = data.get("when", [])
        if not isinstance(raw, list) or not raw:
            raise InvalidRuleError(
                "suppression requires a non-empty 'when' filter list",
                details={"id": data["id"]})
        return cls(id=str(data["id"]),
                   when=tuple(Filter.from_dict(f) for f in raw))

    def matches(self, alert: "Alert") -> bool:
        # Filters run against the triggering (first/last) event represented in
        # evidence; the engine attaches a representative event for this check.
        event = alert.representative_event
        return event is not None and all(f.matches(event) for f in self.when)

    def to_dict(self) -> dict:
        return {"id": self.id, "when": [f.to_dict() for f in self.when]}


@dataclass
class Alert:
    """A correlated detection conclusion with its full audit trail."""

    id: str                     # deterministic: hash of dedup key + basis
    dedup_key: str              # rule_id + group_key (one alert per lane)
    rule_id: str
    severity: str
    state: AlertState
    created_ts: float
    updated_ts: float
    event_count: int = 1        # total correlated events (dedup-safe)
    occurrences: int = 1        # number of times the condition fired
    evidence: list[Evidence] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)
    enrichment: dict = field(default_factory=dict)
    suppressed_by: str | None = None
    # representative triggering event for suppression / explainability
    representative_event: Any = field(default=None, compare=False)
    # when this lane became RESOLVED (kept for coherent reopen/close)
    resolved_ts: float | None = None
    # How the alert reached CLOSED: "manual" (human close) or
    # "rule_retire" (producing rule retired); None while not closed.
    closed_by: str | None = None
    # Retirement detail: "deleted" or "disabled" ("" for a manual close).
    closure_detail: str = ""

    # ----------------------------------------------------- lifecycle
    def transition(self, action: str, *, ts: float,
                   reason: str = "") -> None:
        current = self.state
        # idempotent no-ops for repeated recovery / close
        if action == "resolve" and current is AlertState.RESOLVED:
            return
        if action == "close" and current is AlertState.CLOSED:
            return
        # Retirement is idempotent on every terminal alert: a human close or
        # a prior retirement both win over a repeated retirement command,
        # and no contradictory history record is appended.
        if action == "rule_retire" and current is AlertState.CLOSED:
            return
        if action not in TRANSITIONS:
            raise InvalidStateTransitionError(
                f"unknown lifecycle action '{action}'",
                details={"alert_id": self.id, "action": action})
        if current not in TRANSITIONS[action]:
            raise InvalidStateTransitionError(
                f"cannot {action} an alert in state {current.value}",
                details={"alert_id": self.id, "action": action,
                         "current_state": current.value,
                         "allowed_from": sorted(s.value
                                                for s in TRANSITIONS[action])})
        new_state = {
            "acknowledge": AlertState.ACKNOWLEDGED,
            "unacknowledge": AlertState.OPEN,
            "resolve": AlertState.RESOLVED,
            "reopen": AlertState.OPEN,
            "suppress": AlertState.SUPPRESSED,
            "unsuppress": AlertState.OPEN,
            "close": AlertState.CLOSED,
            "rule_retire": AlertState.CLOSED,
        }[action]
        self.state = new_state
        self.updated_ts = ts
        if action == "resolve":
            self.resolved_ts = ts
        elif action == "reopen":
            self.resolved_ts = None
        if action == "rule_retire":
            self.closed_by = "rule_retire"
            self.closure_detail = reason or self.closure_detail
        elif action == "close":
            self.closed_by = self.closed_by or "manual"
        if action == "suppress":
            self.suppressed_by = reason or self.suppressed_by
        elif action == "unsuppress":
            self.suppressed_by = None
        self.history.append({"action": action, "ts": ts,
                             "from": current.value, "to": new_state.value,
                             "reason": reason})

    # ----------------------------------------------------- correlation
    def record_occurrence(self, evidence: Evidence, event: Any,
                          *, ts: float) -> None:
        """Merge another firing into the same lane (no duplicate alert)."""
        self.occurrences += 1
        self.evidence.append(evidence)
        self.event_count += len(evidence.event_ids)
        self.updated_ts = ts
        self.representative_event = event

    def to_dict(self, *, include_event: bool = False) -> dict:
        data = {
            "id": self.id, "dedup_key": self.dedup_key,
            "rule_id": self.rule_id, "severity": self.severity,
            "state": self.state.value, "created_ts": self.created_ts,
            "updated_ts": self.updated_ts,
            "event_count": self.event_count,
            "occurrences": self.occurrences,
            "suppressed_by": self.suppressed_by,
            "resolved_ts": self.resolved_ts,
            "closed_by": self.closed_by,
            "closure_detail": self.closure_detail,
            "evidence": [e.to_dict() for e in self.evidence],
            "history": list(self.history),
            "enrichment": dict(self.enrichment),
        }
        if include_event and self.representative_event is not None:
            data["representative_event"] = self.representative_event.to_dict()
        return data
