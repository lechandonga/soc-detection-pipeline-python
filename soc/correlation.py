"""Deterministic windowed correlation.

Given all accepted events for a (rule, group) lane, detection is a *pure
function* of the sorted event list, which makes conclusions:

* independent of arrival order (out-of-order events),
* independent of call timing / thread scheduling,
* identical under replay (a replayed stream yields identical match keys),
* stable at window boundaries (``start <= t < start + window``),
* and exactly-once (each conclusion has a stable ``match_key``).

Threshold rule
--------------
A left pointer scans the events in timestamp order; whenever the window
``[e[i].ts, e[i].ts + window)`` contains >= ``count`` events, a firing is
recorded whose basis is the first ``count`` events of that window. The
pointer then advances to the event right after the *first* basis event, so
overlapping greedy firings are distinct but never re-counted events of a
recorded firing.

Sequence rule
-------------
Greedy non-overlapping matching of the ordered steps inside a window: each
consumed event belongs to at most one firing. Every firing's match_key is
derived from the basis event ids (hash), so the same events always produce
the same conclusion.

Late events
-----------
The caller decides whether an event is ``too_late`` (beyond
``max_ts - window - allowed_lateness``). Such events are journaled but never
passed here, giving them a fixed, reproducible conclusion.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from soc.alerts import Evidence
from soc.models import Event
from soc.rules import Rule


@dataclass(frozen=True)
class Firing:
    rule_id: str
    rule_version: int
    group_key: str
    window_seconds: float
    events: tuple[Event, ...]

    @property
    def match_key(self) -> str:
        # Stable across processes: rule + lane + ordered basis event ids.
        basis = ",".join(e.id for e in self.events)
        digest = hashlib.sha256(
            f"{self.rule_id}|{self.group_key}|{basis}".encode()).hexdigest()
        return f"{self.rule_id}:{self.group_key}:{digest[:16]}"

    def evidence(self) -> Evidence:
        return Evidence(
            rule_id=self.rule_id, rule_version=self.rule_version,
            group_key=self.group_key, window_seconds=self.window_seconds,
            event_ids=tuple(e.id for e in self.events),
            basis=tuple(sorted((e.ts, e.seq) for e in self.events)))


def _sorted_events(events: list[Event]) -> list[Event]:
    # Total order: event time first, ingestion sequence as tie-breaker.
    # Defence in depth: identical ids collapse to the first ingestion copy so
    # a duplicate can never be counted twice even if it reached the engine.
    ordered = sorted(events, key=lambda e: (e.ts, e.seq, e.id))
    seen: set[str] = set()
    unique: list[Event] = []
    for event in ordered:
        if event.id in seen:
            continue
        seen.add(event.id)
        unique.append(event)
    return unique


def _threshold_firings(rule: Rule, window: float, version: int,
                       group_key: str,
                       events: list[Event]) -> list[Firing]:
    ordered = _sorted_events(events)
    firings: list[Firing] = []
    n, count = len(ordered), rule.count
    i = 0
    while i + count <= n:
        start = ordered[i].ts
        # collect events in the half-open window [start, start+window)
        basis: list[Event] = []
        j = i
        while j < n and ordered[j].ts < start + window:
            basis.append(ordered[j])
            j += 1
        if len(basis) >= count:
            fired = tuple(basis[:count])
            firings.append(Firing(rule.id, version, group_key, window, fired))
            # advance past the first event of the recorded basis so the same
            # event cannot anchor two conclusions; subsequent events may
            # legitimately form a new firing (sliding, non-overlapping basis).
            i = ordered.index(fired[0]) + 1
        else:
            i += 1
    return firings


def _sequence_firings(rule: Rule, window: float, version: int,
                      group_key: str,
                      events: list[Event]) -> list[Firing]:
    ordered = _sorted_events(events)
    steps = rule.steps
    firings: list[Firing] = []
    used: set[str] = set()
    i, n = 0, len(ordered)
    while i < n:
        first = ordered[i]
        if first.id in used or not _step_match(rule, steps[0], first):
            i += 1
            continue
        # greedily consume subsequent steps within the time window
        chain = [first]
        step_idx = 1
        j = i + 1
        while j < n and step_idx < len(steps):
            cand = ordered[j]
            if cand.ts - first.ts >= window:
                break  # half-open window boundary; later events cannot fit
            if cand.id not in used and _step_match(rule, steps[step_idx], cand):
                chain.append(cand)
                step_idx += 1
            j += 1
        if step_idx == len(steps):
            firings.append(
                Firing(rule.id, version, group_key, window, tuple(chain)))
            used.update(e.id for e in chain)
            i = j
        else:
            i += 1
    return firings


def _step_match(rule: Rule, step_filters: tuple, event: Event) -> bool:
    # event must satisfy the rule-wide filters and this step's filters
    return (rule.matches_filters(event)
            and all(f.matches(event) for f in step_filters))


def detect(rule: Rule, group_key: str, events: list[Event], *,
           version: int, default_window: float) -> list[Firing]:
    """Pure detection for one rule/group lane."""
    if not rule.enabled or not events:
        return []
    window = rule.effective_window(default_window)
    if rule.kind == "threshold":
        return _threshold_firings(rule, window, version, group_key, events)
    return _sequence_firings(rule, window, version, group_key, events)
