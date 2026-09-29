"""Application service: single-threaded, deterministic pipeline core.

Concurrency model
-----------------
One :class:`threading.RLock` guards *all* mutable state. Every public
operation runs fully inside the lock, so concurrent ingestion, rule updates
and alert transitions are serialized into a total order. There are no
cross-request mutable objects outside the lock, hence no torn reads or
cross-talk. The live rule set is an immutable snapshot reference; a rule
reload validates the whole new set before swapping the reference, so an
in-progress detection always sees one complete rule version.

Determinism model
-----------------
Detection is a pure function of ``(rule_version, rule_id, group_key,
sorted events)`` and every firing has a stable ``match_key``. On startup the
service rebuilds from the append-only journals: ingested events are
re-indexed into lanes and the alert command journal (create / transition)
is replayed in order, yielding identical alerts / counts / lifecycle
states - including alerts whose rule has since been retired. Replaying the
same journals a second time changes nothing (ids and match_keys dedupe,
closes are idempotent).

Rule retirement
---------------
Removing a rule from the config or setting ``enabled: false`` retires it:
every non-terminal alert it produced is converged to ``closed`` with
reason ``rule_retired`` (distinguishable from a manual close in the alert
history). The close commands are journaled, so live state, a restart
rebuild and a re-replay of the same journals converge to identical
results. Already-closed alerts are untouched (idempotent), and re-adding
the rule later can never resurrect a retired conclusion: a firing whose
``match_key`` is already known is a no-op regardless of lane state.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Callable

from soc.alerts import Alert, AlertState, Suppression
from soc.config import PipelineConfig
from soc.correlation import Firing, detect
from soc.errors import (
    AlertNotFoundError,
    CapacityExceededError,
    DuplicateEventError,
    DuplicateRuleError,
)
from soc.ingestion import normalize_event
from soc.rules import RuleSet, build_ruleset
from soc.store import Store
from soc.enrichment import LocalIntelProvider

# Close reason recorded when an alert is converged by rule retirement;
# distinguishable from any operator-supplied reason in the alert history.
RULE_RETIRED_REASON = "rule_retired"


class DetectionService:
    def __init__(self, *, config: PipelineConfig | None = None,
                 store: Store | None = None,
                 provider: LocalIntelProvider | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        self.config = config or PipelineConfig()
        self.store = store or Store(None)
        self.provider = provider or LocalIntelProvider()
        self._clock = clock or _default_clock
        self._lock = threading.RLock()

        self.ruleset = RuleSet()
        self.suppressions: dict[str, Suppression] = {}
        self.seq_counter = 0
        self.events_by_id: dict[str, dict] = {}          # id -> event dict
        # rule_id -> group_key -> list[event dicts] (retained, active window)
        self.lanes: dict[str, dict[str, list[dict]]] = defaultdict(
            lambda: defaultdict(list))
        self.too_late_ids: set[str] = set()
        # match_key -> Alert (exact conclusion dedupe across rebuilds)
        self.alerts_by_key: dict[str, Alert] = {}
        # rule_id|group_key -> current alert for the lane
        self.lane_alert: dict[str, Alert] = {}
        self.alert_index: dict[str, Alert] = {}

        self._rebuild()

    # ============================================================ ingest
    def ingest(self, payload: Any) -> dict:
        """Validate -> journal -> state update, atomically under the lock."""
        now = self._clock()
        # Normalize first; rejection raises BEFORE any write.
        from soc.models import Event
        event = normalize_event(payload, now=now, config=self.config)

        with self._lock:
            now = self._clock()
            if event.id in self.events_by_id or event.id in self.too_late_ids:
                raise DuplicateEventError(
                    "event id has already been ingested",
                    details={"event_id": event.id})
            if len(self.events_by_id) >= self.config.max_events:
                raise CapacityExceededError(
                    "maximum retained event count reached",
                    details={"max": self.config.max_events})

            cutoff = self._lateness_cutoff(now)
            if event.ts < cutoff:
                # Deterministic late conclusion: journaled, never correlated.
                record = {"id": event.id, "status": "too_late", "ts": event.ts,
                          "ingested_ts": now, "cutoff": cutoff,
                          "event": event.to_dict()}
                self.store.append_event(record)
                self.too_late_ids.add(event.id)
                return {"id": event.id, "status": "too_late",
                        "reason": "event_ts_before_lateness_cutoff",
                        "cutoff": cutoff, "ts": event.ts}

            seq = self.seq_counter
            self.seq_counter += 1
            stored = Event(**{**event.to_dict(), "seq": seq})

            # Side-effect-free trial run: detect with the event appended to a
            # temporary lane view. If it would create an alert beyond capacity
            # we reject *before* journaling, leaving no partial state.
            trial = self._trial_firings(stored, self.ruleset)
            new_alerts = 0
            for f in trial:
                if f.match_key in self.alerts_by_key:
                    continue  # identical conclusion already exists
                lane = self.lane_alert.get(f"{f.rule_id}|{f.group_key}")
                if lane is None or lane.state is AlertState.CLOSED:
                    new_alerts += 1
            if len(self.alert_index) + new_alerts > self.config.max_alerts:
                self.seq_counter -= 1
                raise CapacityExceededError(
                    "ingestion would exceed the maximum active alert count",
                    details={"max": self.config.max_alerts,
                             "current": len(self.alert_index),
                             "new_alerts": new_alerts})

            # Durable before in-memory commit.
            self.store.append_event(
                {"id": stored.id, "status": "accepted", "ts": stored.ts,
                 "ingested_ts": now, "seq": seq,
                 "rule_version": self.ruleset.version,
                 "event": stored.to_dict()})
            self.events_by_id[stored.id] = stored.to_dict()
            self._index_event(stored, self.ruleset)
            self._run_detection_for_event(stored, self.ruleset)
            return {"id": stored.id, "status": "accepted", "seq": seq,
                    "rule_version": self.ruleset.version}

    def _lateness_cutoff(self, now: float) -> float:
        return now - self.config.window_seconds \
            - self.config.allowed_lateness_seconds

    def _index_event(self, event, ruleset: RuleSet) -> None:
        for rule in ruleset.rules:
            if rule.enabled and rule.matches_filters(event):
                self.lanes[rule.id][rule.group_key(event)].append(
                    event.to_dict())

    def _trial_firings(self, event, ruleset: RuleSet) -> list:
        """Run detection as if ``event`` were appended; no mutation."""
        from soc.models import Event
        results: list = []
        for rule in ruleset.rules:
            if not rule.enabled or not rule.matches_filters(event):
                continue
            key = rule.group_key(event)
            evs = [Event(**d) for d in self.lanes[rule.id].get(key, [])]
            evs.append(event)
            if len(evs) > self.config.max_group_scan:
                evs = sorted(evs, key=lambda e: (e.ts, e.seq))[
                    -self.config.max_group_scan:]
            results.extend(detect(rule, key, evs,
                                  version=ruleset.version,
                                  default_window=self.config.window_seconds))
        return results

    def _prune_lanes(self, ruleset: RuleSet, cutoff: float) -> None:
        """Drop events that can no longer fall inside any active window.

        Pruning is purely an optimization: removed events are older than
        ``cutoff`` and by definition cannot be part of a present or future
        firing, so conclusions never change.
        """
        for rule_id, groups in list(self.lanes.items()):
            for key, evs in list(groups.items()):
                kept = [e for e in evs if e["ts"] >= cutoff]
                if kept:
                    groups[key] = kept
                else:
                    del groups[key]

    # ========================================================== detection
    def _run_detection_for_event(self, event, ruleset: RuleSet) -> None:
        from soc.models import Event
        for rule in ruleset.rules:
            if not rule.enabled or not rule.matches_filters(event):
                continue
            key = rule.group_key(event)
            evs = [Event(**d) for d in self.lanes[rule.id][key]]
            if len(evs) > self.config.max_group_scan:
                # Degrade deterministically: oldest events are dropped.
                evs = sorted(evs, key=lambda e: (e.ts, e.seq))[-self.config.max_group_scan:]
            for firing in detect(rule, key, evs, version=ruleset.version,
                                 default_window=self.config.window_seconds):
                self._record_firing(firing, ruleset)

    def _run_all_detection(self, ruleset: RuleSet, *,
                           persist: bool = True) -> None:
        """Recompute all lanes (rule reload or rebuild)."""
        from soc.models import Event
        for rule in ruleset.rules:
            if not rule.enabled:
                continue
            for key, dicts in self.lanes.get(rule.id, {}).items():
                evs = [Event(**d) for d in dicts]
                for firing in detect(rule, key, evs,
                                     version=ruleset.version,
                                     default_window=self.config.window_seconds):
                    self._record_firing(firing, ruleset)

    def _record_firing(self, firing: Firing, ruleset: RuleSet) -> Alert:
        """Integrate one firing: exact dedupe by match_key, one alert/lane."""
        from soc.enrichment import enrich
        rule = ruleset.get(firing.rule_id)
        severity = rule.severity if rule else "medium"
        lane_id = f"{firing.rule_id}|{firing.group_key}"
        known = self.alerts_by_key.get(firing.match_key)
        if known is not None:
            # Identical conclusion already recorded (possibly long closed):
            # never resurrect, never double-count, never re-journal.
            return known
        # Persist the creation decision first (durable, replayable).
        cmd = {"type": "create", "match_key": firing.match_key,
               "lane_id": lane_id, "rule_id": firing.rule_id,
               "severity": severity,
               "rule_version": firing.rule_version,
               "evidence": firing.evidence().to_dict(),
               "ts": firing.events[-1].ts}
        self.store.append_alert_command(cmd)

        rep = firing.events[-1]
        lane_alert = self.lane_alert.get(lane_id)
        if lane_alert is None or lane_alert.state is AlertState.CLOSED:
            alert = Alert(
                id=firing.match_key, dedup_key=lane_id,
                rule_id=firing.rule_id, severity=severity,
                state=AlertState.OPEN, created_ts=firing.events[0].ts,
                updated_ts=firing.events[-1].ts,
                event_count=len(firing.events),
                evidence=[firing.evidence()],
                representative_event=rep)
            enrich(alert, self.provider)
            self._maybe_suppress(alert, ruleset)
            self.alerts_by_key[firing.match_key] = alert
            self.lane_alert[lane_id] = alert
            self.alert_index[alert.id] = alert
            return alert

        # Existing open lane: an identical conclusion is a no-op, otherwise
        # it is a new occurrence merged into the same alert.
        lane_alert.record_occurrence(firing.evidence(), rep,
                                     ts=firing.events[-1].ts)
        self.alerts_by_key[firing.match_key] = lane_alert
        self.alert_index.setdefault(lane_alert.id, lane_alert)
        if lane_alert.state is AlertState.OPEN:
            enrich(lane_alert, self.provider)
            self._maybe_suppress(lane_alert, ruleset)
        return lane_alert

    def _maybe_suppress(self, alert: Alert, ruleset: RuleSet) -> None:
        for suppression in self.suppressions.values():
            try:
                if suppression.matches(alert):
                    cmd = {"type": "transition", "alert_id": alert.id,
                           "action": "suppress", "reason": suppression.id,
                           "ts": alert.updated_ts}
                    self.store.append_alert_command(cmd)
                    alert.transition("suppress", ts=alert.updated_ts,
                                     reason=suppression.id)
                    return
            except Exception:
                # A broken suppression predicate must not take detection down;
                # it is simply not applied (alert stays visible).
                continue

    # ============================================================= rules
    def replace_rules(self, docs: list[dict],
                      suppressions: list[dict] | None = None) -> dict:
        """Validate everything, then atomically swap the live rule snapshot."""
        with self._lock:
            candidate = build_ruleset(docs, version=self.ruleset.version + 1,
                                      max_rules=self.config.max_rules)
            parsed_supp: dict[str, Suppression] = {}
            for doc in suppressions or []:
                supp = Suppression.from_dict(doc)
                if supp.id in parsed_supp:
                    raise DuplicateRuleError(
                        "duplicate suppression id", details={"id": supp.id})
                parsed_supp[supp.id] = supp

            # Rebuild lane index for the new rule definitions from retained
            # events (pure function of events), prune by lateness, then
            # detect under the new immutable snapshot.
            now = self._clock()
            cutoff = self._lateness_cutoff(now)
            retained = [d for d in self.events_by_id.values()
                        if d["ts"] >= cutoff]
            self.lanes = defaultdict(lambda: defaultdict(list))
            from soc.models import Event
            for d in retained:
                self._index_event(Event(**d), candidate)
            self._prune_lanes(candidate, cutoff)

            # Durable config + detection all happen before the swap is
            # observable externally; lock is held throughout.
            self.store.save_rules({"version": candidate.version,
                                   "rules": docs,
                                   "suppressions": suppressions or []})
            retired = self._retired_rule_ids(self.ruleset, candidate)
            self.ruleset = candidate
            self.suppressions = parsed_supp
            self._run_all_detection(candidate)
            if retired:
                self._retire_rules(retired, ts=now)
            return {"version": candidate.version,
                    "rule_count": len(candidate.rules),
                    "suppression_count": len(parsed_supp),
                    "retired_rules": sorted(retired)}

    @staticmethod
    def _retired_rule_ids(old: RuleSet, new: RuleSet) -> set[str]:
        """Rules that were active and are now gone or disabled."""
        was_active = {r.id for r in old.rules if r.enabled}
        is_active = {r.id for r in new.rules if r.enabled}
        return was_active - is_active

    def _retire_rules(self, rule_ids: set[str], *, ts: float) -> None:
        """Converge every non-terminal alert of retired rules to ``closed``.

        The close is journaled (before the in-memory change is observable)
        with reason ``rule_retired`` so rebuilds and replays converge to the
        same conclusion, and so it stays distinguishable from a manual
        close. Already-closed alerts are skipped: retirement is idempotent
        and never drags an alert out of a terminal state or appends a
        contradictory record.
        """
        for rule_id in sorted(rule_ids):
            affected = sorted(
                (a for a in self.alert_index.values()
                 if a.rule_id == rule_id
                 and a.state is not AlertState.CLOSED),
                key=lambda a: (a.created_ts, a.id))
            for alert in affected:
                log_extra = {"rule_id": rule_id}
                cmd = {"type": "transition", "alert_id": alert.id,
                       "action": "close", "reason": RULE_RETIRED_REASON,
                       "ts": ts, "from_state": alert.state.value,
                       **log_extra}
                self.store.append_alert_command(cmd)
                alert.transition("close", ts=ts, reason=RULE_RETIRED_REASON,
                                 details=log_extra)

    # ========================================================== lifecycle
    def transition_alert(self, alert_id: str, action: str,
                         *, reason: str = "") -> dict:
        with self._lock:
            alert = self.alert_index.get(alert_id)
            if alert is None:
                raise AlertNotFoundError("no alert with that id",
                                         details={"alert_id": alert_id})
            ts = self._clock()
            # Persist intent before applying so replay reproduces the refusal
            # boundary identically; illegal transitions raise before either.
            current = alert.state.value
            cmd = {"type": "transition", "alert_id": alert_id,
                   "action": action, "reason": reason, "ts": ts,
                   "from_state": current}
            # transition() validates and raises InvalidStateTransitionError
            # without mutating on refusal.
            alert.transition(action, ts=ts, reason=reason)
            self.store.append_alert_command(cmd)
            return {"alert_id": alert_id, "state": alert.state.value}

    # ============================================================= reads
    def get_alert(self, alert_id: str) -> dict:
        with self._lock:
            alert = self.alert_index.get(alert_id)
            if alert is None:
                raise AlertNotFoundError("no alert with that id",
                                         details={"alert_id": alert_id})
            return alert.to_dict()

    def list_alerts(self, state: str | None = None) -> list[dict]:
        with self._lock:
            alerts = list(self.alert_index.values())
            if state == "all":
                pass  # explicit opt-in to the full inventory
            elif state:
                alerts = [a for a in alerts if a.state.value == state]
            else:
                # Default browsing shows unfinished work only; closed alerts
                # (manual or rule-retirement) remain queryable by id/state.
                alerts = [a for a in alerts
                          if a.state is not AlertState.CLOSED]
            return [a.to_dict() for a in sorted(
                alerts, key=lambda a: (a.created_ts, a.id))]

    def event_status(self, event_id: str) -> dict:
        with self._lock:
            if event_id in self.too_late_ids:
                return {"id": event_id, "status": "too_late"}
            if event_id in self.events_by_id:
                return {"id": event_id, "status": "accepted",
                        "event": self.events_by_id[event_id]}
            return {"id": event_id, "status": "unknown"}

    def rules_snapshot(self) -> dict:
        with self._lock:
            return self.ruleset.to_dict()

    # ============================================================ rebuild
    def _rebuild(self) -> None:
        """Deterministically reconstruct state from journals.

        Events are re-indexed into lanes in their original ingestion order
        (seq) so future detection sees the same windows. Alerts themselves
        are reconstructed purely from the alert command journal (create /
        transition), in journal order: this reproduces the exact live
        conclusions - including alerts whose rule was later retired - with
        identical ids, counts and lifecycle states.
        """
        from soc.models import Event
        raw = self.store.load_rules_raw()
        if raw:
            self.ruleset = build_ruleset(
                raw.get("rules", []), version=raw.get("version", 0),
                max_rules=self.config.max_rules)
            self.suppressions = {
                s.id: s for s in (Suppression.from_dict(d)
                                  for d in raw.get("suppressions", []))}

        accepted: list[dict] = []
        max_seq = -1
        for rec in self.store.read_events():
            if rec["status"] == "too_late":
                self.too_late_ids.add(rec["id"])
                continue
            ev_d = rec["event"]
            max_seq = max(max_seq, ev_d.get("seq", -1))
            self.events_by_id[ev_d["id"]] = ev_d
            accepted.append(ev_d)
        self.seq_counter = max_seq + 1

        for ev_d in sorted(accepted, key=lambda d: d["seq"]):
            event = Event(**ev_d)
            self._index_event(event, self.ruleset)

        for cmd in self.store.read_alert_commands():
            self._replay_command(cmd)

    def _replay_command(self, cmd: dict) -> None:
        ctype = cmd["type"]
        if ctype == "create":
            self._replay_create(cmd)
            return
        if ctype == "transition":
            alert = self.alert_index.get(cmd["alert_id"])
            if alert is None:
                return
            from soc.errors import InvalidStateTransitionError
            details = ({"rule_id": cmd["rule_id"]}
                       if "rule_id" in cmd else None)
            try:
                alert.transition(cmd["action"], ts=cmd["ts"],
                                 reason=cmd.get("reason", ""),
                                 details=details)
            except InvalidStateTransitionError:
                # Already in the target / a terminal state: replaying the
                # journal repeatedly must converge to identical state.
                pass

    def _replay_create(self, cmd: dict) -> None:
        """Materialize one journaled creation decision, mirroring the live
        ``_record_firing`` integration exactly (no journal writes)."""
        from soc.alerts import Evidence
        from soc.enrichment import enrich
        from soc.models import Event
        match_key = cmd["match_key"]
        if match_key in self.alerts_by_key:
            return  # identical conclusion already integrated
        ev = cmd["evidence"]
        evidence = Evidence(
            rule_id=cmd["rule_id"], rule_version=cmd["rule_version"],
            group_key=ev["group_key"], window_seconds=ev["window_seconds"],
            event_ids=tuple(ev["event_ids"]),
            basis=tuple((ts, seq) for ts, seq in ev["basis"]))
        rep_d = self.events_by_id.get(evidence.event_ids[-1])
        rep = Event(**rep_d) if rep_d is not None else None
        lane_id = cmd["lane_id"]
        lane_alert = self.lane_alert.get(lane_id)
        if lane_alert is None or lane_alert.state is AlertState.CLOSED:
            alert = Alert(
                id=match_key, dedup_key=lane_id,
                rule_id=cmd["rule_id"], severity=cmd["severity"],
                state=AlertState.OPEN,
                created_ts=evidence.basis[0][0] if evidence.basis else cmd["ts"],
                updated_ts=cmd["ts"],
                event_count=len(evidence.event_ids),
                evidence=[evidence],
                representative_event=rep)
            enrich(alert, self.provider)
            self.alerts_by_key[match_key] = alert
            self.lane_alert[lane_id] = alert
            self.alert_index[alert.id] = alert
            return
        lane_alert.record_occurrence(evidence, rep, ts=cmd["ts"])
        self.alerts_by_key[match_key] = lane_alert
        self.alert_index.setdefault(lane_alert.id, lane_alert)
        if lane_alert.state is AlertState.OPEN:
            enrich(lane_alert, self.provider)


def _default_clock() -> float:
    import time
    return time.time()
