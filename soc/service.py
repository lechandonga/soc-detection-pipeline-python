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
service rebuilds from the append-only journals: ingested events replay
through detection and alert commands replay over the resulting alerts,
yielding identical alerts / counts / lifecycle states. Replaying the same
event stream a second time changes nothing (ids and match_keys dedupe).
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

# Alert states considered "still pending work" for the default browse view.
# Alerts closed by a human or by rule retirement are excluded unless the
# caller asks for an explicit state.
PENDING_STATES: frozenset[AlertState] = frozenset({
    AlertState.OPEN, AlertState.ACKNOWLEDGED, AlertState.SUPPRESSED,
    AlertState.RESOLVED,
})


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
                    self._record_firing(firing, ruleset, persist=persist)

    def _record_firing(self, firing: Firing, ruleset: RuleSet,
                       *, persist: bool = True) -> Alert:
        """Integrate one firing: exact dedupe by match_key, one alert/lane."""
        from soc.enrichment import enrich
        rule = ruleset.get(firing.rule_id)
        severity = rule.severity if rule else "medium"
        lane_id = f"{firing.rule_id}|{firing.group_key}"
        if persist:
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
            prior = self.alerts_by_key.get(firing.match_key)
            if prior is not None and prior.state is AlertState.CLOSED:
                # This exact conclusion was already concluded terminally
                # (typically because its rule was retired). Re-enabling a
                # rule must not resurrect it or mint a duplicate alert for
                # the same basis. The closed alert stays the lane's only
                # conclusion; a genuinely new firing has a new match_key.
                return prior
            alert = Alert(
                id=firing.match_key, dedup_key=lane_id,
                rule_id=firing.rule_id, severity=severity,
                state=AlertState.OPEN, created_ts=firing.events[0].ts,
                updated_ts=firing.events[-1].ts,
                event_count=len(firing.events),
                evidence=[firing.evidence()],
                representative_event=rep)
            enrich(alert, self.provider)
            if persist:
                self._maybe_suppress(alert, ruleset)
            self.alerts_by_key[firing.match_key] = alert
            self.lane_alert[lane_id] = alert
            self.alert_index[alert.id] = alert
            return alert

        # Existing open lane: an identical conclusion is a no-op, otherwise
        # it is a new occurrence merged into the same alert.
        if firing.match_key not in self.alerts_by_key:
            lane_alert.record_occurrence(firing.evidence(), rep,
                                         ts=firing.events[-1].ts)
            self.alerts_by_key[firing.match_key] = lane_alert
            self.alert_index.setdefault(lane_alert.id, lane_alert)
            if lane_alert.state is AlertState.OPEN:
                enrich(lane_alert, self.provider)
                if persist:
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
        """Validate everything, then atomically swap and retire withdrawn rules.

        Retirement is part of the same atomic commit: a rule present and
        enabled in the old snapshot but missing (``deleted``) or present with
        ``enabled: false`` (``disabled``) in the new snapshot is retired.
        Every alert it produced is concluded CLOSED with a ``rule_retire``
        history record. Validation of the whole new document set happens
        first, so an invalid configuration is rejected wholesale and no
        retirement conclusion is ever half-applied.
        """
        # Validate BEFORE taking the lock / touching anything; a bad config
        # must leave the previous ruleset and every alert exactly as they
        # were (no half retirement).
        candidate = build_ruleset(docs, version=self.ruleset.version + 1,
                                  max_rules=self.config.max_rules)
        parsed_supp: dict[str, Suppression] = {}
        for doc in suppressions or []:
            supp = Suppression.from_dict(doc)
            if supp.id in parsed_supp:
                raise DuplicateRuleError(
                    "duplicate suppression id", details={"id": supp.id})
            parsed_supp[supp.id] = supp

        with self._lock:
            retired = self._diff_retirements(candidate)

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
            self.ruleset = candidate
            self.suppressions = parsed_supp
            self._run_all_detection(candidate)
            self._retire_alerts(candidate.version, retired)
            return {"version": candidate.version,
                    "rule_count": len(candidate.rules),
                    "suppression_count": len(parsed_supp),
                    "retired_rule_ids": sorted(retired)}

    def _diff_retirements(self, candidate: RuleSet) -> dict[str, str]:
        """rule_id -> 'deleted' | 'disabled' for rules withdrawn now.

        Only a rule that was present *and enabled* in the live snapshot can
        be retired by this commit. A rule that was already disabled stays in
        its previously retired state: re-disabling or keeping it disabled is
        a no-op (no repeated, contradictory retirement records).
        """
        retired: dict[str, str] = {}
        for old in self.ruleset.rules:
            if not old.enabled:
                continue  # already retired in an earlier commit
            new = candidate.get(old.id)
            if new is None:
                retired[old.id] = "deleted"
            elif not new.enabled:
                retired[old.id] = "disabled"
        return retired

    def _retire_alerts(self, rule_version: int,
                       retired: dict[str, str]) -> int:
        """Close every non-terminal alert of each retired rule.

        Terminal alerts (already closed by a human or an earlier retirement)
        are left untouched. Commands are journaled before the in-memory
        change, so restart replay reproduces the exact same conclusions and
        replaying the journal a second time converges identically.
        """
        from soc.alerts import RETIRE_REASON
        closed = 0
        if not retired:
            return closed
        ts = self._clock()
        # Stable order keeps the journal (and any logs) deterministic.
        for alert in sorted(self.alert_index.values(),
                            key=lambda a: (a.created_ts, a.id)):
            detail = retired.get(alert.rule_id)
            if detail is None or alert.state is AlertState.CLOSED:
                continue
            cmd = {"type": "transition", "alert_id": alert.id,
                   "action": "rule_retire", "reason": RETIRE_REASON,
                   "detail": detail, "rule_version": rule_version, "ts": ts,
                   "from_state": alert.state.value}
            self.store.append_alert_command(cmd)
            alert.transition("rule_retire", ts=ts, reason=detail)
            closed += 1
        return closed

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
            if state:
                alerts = [a for a in alerts if a.state.value == state]
            else:
                # Default browse view: only alerts with pending work.
                # Closed alerts (manual close or rule retirement) remain
                # fully fetchable by id or via ?state=closed.
                alerts = [a for a in alerts if a.state in PENDING_STATES]
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

        Events are replayed in their original ingestion order (seq), running
        detection incrementally just like the live path, so every firing is
        regenerated with the same match_key but no journal writes occur. The
        alert command journal is then replayed to restore lifecycle states.
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
            self._run_detection_replay_event(event, self.ruleset)

        # Replay the command journal in a total order. Retirement commands
        # may interleave with human lifecycle commands; ordering by (ts,
        # journal position) preserves the real "who happened first"
        # ordering so the final winner is unique and reproducible.
        commands = list(self.store.read_alert_commands())
        for pos, cmd in enumerate(commands):
            cmd["_pos"] = pos
        commands.sort(key=lambda c: (c["ts"], c["_pos"]))
        for cmd in commands:
            self._replay_command(cmd)

        # Safety net / pure re-derivation: conclusions implied by the final
        # configuration (rules withdrawn) are also recomputed. This is a
        # no-op when the journal is complete and keeps a second replay of
        # the same journals convergent.
        self._rebuild_retirements()

    def _run_detection_replay_event(self, event, ruleset: RuleSet) -> None:
        from soc.models import Event
        for rule in ruleset.rules:
            if not rule.enabled or not rule.matches_filters(event):
                continue
            key = rule.group_key(event)
            evs = [Event(**d) for d in self.lanes[rule.id][key]]
            for firing in detect(rule, key, evs, version=ruleset.version,
                                 default_window=self.config.window_seconds):
                self._record_firing(firing, ruleset, persist=False)

    def _replay_command(self, cmd: dict) -> None:
        ctype = cmd["type"]
        if ctype == "create":
            # Detection regenerates alerts for rules still present in the
            # final snapshot. Alerts of retired (deleted/disabled) rules
            # cannot be regenerated that way, so restore them from their
            # durable create command with CLOSED-immune creation.
            if cmd["match_key"] in self.alerts_by_key:
                return
            self._restore_created_alert(cmd)
            return
        if ctype == "transition":
            alert = self.alert_index.get(cmd["alert_id"])
            if alert is None:
                return
            from soc.errors import InvalidStateTransitionError
            try:
                action = cmd["action"]
                reason = (cmd.get("detail") if action == "rule_retire"
                          else cmd.get("reason", ""))
                alert.transition(action, ts=cmd["ts"], reason=reason)
            except InvalidStateTransitionError:
                # Already in the target / a terminal state: replaying the
                # journal repeatedly must converge to identical state.
                pass

    def _restore_created_alert(self, cmd: dict) -> None:
        """Rebuild an Alert object from a journaled create command."""
        from soc.models import Event
        evidence_d = cmd.get("evidence") or {}
        evidence = self._evidence_from_dict(evidence_d)
        rep = None
        last_id = (evidence.event_ids[-1] if evidence.event_ids else None)
        if last_id is not None and last_id in self.events_by_id:
            rep = Event(**self.events_by_id[last_id])
        created_ts = cmd.get("ts", 0.0)
        alert = Alert(
            id=cmd["match_key"], dedup_key=cmd.get("lane_id",
                                                  f"{cmd['rule_id']}|"),
            rule_id=cmd["rule_id"], severity=cmd.get("severity", "medium"),
            state=AlertState.OPEN, created_ts=created_ts,
            updated_ts=created_ts,
            event_count=len(evidence.event_ids),
            evidence=[evidence], representative_event=rep)
        self.alerts_by_key[alert.id] = alert
        self.alert_index[alert.id] = alert
        # Do not repopulate lane_alert: a retired rule must never have its
        # old alert revived by later detection, and a re-enabled rule
        # starts a fresh lane (a genuinely new firing gets a new id).

    @staticmethod
    def _evidence_from_dict(data: dict):
        from soc.alerts import Evidence
        return Evidence(
            rule_id=data.get("rule_id", ""),
            rule_version=data.get("rule_version", 0),
            group_key=data.get("group_key", ""),
            window_seconds=float(data.get("window_seconds", 0.0)),
            event_ids=tuple(data.get("event_ids", [])),
            basis=tuple((float(ts), int(seq))
                        for ts, seq in data.get("basis", [])))

    def _rebuild_retirements(self) -> None:
        """Re-derive rule-retirement conclusions without the journal.

        Retirement is a pure consequence of the final rule configuration
        versus the alerts the stream produced: any enabled-in-history rule
        that is absent or disabled in the final snapshot must have all its
        alerts CLOSED. Commands in ``alerts.jsonl`` (including retirements
        interleaved with human actions) are replayed afterwards in ts/id
        order, so the winner is always whichever conclusion was recorded
        first. Running this before the command replay is idempotent and
        converges: the journal applies the identical terminal outcome.
        """
        from soc.alerts import RETIRE_REASON
        retired: dict[str, str] = {}
        current = self.ruleset
        # Rules that produced alerts but are gone/disabled in the final
        # configuration are retired by the final snapshot.
        rule_ids = {a.rule_id for a in self.alert_index.values()}
        for rid in rule_ids:
            rule = current.get(rid)
            if rule is None:
                retired[rid] = "deleted"
            elif not rule.enabled:
                retired[rid] = "disabled"
        for alert in sorted(self.alert_index.values(),
                            key=lambda a: (a.created_ts, a.id)):
            detail = retired.get(alert.rule_id)
            if detail is None or alert.state is AlertState.CLOSED:
                continue
            alert.transition("rule_retire", ts=alert.updated_ts,
                             reason=detail)


def _default_clock() -> float:
    import time
    return time.time()
