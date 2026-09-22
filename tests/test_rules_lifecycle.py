"""Rule reload atomicity, invalid-config rejection and alert lifecycle."""
from __future__ import annotations

import pytest

from soc.errors import (
    InvalidRuleError,
    InvalidStateTransitionError,
    UnknownFieldReferenceError,
)
from tests.conftest import explain_alert, log

RULES_V1 = [{
    "id": "brute", "kind": "threshold", "count": 3, "window_seconds": 60,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
}]
RULES_V2 = [{
    "id": "brute", "kind": "threshold", "count": 2, "window_seconds": 60,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
}]


def fail_event(eid, ts, host="h1"):
    return {"id": eid, "source": "auth", "event_type": "fail",
            "severity": "high", "ts": ts, "host": host}


def test_invalid_rule_rejected_at_load(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    cases = [
        ([{}], InvalidRuleError, "missing id/kind"),
        ([{"id": "x", "kind": "threshold",
           "filters": [{"field": "ghost", "op": "eq", "value": "1"}]}],
         UnknownFieldReferenceError, "unknown field"),
        ([{"id": "x", "kind": "threshold", "count": 0}],
         InvalidRuleError, "count < 1"),
        ([{"id": "x", "kind": "sequence", "steps": []}],
         InvalidRuleError, "empty sequence"),
        ([{"id": "x", "kind": "threshold", "window_seconds": -5}],
         InvalidRuleError, "negative window"),
    ]
    for docs, exc_type, label in cases:
        log.info("load invalid config (%s): %s", label, docs)
        with pytest.raises(exc_type) as exc:
            svc.replace_rules(docs)
        log.info("  -> rejected: %s", exc.value.reason)


def test_failed_reload_leaves_previous_rules_intact(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules(RULES_V1)
    v1 = svc.rules_snapshot()["version"]
    for ev in [fail_event("a", 1_000), fail_event("b", 1_010)]:
        clock.now = ev["ts"] + 1
        svc.ingest(ev)  # only 2 events -> no alert under count=3
    assert svc.list_alerts() == []

    # invalid update must not partially apply
    with pytest.raises(UnknownFieldReferenceError):
        svc.replace_rules(RULES_V2 + [
            {"id": "bad", "kind": "threshold",
             "filters": [{"field": "nope", "op": "eq", "value": "x"}]}])
    snap = svc.rules_snapshot()
    log.info("after failed reload version=%s (still v1=%s)",
             snap["version"], v1)
    assert snap["version"] == v1
    assert [r["id"] for r in snap["rules"]] == ["brute"]


def test_atomic_rule_change_is_effective_and_versioned(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules(RULES_V1)
    for ev in [fail_event("a", 1_000), fail_event("b", 1_010)]:
        clock.now = ev["ts"] + 1
        svc.ingest(ev)
    assert svc.list_alerts() == []
    # swap to count=2: existing retained events now correlate immediately
    result = svc.replace_rules(RULES_V2)
    log.info("rules atomically replaced -> %s", result)
    alerts = svc.list_alerts()
    assert len(alerts) == 1
    log.info(explain_alert(alerts[0]))
    assert alerts[0]["evidence"][0]["rule_version"] == result["version"]


def test_lifecycle_illegal_transitions_distinct(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules(RULES_V2)
    for ev in [fail_event("a", 1_000), fail_event("b", 1_010)]:
        clock.now = ev["ts"] + 1
        svc.ingest(ev)
    aid = svc.list_alerts()[0]["id"]

    for bad_action in ("resolve", "reopen", "close", "frobnicate"):
        # first move to resolved then exercise illegal-from-resolved etc.
        pass
    # legal path
    svc.transition_alert(aid, "acknowledge")
    svc.transition_alert(aid, "resolve")
    log.info("alert resolved")
    # double resolve is idempotent (coherent recovery)
    svc.transition_alert(aid, "resolve")
    # cannot acknowledge from resolved
    with pytest.raises(InvalidStateTransitionError) as exc:
        svc.transition_alert(aid, "acknowledge")
    assert exc.value.reason == "invalid_state_transition"
    log.info("illegal ack-from-resolved rejected: %s", exc.value.details)
    # reopen works, then close is terminal
    svc.transition_alert(aid, "reopen")
    svc.transition_alert(aid, "close")
    with pytest.raises(InvalidStateTransitionError):
        svc.transition_alert(aid, "resolve")
    log.info("closed alert is terminal")


def test_unknown_alert_404(service_factory, clock):
    from soc.errors import AlertNotFoundError
    svc = service_factory()
    with pytest.raises(AlertNotFoundError) as exc:
        svc.transition_alert("ghost", "acknowledge")
    assert exc.value.reason == "alert_not_found"


def test_suppression_creates_suppressed_alert(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules(
        RULES_V2,
        suppressions=[{"id": "quiet-host",
                       "when": [{"field": "host", "op": "eq",
                                 "value": "h1"}]}])
    for ev in [fail_event("a", 1_000), fail_event("b", 1_010)]:
        clock.now = ev["ts"] + 1
        svc.ingest(ev)
    alert = svc.list_alerts()[0]
    log.info("suppressed alert: state=%s by=%s",
             alert["state"], alert["suppressed_by"])
    assert alert["state"] == "suppressed"
    assert alert["suppressed_by"] == "quiet-host"
