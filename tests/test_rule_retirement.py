"""Rule retirement (撤下): deterministic wind-down of alerts.

Retiring a rule - by deleting it from the config or by setting
``enabled: false`` - converges every non-terminal alert it produced to
``closed`` with reason ``rule_retired``. The conclusion is journaled, so
live state, a restart rebuild and a re-replay of the same journals agree
alert-by-alert; re-enabling the rule never resurrects retired alerts.
"""
from __future__ import annotations

import threading

import pytest

from soc.config import PipelineConfig
from soc.errors import UnknownFieldReferenceError
from soc.service import RULE_RETIRED_REASON, DetectionService
from soc.store import Store
from tests.conftest import explain_alert, log

RULE = {
    "id": "brute", "kind": "threshold", "count": 2, "window_seconds": 60,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
}
OTHER_RULE = {
    "id": "scanner", "kind": "threshold", "count": 1, "window_seconds": 60,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "scan"}],
}


def fail_event(eid, ts, host="h1"):
    return {"id": eid, "source": "auth", "event_type": "fail",
            "severity": "high", "ts": ts, "host": host}


def make_alert(svc, clock, prefix="e", host="h1"):
    for ev in [fail_event(f"{prefix}a", 1_000, host),
               fail_event(f"{prefix}b", 1_010, host)]:
        clock.now = ev["ts"] + 1
        svc.ingest(ev)
    alerts = [a for a in svc.list_alerts()
              if a["dedup_key"] == f"brute|host={host}"]
    assert len(alerts) == 1
    log.info("input=2 fail events on host=%s -> %s", host,
             explain_alert(alerts[0]))
    return alerts[0]


def close_entries(alert):
    return [h for h in alert["history"] if h["action"] == "close"]


def test_retire_by_delete_closes_alerts(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules([RULE])
    alert = make_alert(svc, clock)

    result = svc.replace_rules([OTHER_RULE])  # 'brute' deleted
    log.info("retire by delete -> %s", result)
    assert result["retired_rules"] == ["brute"]

    # default browsing (unfinished work) no longer shows it ...
    assert svc.list_alerts() == []
    # ... but it is still queryable by id and by state, evidence intact
    by_id = svc.get_alert(alert["id"])
    log.info("after retire: %s", explain_alert(by_id))
    assert by_id["state"] == "closed"
    assert by_id["event_count"] == 2 and by_id["occurrences"] == 1
    assert len(by_id["evidence"]) == 1
    closes = close_entries(by_id)
    assert len(closes) == 1
    assert closes[0]["reason"] == RULE_RETIRED_REASON
    assert closes[0]["rule_id"] == "brute"
    assert closes[0]["from"] == "open" and closes[0]["to"] == "closed"
    by_state = svc.list_alerts(state="closed")
    assert [a["id"] for a in by_state] == [alert["id"]]
    assert [a["id"] for a in svc.list_alerts(state="all")] == [alert["id"]]


def test_retire_by_disable_closes_alerts(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules([RULE])
    alert = make_alert(svc, clock)
    svc.transition_alert(alert["id"], "acknowledge")

    disabled = dict(RULE, enabled=False)
    result = svc.replace_rules([disabled])
    log.info("retire by enabled=false -> %s", result)
    assert result["retired_rules"] == ["brute"]

    by_id = svc.get_alert(alert["id"])
    closes = close_entries(by_id)
    log.info("disabled-rule alert: state=%s closes=%s",
             by_id["state"], closes)
    assert by_id["state"] == "closed"
    assert len(closes) == 1
    assert closes[0]["reason"] == RULE_RETIRED_REASON
    assert closes[0]["from"] == "acknowledged"
    # rule still listed (disabled), but produces nothing new
    assert svc.rules_snapshot()["rules"][0]["enabled"] is False


def test_retire_is_idempotent_on_terminal_alerts(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules([RULE])
    alert = make_alert(svc, clock)
    svc.transition_alert(alert["id"], "close", reason="operator: false positive")
    before = svc.get_alert(alert["id"])

    svc.replace_rules([])  # retire everything
    after = svc.get_alert(alert["id"])
    log.info("terminal alert untouched by retire: closes=%s",
             close_entries(after))
    assert after["state"] == "closed"
    # exactly one close record, still the operator's - not dragged out of
    # the terminal state, no contradictory second record
    assert close_entries(after) == close_entries(before)
    assert close_entries(after)[0]["reason"] == "operator: false positive"

    # retiring an already-retired rule set again changes nothing
    svc.replace_rules([])
    assert svc.get_alert(alert["id"])["history"] == after["history"]


def test_retire_restart_and_replay_converge(tmp_data_dir, clock):
    clock.now = 1_001.0
    cfg = PipelineConfig(window_seconds=60)
    svc = DetectionService(config=cfg, store=Store(tmp_data_dir), clock=clock)
    svc.replace_rules([RULE, OTHER_RULE])
    make_alert(svc, clock)
    svc.transition_alert(svc.list_alerts()[0]["id"], "acknowledge")
    # retire 'brute', then re-add it disabled, then delete it entirely:
    # several rule changes before the final config settles
    svc.replace_rules([OTHER_RULE])
    svc.replace_rules([OTHER_RULE, dict(RULE, enabled=False)])
    svc.replace_rules([OTHER_RULE])
    live = svc.list_alerts(state="all")
    log.info("live after retire sequence: %s",
             [explain_alert(a) for a in live])
    assert len(live) == 1 and live[0]["state"] == "closed"
    svc.store.close()

    def rebuild():
        svc2 = DetectionService(config=cfg, store=Store(tmp_data_dir),
                                clock=clock)
        snap = svc2.list_alerts(state="all")
        svc2.store.close()
        return snap

    once, twice = rebuild(), rebuild()
    for label, snap in (("rebuild#1", once), ("rebuild#2", twice)):
        log.info("%s: %s", label, [explain_alert(a) for a in snap])
        assert snap == live, f"{label} diverged from live state"
    closes = close_entries(once[0])
    assert len(closes) == 1 and closes[0]["reason"] == RULE_RETIRED_REASON


def test_reenable_does_not_resurrect_or_duplicate(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules([RULE])
    alert = make_alert(svc, clock)
    svc.replace_rules([])                       # retire
    retired = svc.get_alert(alert["id"])
    assert retired["state"] == "closed"

    svc.replace_rules([RULE])                   # same rule back online
    after = svc.get_alert(alert["id"])
    log.info("after re-enable: %s", explain_alert(after))
    # not resurrected, not double-counted, no duplicate alert
    assert after["state"] == "closed"
    assert after["event_count"] == retired["event_count"]
    assert after["occurrences"] == retired["occurrences"]
    assert after["history"] == retired["history"]
    assert len(svc.list_alerts(state="all")) == 1

    # genuinely new events form a NEW conclusion in the same lane
    for ev in [fail_event("na", 1_020), fail_event("nb", 1_030)]:
        clock.now = ev["ts"] + 1
        svc.ingest(ev)
    alerts = svc.list_alerts()
    log.info("new firing after re-enable: %s",
             [explain_alert(a) for a in alerts])
    assert len(alerts) == 1
    assert alerts[0]["id"] != alert["id"]
    assert alerts[0]["state"] == "open"
    assert svc.get_alert(alert["id"])["state"] == "closed"


def test_retire_vs_manual_transitions_concurrent(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory(window_seconds=3600,
                          allowed_lateness_seconds=100_000)
    svc.replace_rules([dict(RULE, count=2, window_seconds=3600)])
    # several lanes -> several alerts to race over
    for host in ("h1", "h2", "h3", "h4"):
        make_alert(svc, clock, prefix=f"{host}-", host=host)
    alert_ids = [a["id"] for a in svc.list_alerts()]
    log.info("racing retire vs manual actions over %d alerts",
             len(alert_ids))

    errors: list[Exception] = []
    barrier = threading.Barrier(3)

    def retirer():
        barrier.wait()
        svc.replace_rules([])  # retire 'brute'

    def operator(action):
        barrier.wait()
        for aid in alert_ids:
            try:
                svc.transition_alert(aid, action, reason=f"op:{action}")
            except Exception as exc:  # illegal-from-state races are expected
                errors.append(exc)

    threads = [threading.Thread(target=retirer),
               threading.Thread(target=operator, args=("acknowledge",)),
               threading.Thread(target=operator, args=("close",))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    from soc.errors import InvalidStateTransitionError
    assert all(isinstance(e, InvalidStateTransitionError) for e in errors)
    final = svc.list_alerts(state="all")
    for a in final:
        log.info("final: %s closes=%s", explain_alert(a),
                 close_entries(a))
        # every alert lands on exactly one deterministic outcome: closed
        assert a["state"] == "closed"
        # exactly one close record - first writer wins, the rest are
        # idempotent no-ops; no contradictory double wind-down
        closes = close_entries(a)
        assert len(closes) == 1
        assert closes[0]["reason"] in (RULE_RETIRED_REASON, "op:close")
        # history is a coherent sequence of legal transitions
        states = ["open"] + [h["to"] for h in a["history"]]
        for h, expect_from in zip(a["history"], states):
            assert h["from"] == expect_from


def test_failed_update_leaves_no_partial_retirement(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory()
    svc.replace_rules([RULE])
    alert = make_alert(svc, clock)

    bad_docs = [OTHER_RULE,  # would retire 'brute' ...
                {"id": "bad", "kind": "threshold",
                 "filters": [{"field": "ghost", "op": "eq", "value": "x"}]}]
    with pytest.raises(UnknownFieldReferenceError) as exc:
        svc.replace_rules(bad_docs)
    log.info("invalid update rejected: %s", exc.value.reason)

    after = svc.get_alert(alert["id"])
    log.info("alert after failed retire: %s", explain_alert(after))
    # no half-applied wind-down: alert untouched, rule set untouched
    assert after["state"] == "open"
    assert after["history"] == []
    assert [r["id"] for r in svc.rules_snapshot()["rules"]] == ["brute"]
    assert svc.list_alerts(state="all")[0]["id"] == alert["id"]
