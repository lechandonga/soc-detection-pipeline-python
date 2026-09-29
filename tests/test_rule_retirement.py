"""Rule retirement: deterministic closeout, replay, re-enable, concurrency.

Retiring a rule means either deleting it from the configuration or setting
its ``enabled`` flag to false. Every alert it produced is concluded CLOSED
with a ``rule_retire`` history record (``deleted`` vs ``disabled``), kept
distinct from a human close. The conclusion is journaled, so online state,
restart rebuild and a second replay converge to the same per-alert state,
close reason and counts.
"""
from __future__ import annotations

import threading

import pytest

from soc.config import PipelineConfig
from soc.errors import InvalidStateTransitionError, UnknownFieldReferenceError
from soc.service import DetectionService
from soc.store import Store
from tests.conftest import explain_alert, log

RULES = [{
    "id": "brute", "kind": "threshold", "count": 2, "window_seconds": 60,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
}]
RULE_DISABLED = [dict(RULES[0], enabled=False)]


def fail_event(eid, ts, host="h1"):
    return {"id": eid, "source": "auth", "event_type": "fail",
            "severity": "high", "ts": ts, "host": host}


def _fire_one(svc, clock, ids=("e1", "e2"), ts0=1_000):
    for i, eid in enumerate(ids):
        clock.now = ts0 + i * 10 + 1
        svc.ingest(fail_event(eid, ts0 + i * 10))
    return svc.list_alerts()[0]["id"]


def test_delete_rule_closes_alerts_with_retirement_record(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory(allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    log.info("input rule=brute events=e1,e2 -> %s",
             explain_alert(svc.get_alert(aid)))

    result = svc.replace_rules([])
    log.info("delete-rule result=%s", result)
    assert result["retired_rule_ids"] == ["brute"]

    alert = svc.get_alert(aid)
    assert alert["state"] == "closed"
    assert alert["closed_by"] == "rule_retire"
    assert alert["closure_detail"] == "deleted"
    last = alert["history"][-1]
    assert last["action"] == "rule_retire"
    assert last["reason"] == "deleted"
    assert alert["event_count"] == 2 and alert["occurrences"] == 1
    assert alert["evidence"][0]["event_ids"] == ["e1", "e2"]
    assert len(svc.list_alerts("closed")) == 1
    assert svc.list_alerts() == []
    log.info("retired alert: state=%s closed_by=%s detail=%s",
             alert["state"], alert["closed_by"], alert["closure_detail"])


def test_disable_rule_is_also_retirement(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory(allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    result = svc.replace_rules(RULE_DISABLED)
    assert result["retired_rule_ids"] == ["brute"]
    alert = svc.get_alert(aid)
    assert alert["state"] == "closed"
    assert alert["closed_by"] == "rule_retire"
    assert alert["closure_detail"] == "disabled"
    assert alert["history"][-1]["reason"] == "disabled"
    log.info("disabled-rule closeout: %s", explain_alert(alert))


def test_manual_close_is_distinct_from_retirement(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory(allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    svc.transition_alert(aid, "close", reason="operator_closed")
    svc.replace_rules([])
    alert = svc.get_alert(aid)
    assert alert["state"] == "closed"
    assert alert["closed_by"] == "manual"
    assert alert["closure_detail"] == ""
    closes = [h for h in alert["history"] if h["to"] == "closed"]
    assert len(closes) == 1 and closes[0]["action"] == "close"
    log.info("manual close survives retirement: %s", closes)


def test_retirement_is_idempotent(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory(allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    svc.replace_rules([])
    before_hist = list(svc.get_alert(aid)["history"])
    svc.replace_rules([])
    svc.replace_rules(RULE_DISABLED)
    after = svc.get_alert(aid)
    assert after["state"] == "closed"
    assert after["history"] == before_hist
    log.info("repeated retirement added %d new records",
             len(after["history"]) - len(before_hist))


def _reopen(directory, cfg, clock):
    return DetectionService(config=cfg, store=Store(directory), clock=clock)


def _view(svc, aid):
    a = svc.get_alert(aid)
    return {
        "state": a["state"], "closed_by": a["closed_by"],
        "detail": a["closure_detail"],
        "count": a["event_count"], "occ": a["occurrences"],
        "history": a["history"],
        "default_pending": len(svc.list_alerts()),
        "closed": len(svc.list_alerts("closed")),
    }


def test_online_restart_and_replay_agree(tmp_data_dir, clock):
    clock.now = 1_001.0
    cfg = PipelineConfig(window_seconds=60, allowed_lateness_seconds=100_000)
    svc = _reopen(tmp_data_dir, cfg, clock)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    clock.now = 2_000.0
    svc.replace_rules([])
    online_view = _view(svc, aid)
    log.info("online closeout=%s", online_view)
    svc.store.close()

    svc2 = _reopen(tmp_data_dir, cfg, clock)
    rebuilt_view = _view(svc2, aid)
    svc2.store.close()
    svc3 = _reopen(tmp_data_dir, cfg, clock)
    again_view = _view(svc3, aid)
    log.info("rebuild=%s replay=%s", rebuilt_view, again_view)
    assert online_view == rebuilt_view == again_view


def test_disable_retirement_also_rebuilds_identically(tmp_data_dir, clock):
    clock.now = 1_001.0
    cfg = PipelineConfig(window_seconds=60, allowed_lateness_seconds=100_000)
    svc = _reopen(tmp_data_dir, cfg, clock)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    svc.replace_rules(RULE_DISABLED)
    svc.store.close()
    svc2 = _reopen(tmp_data_dir, cfg, clock)
    alert = svc2.get_alert(aid)
    assert (alert["state"], alert["closed_by"], alert["closure_detail"]) == (
        "closed", "rule_retire", "disabled")
    assert len(svc2.list_alerts()) == 0
    log.info("disabled retirement rebuilt: %s", explain_alert(alert))


def test_re_enable_does_not_revive_or_duplicate(tmp_data_dir, clock):
    clock.now = 1_001.0
    cfg = PipelineConfig(window_seconds=60, allowed_lateness_seconds=100_000)
    svc = _reopen(tmp_data_dir, cfg, clock)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    svc.replace_rules([])
    assert svc.get_alert(aid)["state"] == "closed"
    svc.replace_rules(RULES)
    assert svc.get_alert(aid)["state"] == "closed"
    assert len(svc.list_alerts("closed")) == 1
    assert len(svc.list_alerts()) == 0
    counts_before = (svc.get_alert(aid)["event_count"],
                     svc.get_alert(aid)["occurrences"])
    log.info("old alert after re-enable: state=closed counts=%s",
             counts_before)
    svc.store.close()

    svc2 = _reopen(tmp_data_dir, cfg, clock)
    again = svc2.get_alert(aid)
    assert again["state"] == "closed"
    assert (again["event_count"], again["occurrences"]) == counts_before
    assert len(svc2.list_alerts("closed")) == 1
    log.info("rebuilt after offline/online churn: %s", explain_alert(again))


def test_failed_update_mid_closeout_leaves_no_partial_state(
        service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory(allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    version_before = svc.rules_snapshot()["version"]
    bad = [{"id": "other", "kind": "threshold",
            "filters": [{"field": "ghost", "op": "eq", "value": "x"}]}]
    with pytest.raises(UnknownFieldReferenceError):
        svc.replace_rules(bad)
    alert = svc.get_alert(aid)
    assert alert["state"] == "open"
    assert alert["closed_by"] is None
    assert [h["action"] for h in alert["history"]] == []
    assert svc.rules_snapshot()["version"] == version_before
    log.info("failed retirement update left alert open, rules intact")


def test_retirement_vs_human_action_has_one_winner(service_factory, clock):
    clock.now = 1_001.0
    svc = service_factory(allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)

    barrier = threading.Barrier(2)

    def human_resolve():
        barrier.wait()
        try:
            svc.transition_alert(aid, "resolve", reason="operator")
        except InvalidStateTransitionError:
            pass

    def retire():
        barrier.wait()
        svc.replace_rules([])

    threads = [threading.Thread(target=human_resolve),
               threading.Thread(target=retire)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    alert = svc.get_alert(aid)
    assert alert["state"] == "closed"
    closing = [h for h in alert["history"] if h["to"] == "closed"]
    assert len(closing) == 1
    winner = closing[0]["action"]
    assert winner == "rule_retire"
    log.info("concurrent winner=%s full_history=%s", winner, alert["history"])


@pytest.mark.parametrize("human_first", [True, False])
def test_retirement_vs_manual_close_order_is_deterministic(
        service_factory, clock, human_first):
    """Whichever terminal conclusion happens first wins, reproducibly."""
    clock.now = 1_001.0
    svc = service_factory(allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    aid = _fire_one(svc, clock)
    if human_first:
        clock.now = 2_000.0
        svc.transition_alert(aid, "close", reason="operator")
        clock.now = 3_000.0
        svc.replace_rules([])
        expected = "manual"
    else:
        clock.now = 2_000.0
        svc.replace_rules([])
        clock.now = 3_000.0
        # a late human close is an idempotent no-op: CLOSED is terminal and
        # the rule-retirement conclusion is not overwritten or re-recorded
        hist_before = list(svc.get_alert(aid)["history"])
        svc.transition_alert(aid, "close", reason="operator")
        assert svc.get_alert(aid)["history"] == hist_before
        expected = "rule_retire"
    alert = svc.get_alert(aid)
    assert alert["state"] == "closed"
    assert alert["closed_by"] == expected
    closing = [h for h in alert["history"] if h["to"] == "closed"]
    assert len(closing) == 1
    log.info("human_first=%s winner=%s history=%s",
             human_first, expected, alert["history"])


ENABLED_RULE = {
    "id": "brute", "kind": "threshold", "count": 50, "window_seconds": 3600,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
}


def test_concurrent_ingest_stays_available_during_retirement(
        service_factory, clock):
    clock.now = 5_000.0
    svc = service_factory(window_seconds=3600,
                          allowed_lateness_seconds=100_000)
    svc.replace_rules([dict(ENABLED_RULE)])
    stop = threading.Event()
    errors: list[Exception] = []
    ingested = []

    def ingester():
        i = 0
        while not stop.is_set():
            try:
                clock.now = 6_000.0 + (i % 900)
                result = svc.ingest({
                    "id": f"c-{i}", "source": "auth", "event_type": "fail",
                    "severity": "high", "ts": 5_000 + i % 900, "host": "h1"})
                ingested.append(result["status"])
            except Exception as exc:
                errors.append(exc)
            i += 1

    state = {"off": False}

    def retirer():
        while not stop.is_set():
            try:
                if state["off"]:
                    svc.replace_rules([dict(ENABLED_RULE)])
                    state["off"] = False
                else:
                    svc.replace_rules([])
                    state["off"] = True
            except Exception as exc:
                errors.append(exc)
            stop.wait(0.001)

    threads = [threading.Thread(target=ingester),
               threading.Thread(target=retirer)]
    for t in threads:
        t.start()
    stop.wait(0.4)
    stop.set()
    for t in threads:
        t.join()
    assert ingested, "ingestion made no progress during rule churn"
    assert not errors, f"unexpected errors: {errors}"
    for a in svc.list_alerts("closed"):
        assert sum(1 for h in a["history"] if h["to"] == "closed") == 1
    log.info("ingestion conclusions during churn=%d, closed alerts=%d",
             len(ingested), len(svc.list_alerts("closed")))
