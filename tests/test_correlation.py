"""Out-of-order arrival, duplicates, window boundaries and replay.

Conclusions must be distinguishable, reproducible and exactly-once.
"""
from __future__ import annotations

import pytest

from soc.config import PipelineConfig
from soc.service import DetectionService
from soc.store import Store
from tests.conftest import explain_alert, log

THRESHOLD = [{
    "id": "brute", "kind": "threshold", "count": 3, "window_seconds": 60,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
}]
SEQUENCE = [{
    "id": "escalation", "kind": "sequence", "window_seconds": 60,
    "group_by": ["user"],
    "steps": [{"field": "action", "op": "eq", "value": "login"},
              {"field": "action", "op": "eq", "value": "sudo"},
              {"field": "action", "op": "eq", "value": "shadow_read"}],
}]


def fail_event(eid, ts, host="h1"):
    return {"id": eid, "source": "auth", "event_type": "fail",
            "severity": "high", "ts": ts, "host": host}


def test_out_of_order_detects_once(service_factory, clock):
    clock.now = 1_000.0
    svc = service_factory(window_seconds=60, allowed_lateness_seconds=0)
    svc.replace_rules(THRESHOLD)
    # ingestion order deliberately scrambled relative to event time
    order = [fail_event("e3", 1_059), fail_event("e1", 1_000),
             fail_event("e2", 1_030)]
    for ev in order:
        clock.now = ev["ts"] + 1  # ingest time tracks event timeline
        log.info("ingest out-of-order %s ts=%s now=%.0f",
                 ev["id"], ev["ts"], clock.now)
        svc.ingest(ev)
    alerts = svc.list_alerts()
    assert len(alerts) == 1
    log.info(explain_alert(alerts[0]))
    assert alerts[0]["evidence"][0]["event_ids"] == ["e1", "e2", "e3"]


def test_window_boundary_half_open(service_factory, clock):
    clock.now = 1_000.0
    svc = service_factory(window_seconds=60, allowed_lateness_seconds=0)
    svc.replace_rules(THRESHOLD)
    # e4 at exactly 1060 is OUTSIDE window anchored at 1000
    for ev in [fail_event("e1", 1_000), fail_event("e2", 1_030),
               fail_event("e3", 1_059), fail_event("e4", 1_060)]:
        clock.now = ev["ts"] + 1
        log.info("ingest boundary %s ts=%s", ev["id"], ev["ts"])
        svc.ingest(ev)
    alerts = svc.list_alerts()
    basis_ids = [tuple(e["event_ids"]) for a in alerts for e in a["evidence"]]
    log.info("firings basis=%s", basis_ids)
    # first firing [e1,e2,e3]; e1 must never pair with e4 in [1000,1060)
    assert ("e1", "e2", "e3") in basis_ids
    assert not any(ids[0] == "e1" and "e4" in ids for ids in basis_ids)


def test_too_late_conclusion_is_deterministic(service_factory, clock):
    clock.now = 1_100.0
    svc = service_factory(window_seconds=60, allowed_lateness_seconds=0)
    svc.replace_rules(THRESHOLD)
    # cutoff = 1100 - 60 - 0 = 1040; ts 1039 too late, 1040 accepted
    r_late = svc.ingest(fail_event("late", 1_039))
    r_edge = svc.ingest(fail_event("edge", 1_040))
    log.info("late decision=%s edge decision=%s", r_late["status"],
             r_edge["status"])
    assert r_late["status"] == "too_late"
    assert r_edge["status"] == "accepted"
    assert svc.list_alerts() == []  # late event never participates


def test_duplicates_do_not_double_count(service_factory, clock):
    clock.now = 1_000.0
    svc = service_factory(window_seconds=60, allowed_lateness_seconds=0)
    svc.replace_rules(THRESHOLD)
    for ev in [fail_event("e1", 1_000), fail_event("e2", 1_010),
               fail_event("e3", 1_020)]:
        clock.now = ev["ts"] + 1
        svc.ingest(ev)
    clock.now = 1_021
    from soc.errors import DuplicateEventError
    with pytest.raises(DuplicateEventError):
        svc.ingest(fail_event("e2", 1_010))  # replay same id
    alerts = svc.list_alerts()
    log.info(explain_alert(alerts[0]))
    assert len(alerts) == 1
    assert alerts[0]["evidence"][0]["event_ids"] == ["e1", "e2", "e3"]


def test_sequence_out_of_order(service_factory, clock):
    clock.now = 1_000.0
    svc = service_factory(window_seconds=60, allowed_lateness_seconds=0)
    svc.replace_rules(SEQUENCE)

    def seq_event(eid, ts, action, user="alice"):
        return {"id": eid, "source": "auth", "event_type": "x",
                "severity": "high", "ts": ts, "user": user, "action": action}

    # arrive in reverse order: final step is ingested first
    for ev in [seq_event("c", 1_020, "shadow_read"),
               seq_event("b", 1_010, "sudo"),
               seq_event("a", 1_000, "login")]:
        clock.now = ev["ts"] + 1
        log.info("ingest sequence %s action=%s", ev["id"], ev["action"])
        svc.ingest(ev)
    alerts = svc.list_alerts()
    log.info(explain_alert(alerts[0]))
    assert [e["event_ids"] for e in alerts[0]["evidence"]] == [["a", "b", "c"]]


def test_replay_after_restart_is_identical(tmp_data_dir, clock):
    clock.now = 1_000.0
    cfg = PipelineConfig(window_seconds=60, allowed_lateness_seconds=0)
    svc = DetectionService(config=cfg, store=Store(tmp_data_dir), clock=clock)
    svc.replace_rules(THRESHOLD)
    events = [fail_event(f"e{i}", 1_000 + i * 5) for i in range(8)]
    for ev in events:
        clock.now = ev["ts"] + 1
        svc.ingest(ev)
    first = [(a["id"], a["state"], a["event_count"], a["occurrences"])
             for a in svc.list_alerts()]
    log.info("before restart: %s", first)
    svc.store.close()

    # rebuild twice - repeated rebuild must converge identically
    svc2 = DetectionService(config=cfg, store=Store(tmp_data_dir), clock=clock)
    second = [(a["id"], a["state"], a["event_count"], a["occurrences"])
              for a in svc2.list_alerts()]
    svc2.store.close()
    svc3 = DetectionService(config=cfg, store=Store(tmp_data_dir), clock=clock)
    third = [(a["id"], a["state"], a["event_count"], a["occurrences"])
             for a in svc3.list_alerts()]
    log.info("after restart x2: %s", third)
    assert first == second == third
