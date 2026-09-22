"""End-to-end HTTP behaviour: distinct status codes, capacity policy,
explainable alert payload.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from soc.api import create_app
from soc.config import PipelineConfig
from soc.service import DetectionService
from soc.store import Store
from tests.conftest import log

RULES = [{
    "id": "brute", "kind": "threshold", "count": 2, "window_seconds": 60,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
}]


@pytest.fixture
def client(tmp_path):
    class Clock:
        def __init__(self_) -> None:
            self_.now = 1_001.0

        def __call__(self_) -> float:
            return self_.now

    clock = Clock()
    svc = DetectionService(
        config=PipelineConfig(window_seconds=60, allowed_lateness_seconds=0),
        store=Store(str(tmp_path)), clock=clock)
    app = create_app(service=svc)
    with TestClient(app) as c:
        c.clock = clock
        yield c


def ev(eid, ts=1_000.0, host="h1"):
    return {"id": eid, "source": "auth", "event_type": "fail",
            "severity": "high", "ts": ts, "host": host}


def _post_at(client, ts, payload):
    client.clock.now = ts + 1
    return client.post("/api/v1/events", json=payload)


def test_health_and_full_flow(client):
    assert client.get("/health").json() == {"status": "ok"}

    r = client.put("/api/v1/rules", json={"rules": RULES})
    assert r.status_code == 200, r.text
    log.info("rules PUT -> %s", r.json())

    r1 = _post_at(client, 1_000, ev("a"))
    r2 = _post_at(client, 1_010, ev("b", 1_010))
    log.info("ingest statuses %s %s", r1.status_code, r2.status_code)
    assert r1.status_code == 201

    alerts = client.get("/api/v1/alerts").json()
    assert len(alerts) == 1
    log.info("alert payload basis=%s", alerts[0]["evidence"][0]["basis"])
    assert alerts[0]["evidence"][0]["event_ids"] == ["a", "b"]

    aid = alerts[0]["id"]
    assert client.post(f"/api/v1/alerts/{aid}/transition",
                       json={"action": "acknowledge"}).status_code == 200
    bad = client.post(f"/api/v1/alerts/{aid}/transition",
                      json={"action": "reopen"})
    assert bad.status_code == 409
    assert bad.json()["error"]["reason"] == "invalid_state_transition"
    log.info("illegal transition body=%s", bad.json())


def test_malformed_json_is_distinct_reason(client):
    r = client.post("/api/v1/events", content="{not json",
                    headers={"content-type": "application/json"})
    assert r.status_code == 422
    assert r.json()["error"]["reason"] == "malformed_payload"


def test_rejection_reasons_over_http(client):
    client.put("/api/v1/rules", json={"rules": RULES})
    r = client.post("/api/v1/events", json={"id": "x"})
    assert r.status_code == 422
    assert r.json()["error"]["reason"] == "missing_field"
    r = client.post("/api/v1/events",
                    json={"id": "x", "source": "ufo",
                          "event_type": "fail", "severity": "high",
                          "ts": 1_000})
    assert r.json()["error"]["reason"] == "unknown_source"
    client.post("/api/v1/events", json=ev("dup"))
    r = client.post("/api/v1/events", json=ev("dup"))
    assert r.status_code == 409
    assert r.json()["error"]["reason"] == "duplicate_event"
    log.info("duplicate over http -> %s", r.json()["error"]["reason"])


def test_too_late_returns_202_and_no_alert(client):
    client.put("/api/v1/rules", json={"rules": RULES})
    client.clock.now = 1_001.0  # cutoff = 1001 - 60 = 941
    r = client.post("/api/v1/events", json=ev("ancient", 900.0))
    assert r.status_code == 202
    assert r.json()["status"] == "too_late"
    log.info("too-late decision=%s", r.json())
    assert client.get("/api/v1/alerts").json() == []


def test_invalid_rules_over_http(client):
    r = client.put("/api/v1/rules", json={"rules": [
        {"id": "bad", "kind": "threshold",
         "filters": [{"field": "ghost_field", "op": "eq", "value": "x"}]}]})
    assert r.status_code == 400
    assert r.json()["error"]["reason"] == "unknown_field_reference"
    # live rules remain empty/usable
    assert client.get("/api/v1/rules").json()["rules"] == []


def test_capacity_policy_rejects_without_partial_state(tmp_path):
    class Clock:
        now = 1_001.0

        def __call__(self_) -> float:
            return self_.now

    svc = DetectionService(
        config=PipelineConfig(max_events=2, window_seconds=60,
                              allowed_lateness_seconds=100_000),
        store=Store(str(tmp_path)), clock=Clock())
    app = create_app(service=svc)

    def post_at(ts, payload):
        Clock.now = ts + 1
        return c.post("/api/v1/events", json=payload)

    with TestClient(app) as c:
        c.put("/api/v1/rules", json={"rules": RULES})
        assert post_at(1_000, ev("a")).status_code == 201
        assert post_at(1_010, ev("b", 1_010)).status_code == 201
        r = post_at(1_020, ev("c", 1_020))
        assert r.status_code == 422
        body = r.json()
        log.info("capacity rejection=%s", body)
        assert body["error"]["reason"] == "capacity_exceeded"
        # rejected event left no state
        assert svc.event_status("c")["status"] == "unknown"


def test_alert_capacity_rejected_without_partial_state(tmp_path):
    class Clock:
        now = 1_001.0

        def __call__(self_) -> float:
            return self_.now

    # max_alerts=1: distinct hosts each create their own lane/alert
    single = [{
        "id": "single", "kind": "threshold", "count": 1,
        "window_seconds": 60, "group_by": ["host"],
        "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
    }]
    svc = DetectionService(
        config=PipelineConfig(max_alerts=1, window_seconds=60,
                              allowed_lateness_seconds=100_000),
        store=Store(str(tmp_path)), clock=Clock())
    app = create_app(service=svc)
    with TestClient(app) as c:
        c.put("/api/v1/rules", json={"rules": single})
        assert c.post("/api/v1/events", json=ev("a", host="h1")).status_code == 201
        r = c.post("/api/v1/events", json=ev("b", host="h2"))
        assert r.status_code == 422
        assert r.json()["error"]["reason"] == "capacity_exceeded"
        # rejected event and its alert were not written
        assert svc.event_status("b")["status"] == "unknown"
        assert len(svc.list_alerts()) == 1
        log.info("alert capacity rejection=%s", r.json()["error"])
