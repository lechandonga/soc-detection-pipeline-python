"""Malformed / illegal events must be rejected with distinct reasons and
must never leave partial state behind.
"""
from __future__ import annotations

import pytest

from soc.errors import (
    CapacityExceededError,
    DuplicateEventError,
    EventInFutureError,
    InvalidFieldValueError,
    InvalidTimestampError,
    MalformedPayloadError,
    MissingFieldError,
    UnknownSourceError,
)
from tests.conftest import log

BRUTE_RULES = [{
    "id": "brute", "kind": "threshold", "count": 1, "window_seconds": 60,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "login_failed"}],
}]


def base_event(**over):
    ev = {"id": "e1", "source": "auth", "event_type": "login_failed",
          "severity": "high", "ts": 10_000.0, "host": "h1"}
    ev.update(over)
    return ev


@pytest.mark.parametrize("name,payload,expected", [
    ("not_object", ["nope"], MalformedPayloadError),
    ("missing_id", base_event(id=None), MissingFieldError),
    ("empty_source", base_event(source=""), MissingFieldError),
    ("missing_ts", {k: v for k, v in base_event().items() if k != "ts"},
     MissingFieldError),
    ("unknown_source", base_event(source="totally-made-up"),
     UnknownSourceError),
    ("bad_severity", base_event(severity="apocalyptic"),
     InvalidFieldValueError),
    ("bad_ts_type", base_event(ts={"a": 1}), InvalidTimestampError),
    ("bad_ts_text", base_event(ts="yesterday"), InvalidTimestampError),
    ("nan_ts", base_event(ts=float("nan")), InvalidTimestampError),
    ("future_ts", base_event(ts=9_000_000_000), EventInFutureError),
    ("wrong_type_field", base_event(host=1234), InvalidFieldValueError),
])
def test_reject_distinct_reasons(service_factory, clock,
                                 name, payload, expected):
    svc = service_factory()
    svc.replace_rules(BRUTE_RULES)
    log.info("[%s] input=%r", name, payload)
    with pytest.raises(expected) as exc:
        svc.ingest(payload)
    log.info("[%s] rejected reason=%s details=%s",
             name, exc.value.reason, exc.value.details)
    # nothing accepted, nothing alerting, no late record
    assert svc.list_alerts() == []
    assert svc.event_status("e1")["status"] == "unknown"


def test_iso8601_and_epoch_equivalent(service_factory, clock):
    clock.now = 1_790_071_230.0  # 30s after the event, inside the window
    svc = service_factory()
    svc.replace_rules(BRUTE_RULES)
    log.info("iso input ts='2026-09-22T10:00:00Z' now=%.1f", clock.now)
    r1 = svc.ingest({"id": "a", "source": "auth",
                     "event_type": "other", "severity": "low",
                     "ts": "2026-09-22T10:00:00Z"})
    stored = svc.event_status("a")["event"]
    log.info("normalized ts=%.3f", stored["ts"])
    assert stored["ts"] == pytest.approx(1790071200.0)
    assert r1["status"] == "accepted"


def test_duplicate_id_rejected_without_double_count(service_factory, clock):
    svc = service_factory()
    svc.replace_rules(BRUTE_RULES)
    payload = base_event()
    log.info("first ingest input=%r", payload)
    svc.ingest(payload)
    log.info("duplicate ingest same id")
    with pytest.raises(DuplicateEventError) as exc:
        svc.ingest(payload)
    assert exc.value.reason == "duplicate_event"
    alerts = svc.list_alerts()
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 1
    log.info("duplicate rejected; alerts=%d count=%d",
             len(alerts), alerts[0]["event_count"])


def test_capacity_raw_fields(tmp_data_dir, clock):
    from soc.config import PipelineConfig
    from soc.service import DetectionService
    from soc.store import Store
    cfg = PipelineConfig(max_raw_fields_per_event=2)
    svc = DetectionService(config=cfg, store=Store(tmp_data_dir), clock=clock)
    payload = base_event()
    payload.update({"x1": "1", "x2": "2", "x3": "3"})
    log.info("capacity input extras=%r", ["x1", "x2", "x3"])
    with pytest.raises(CapacityExceededError) as exc:
        svc.ingest(payload)
    assert exc.value.reason == "capacity_exceeded"
    assert svc.event_status("e1")["status"] == "unknown"
    svc.store.close()
