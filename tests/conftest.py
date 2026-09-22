"""Shared pytest fixtures and logging helper.

Every test prints its inputs and the decision basis (rule version, lane,
participating event ids / timestamps) so detection conclusions are
explainable straight from the test log.
"""
from __future__ import annotations

import logging
import tempfile

import pytest

from soc.config import PipelineConfig
from soc.service import DetectionService
from soc.store import Store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s | %(message)s")
log = logging.getLogger("soc-test")


class FakeClock:
    """Deterministic, test-controlled clock."""

    def __init__(self, start: float = 10_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
        log.info("clock advanced %.3fs -> %.3f", seconds, self.now)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def tmp_data_dir() -> str:
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def service_factory(tmp_data_dir, clock):
    created: list[DetectionService] = []

    def _factory(*, window_seconds: float = 60.0,
                 allowed_lateness_seconds: float = 0.0,
                 max_events: int = 100_000, max_rules: int = 1000,
                 max_alerts: int = 50_000,
                 data_dir: str | None = None) -> DetectionService:
        cfg = PipelineConfig(
            window_seconds=window_seconds,
            allowed_lateness_seconds=allowed_lateness_seconds,
            max_events=max_events, max_rules=max_rules,
            max_alerts=max_alerts)
        svc = DetectionService(
            config=cfg,
            store=Store(data_dir if data_dir is not None else tmp_data_dir),
            clock=clock)
        created.append(svc)
        return svc

    yield _factory
    for svc in created:
        svc.store.close()


def explain_alert(alert: dict) -> str:
    """Render a one-line human/audit explanation of an alert."""
    ev = alert["evidence"][-1] if alert["evidence"] else None
    basis = ev["basis"] if ev else []
    ids = ev["event_ids"] if ev else []
    return (
        f"alert={alert['id'][:24]} rule={alert['rule_id']} "
        f"state={alert['state']} lane={alert['dedup_key']} "
        f"rule_version={ev['rule_version'] if ev else '?'} "
        f"events={ids} basis(ts,seq)={basis} window={ev['window_seconds'] if ev else '?'} "
        f"occurrences={alert['occurrences']} count={alert['event_count']}")
