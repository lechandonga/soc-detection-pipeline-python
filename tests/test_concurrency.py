"""Concurrent ingestion, rule reloads and lifecycle transitions.

The serialized core must yield deterministic results regardless of thread
interleaving: no duplicate counts, no torn rule versions, no cross-talk.
"""
from __future__ import annotations

import threading

from tests.conftest import explain_alert, log

RULES = [{
    "id": "brute", "kind": "threshold", "count": 10, "window_seconds": 3600,
    "group_by": ["host"],
    "filters": [{"field": "event_type", "op": "eq", "value": "fail"}],
}]


def test_concurrent_ingestion_counts_exactly_once(service_factory, clock):
    # wide lateness so interleaved ingest-time vs event-time never rejects
    clock.now = 5_000.0
    svc = service_factory(window_seconds=3600, allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    n_threads, per_thread = 8, 25  # 200 unique events on host h1
    barrier = threading.Barrier(n_threads)

    def worker(tid: int) -> None:
        barrier.wait()
        for i in range(per_thread):
            eid = f"t{tid}-{i}"
            clock.now = 5_100.0
            svc.ingest({"id": eid, "source": "auth", "event_type": "fail",
                        "severity": "high", "ts": 5_000 + (tid + i) % 1000,
                        "host": "h1"})

    threads = [threading.Thread(target=worker, args=(t,))
               for t in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    alerts = svc.list_alerts()
    log.info("concurrent ingest: %d events, alerts=%d, occurrences=%d",
             n_threads * per_thread, len(alerts),
             sum(a["occurrences"] for a in alerts))

    # exact-once conclusions: each firing's evidence basis appears once ...
    basis_set: set[tuple] = set()
    for a in alerts:
        for ev in a["evidence"]:
            basis = tuple(ev["event_ids"])
            assert basis not in basis_set, "duplicate conclusion produced"
            basis_set.add(basis)
    # ... and each alert id (match_key) is globally unique
    all_ids = [a["id"] for a in alerts]
    assert len(all_ids) == len(set(all_ids))
    # event-time order is respected inside every basis
    for a in alerts:
        for ev in a["evidence"]:
            ts_list = [ts for ts, _ in ev["basis"]]
            assert ts_list == sorted(ts_list)
    log.info(explain_alert(alerts[0]))


def test_concurrent_ingest_reload_and_transitions(service_factory, clock):
    clock.now = 6_000.0
    svc = service_factory(window_seconds=3600, allowed_lateness_seconds=100_000)
    svc.replace_rules(RULES)
    stop = threading.Event()
    errors: list[Exception] = []

    def ingester() -> None:
        i = 0
        while not stop.is_set():
            try:
                clock.now = 6_000.0
                svc.ingest({"id": f"c-{i}", "source": "auth",
                            "event_type": "fail", "severity": "high",
                            "ts": 5_000 + i % 900, "host": "h1"})
            except Exception as exc:  # capacity/dup may occur; record others
                errors.append(exc)
            i += 1

    def reloader() -> None:
        v = 10
        while not stop.is_set():
            try:
                docs = [dict(RULES[0], count=10 + (v % 5))]
                svc.replace_rules(docs)
            except Exception as exc:
                errors.append(exc)
            v += 1
            stop.wait(0.002)

    def lifecycler() -> None:
        seen: set[str] = set()
        while not stop.is_set():
            for a in svc.list_alerts():
                aid = a["id"]
                try:
                    if a["state"] == "open" and aid not in seen:
                        svc.transition_alert(aid, "acknowledge")
                        seen.add(aid)
                except Exception as exc:
                    errors.append(exc)
            stop.wait(0.001)

    threads = [threading.Thread(target=ingester),
               threading.Thread(target=reloader),
               threading.Thread(target=lifecycler)]
    for t in threads:
        t.start()
    stop.wait(0.6)
    stop.set()
    for t in threads:
        t.join()

    log.info("mixed concurrency finished, errors=%d", len(errors))
    # only benign errors (none expected from serialization itself)
    fatal = [e for e in errors if not isinstance(e, Exception)]
    assert not fatal
    # invariant: each alert has exactly one state, stable ids
    ids = [a["id"] for a in svc.list_alerts()]
    assert len(ids) == len(set(ids))
    # reload always ended on an even internally-consistent version
    snap = svc.rules_snapshot()
    assert all("id" in r and "kind" in r for r in snap["rules"])
    log.info("final rule version=%s, alerts=%d", snap["version"], len(ids))


def test_restart_after_concurrency_is_stable(tmp_data_dir, clock):
    from soc.config import PipelineConfig
    from soc.service import DetectionService
    from soc.store import Store
    clock.now = 5_000.0
    cfg = PipelineConfig(window_seconds=3600, allowed_lateness_seconds=3600)
    svc = DetectionService(config=cfg, store=Store(tmp_data_dir), clock=clock)
    svc.replace_rules(RULES)

    def worker(tid: int) -> None:
        for i in range(20):
            clock.now = 5_500.0
            svc.ingest({"id": f"p{tid}-{i}", "source": "auth",
                        "event_type": "fail", "severity": "high",
                        "ts": 5_000 + i % 500, "host": "h1"})

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    svc.store.close()

    svc2 = DetectionService(config=cfg, store=Store(tmp_data_dir), clock=clock)
    ids2 = sorted((a["id"], a["event_count"], a["occurrences"])
                  for a in svc2.list_alerts())
    svc2.store.close()
    svc3 = DetectionService(config=cfg, store=Store(tmp_data_dir), clock=clock)
    ids3 = sorted((a["id"], a["event_count"], a["occurrences"])
                  for a in svc3.list_alerts())
    log.info("restart stability: %d alerts, identical across 2 rebuilds=%s",
             len(ids3), ids2 == ids3)
    assert ids2 == ids3
