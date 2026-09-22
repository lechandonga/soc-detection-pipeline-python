"""乱序、重复、窗口边界与迟到事件：结论确定且可复现。"""

import logging
import random

import pytest

from app.correlation import LATE_IGNORED, CorrelationEngine
from app.errors import EventRejected
from app.ingestion import normalize
from app.models import Config
from app.rules import validate_rule
from app.service import DetectionService

logger = logging.getLogger("soc.test.correlation")


def event(event_id, t, event_type="login.fail", src_ip="10.0.0.1"):
    return normalize(
        dict(
            event_id=event_id,
            source="ids",
            event_type=event_type,
            severity="high",
            event_time=t,
            src_ip=src_ip,
        )
    )


THRESHOLD = {
    "rule_id": "brute",
    "name": "登录爆破",
    "rule_type": "threshold",
    "group_by": ["src_ip"],
    "threshold": {"count": 3, "window_seconds": 60, "event_types": ["login.fail"]},
}

SEQUENCE = {
    "rule_id": "chain",
    "name": "扫描后登录",
    "rule_type": "sequence",
    "group_by": ["src_ip"],
    "sequence": {
        "window_seconds": 120,
        "steps": [
            {"name": "scan", "event_type": "port.scan"},
            {"name": "login", "event_type": "login.ok"},
        ],
    },
}


def test_threshold_out_of_order_fires_once():
    rule = validate_rule(THRESHOLD)
    # 同一窗口 [0,60) 的三条事件乱序到达
    shuffled = [event("e1", 20), event("e2", 0), event("e3", 10)]
    fired = []
    eng = CorrelationEngine(allowed_lateness_seconds=300)
    for ev in shuffled:
        matches, verdict = eng.add(ev, {rule.rule_id: rule})
        logger.info("输入 event_id=%s t=%s 判定=%s 新命中=%d",
                    ev.event_id, ev.event_time, verdict, len(matches))
        fired.extend(matches)
    assert len(fired) == 1
    assert fired[0].event_ids == ("e1", "e2", "e3")
    assert fired[0].window_start == 0.0 and fired[0].window_end == 60.0
    logger.info("判定依据=%s", fired[0].explanation)


def test_window_boundary_is_deterministic():
    """左闭右开：t=60 属于下一个窗口，不与 [0,60) 合并计数。"""
    rule = validate_rule(THRESHOLD)
    eng = CorrelationEngine(allowed_lateness_seconds=300)

    feed = [("a", 0.0), ("b", 59.999), ("c", 60.0), ("d", 61.0), ("e", 119.999)]
    total = []
    for eid, t in feed:
        matches, verdict = eng.add(event(eid, t), {rule.rule_id: rule})
        logger.info("边界输入 id=%s t=%.3f 判定=%s 命中=%d", eid, t, verdict, len(matches))
        total.extend(matches)
    windows = sorted((m.window_start, m.event_ids) for m in total)
    logger.info("命中窗口归属=%s", windows)
    # 窗口0: a,b（2 条，不触发）；窗口1: c,d,e（3 条，触发一次）
    assert [(w, ids) for w, ids in windows] == [(60.0, ("c", "d", "e"))]


def test_shuffled_stream_same_conclusion():
    """以多种随机注入顺序（均在允许迟到范围内）得到同一命中集合。"""
    rule = validate_rule(THRESHOLD)
    timeline = [event(f"e{i}", float(t)) for i, t in enumerate(
        [5, 2, 8, 62, 65, 70, 125, 126, 127]
    )]
    baseline = None
    for seed in range(5):
        rnd = random.Random(seed)
        order = list(timeline)
        rnd.shuffle(order)
        eng = CorrelationEngine(allowed_lateness_seconds=10_000)  # 全在范围内
        fired_keys = set()
        for ev in order:
            matches, _ = eng.add(ev, {rule.rule_id: rule})
            fired_keys.update(m.dedupe_key for m in matches)
        logger.info("seed=%s 注入乱序后命中键=%s", seed, fired_keys)
        if baseline is None:
            baseline = fired_keys
        else:
            assert fired_keys == baseline, "乱序结论必须一致"


def test_duplicate_event_rejected_without_double_count(tmp_path):
    svc = DetectionService(config=Config(data_dir=str(tmp_path)))
    svc.replace_rules([THRESHOLD])
    svc.ingest({"event_id": "d1", "source": "ids", "event_type": "login.fail",
                "severity": "high", "event_time": 1, "src_ip": "10.0.0.1"})
    with pytest.raises(EventRejected) as ei:
        svc.ingest({"event_id": "d1", "source": "ids", "event_type": "login.fail",
                    "severity": "high", "event_time": 1, "src_ip": "10.0.0.1"})
    logger.info("重复输入判定 reason=%s", ei.value.reason)
    assert ei.value.reason == "duplicate_event"
    assert svc.stats()["events"] == 1


def test_late_event_has_deterministic_conclusion():
    """早于 watermark 的迟到事件不参与关联，结论 late_ignored，可复现。"""
    rule = validate_rule(THRESHOLD)
    eng = CorrelationEngine(allowed_lateness_seconds=10)
    # 先推进水位到 t=100，watermark=90
    for i, t in enumerate([0, 100]):
        eng.add(event(f"f{i}", t), {rule.rule_id: rule})
    matches, verdict = eng.add(event("late", 50), {rule.rule_id: rule})
    logger.info("迟到输入 t=50（watermark=90）判定=%s", verdict)
    assert verdict == LATE_IGNORED and matches == []
    # 再次构造同样引擎、同样顺序，结论一致
    eng2 = CorrelationEngine(allowed_lateness_seconds=10)
    for i, t in enumerate([0, 100]):
        eng2.add(event(f"f{i}", t), {rule.rule_id: rule})
    _, verdict2 = eng2.add(event("late", 50), {rule.rule_id: rule})
    assert verdict2 == LATE_IGNORED


def test_sequence_out_of_order_and_no_duplicate():
    rule = validate_rule(SEQUENCE)
    eng = CorrelationEngine(allowed_lateness_seconds=300)
    # 先到"登录"，后到"扫描"（乱序）仍须按 event_time 命中
    m1, v1 = eng.add(event("login-1", 50, "login.ok"), {rule.rule_id: rule})
    m2, v2 = eng.add(event("scan-1", 10, "port.scan"), {rule.rule_id: rule})
    logger.info("序列乱序判定: login@50 -> %s; scan@10 -> %s 命中=%s",
                v1, v2, [m.event_ids for m in m2])
    assert m1 == [] and len(m2) == 1
    assert m2[0].event_ids == ("scan-1", "login-1")
    # 再来一个无关事件不会重复命中
    m3, _ = eng.add(event("noise", 30, "other.event"), {rule.rule_id: rule})
    assert m3 == []


def test_sequence_window_span_exceeded_no_match():
    rule = validate_rule(SEQUENCE)
    eng = CorrelationEngine(allowed_lateness_seconds=10_000)
    eng.add(event("s", 0, "port.scan"), {rule.rule_id: rule})
    matches, verdict = eng.add(event("l", 200, "login.ok"), {rule.rule_id: rule})
    logger.info("跨窗口序列(span=200>120)判定=%s 命中=%s", verdict, matches)
    assert matches == []
