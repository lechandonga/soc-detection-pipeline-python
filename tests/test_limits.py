"""规模上限：超限拒绝，失败后不残留中间状态/重复计数。"""

import logging

import pytest

from app.errors import LimitExceeded
from app.models import Config, Limits
from app.service import DetectionService

logger = logging.getLogger("soc.test.limits")

RULE = {
    "rule_id": "r1",
    "name": "阈值",
    "rule_type": "threshold",
    "group_by": ["src_ip"],
    "threshold": {"count": 1, "window_seconds": 6000, "event_types": ["evt"]},
}


def _svc(tmp_path, **limits):
    base = dict(max_events=3, max_rules=2, max_alerts=2, max_group_members=100)
    base.update(limits)
    return DetectionService(config=Config(limits=Limits(**base), data_dir=str(tmp_path)))


def _ev(eid, t, src_ip="10.0.0.1"):
    return {"event_id": eid, "source": "ids", "event_type": "evt",
            "severity": "high", "event_time": t, "src_ip": src_ip}


def test_event_limit_rejected_without_residue(tmp_path):
    svc = _svc(tmp_path)
    svc.replace_rules([RULE])
    for i in range(3):
        svc.ingest(_ev(f"e{i}", i))
    with pytest.raises(LimitExceeded) as ei:
        svc.ingest(_ev("e3", 3))
    logger.info("超事件上限判定 reason=%s 统计=%s", ei.value.reason, svc.stats())
    assert ei.value.reason == "event_limit_exceeded"
    assert svc.stats()["events"] == 3  # 无第 4 条残留


def test_alert_limit_atomically_rejected(tmp_path):
    # 两个不同分组各 1 条即产生 2 条告警，第三条分组会超告警上限：
    # 必须整体拒绝（事件也不得计入），不留半套结果
    svc = _svc(tmp_path, max_events=100)
    svc.replace_rules([RULE])
    svc.ingest(_ev("a", 1, src_ip="1.1.1.1"))
    svc.ingest(_ev("b", 2, src_ip="2.2.2.2"))
    assert svc.stats()["alerts"] == 2
    with pytest.raises(LimitExceeded) as ei:
        svc.ingest(_ev("c", 3, src_ip="3.3.3.3"))
    logger.info("超告警上限判定 reason=%s 统计=%s", ei.value.reason, svc.stats())
    assert ei.value.reason == "alert_limit_exceeded"
    stats = svc.stats()
    assert stats["alerts"] == 2 and stats["events"] == 2


def test_group_member_limit(tmp_path):
    # count 设高，单组事件数受 max_group_members 约束
    rule = {**RULE, "threshold": {"count": 100, "window_seconds": 6000,
                                   "event_types": ["evt"]}}
    svc = _svc(tmp_path, max_events=1000, max_alerts=100, max_group_members=5)
    svc.replace_rules([rule])
    with pytest.raises(LimitExceeded) as ei:
        for i in range(6):
            svc.ingest(_ev(f"e{i}", i))
    logger.info("超分组上限判定 reason=%s 统计=%s", ei.value.reason, svc.stats())
    assert ei.value.reason == "group_limit_exceeded"
    # 失败那次未计入
    assert svc.stats()["events"] == 5
