"""畸形事件摄入：不同失败原因必须可区分；失败不得留下部分状态。"""

import logging

import pytest

from app.errors import EventRejected
from app.ingestion import normalize
from app.models import Config, Limits
from app.service import DetectionService

logger = logging.getLogger("soc.test.ingestion")


def base_event(**over):
    ev = dict(
        event_id="evt-1",
        source="ids",
        event_type="login.fail",
        severity="high",
        event_time="2026-09-22T10:00:00+08:00",
        src_ip="10.0.0.1",
        attrs={"signature_id": "S-1001"},
    )
    ev.update(over)
    return ev


MALFORMED_CASES = [
    ("缺少 event_id", lambda: {k: v for k, v in base_event().items() if k != "event_id"}, "missing_field"),
    ("缺少 source", lambda: {k: v for k, v in base_event().items() if k != "source"}, "missing_field"),
    ("空 event_type", lambda: base_event(event_type="   "), "invalid_payload"),
    ("非法时间字符串", lambda: base_event(event_time="yesterday"), "invalid_time"),
    ("朴素时间(无时区)", lambda: base_event(event_time="2026-09-22T10:00:00"), "invalid_time"),
    ("布尔时间", lambda: base_event(event_time=True), "invalid_time"),
    ("NaN 时间", lambda: base_event(event_time=float("nan")), "invalid_time"),
    ("未知来源", lambda: base_event(source="ufo-sensor"), "unknown_source"),
    ("attrs 非对象", lambda: base_event(attrs=[1, 2]), "invalid_payload"),
    ("attrs 非标量值", lambda: base_event(attrs={"bad": {"nested": 1}}), "invalid_payload"),
    ("请求体非对象", lambda: ["not", "a", "dict"], "invalid_payload"),
]


@pytest.mark.parametrize("case_name,build,reason", MALFORMED_CASES)
def test_malformed_events_are_distinctly_rejected(case_name, build, reason):
    raw = build()
    logger.info("输入=%r 期望拒绝原因=%s", raw, reason)
    with pytest.raises(EventRejected) as ei:
        normalize(raw)
    logger.info("判定依据=拒绝 reason=%s message=%s", ei.value.reason, ei.value)
    assert ei.value.reason == reason


def test_accepted_event_is_normalized():
    raw = base_event()
    event = normalize(raw)
    logger.info("输入=%r 归一化结果 event_time=%s(epoch) attrs=%s",
                raw, event.event_time, event.attrs)
    assert event.source == "ids"
    assert event.attrs == {"signature_id": "S-1001"}


def test_failed_ingest_leaves_no_state(tmp_path):
    svc = DetectionService(
        config=Config(limits=Limits(), data_dir=str(tmp_path))
    )
    # 先制造一个会命中的规则
    svc.replace_rules(
        [
            {
                "rule_id": "r1",
                "name": "n",
                "rule_type": "threshold",
                "group_by": ["src_ip"],
                "threshold": {"count": 1, "window_seconds": 60, "event_types": ["x"]},
            }
        ]
    )
    before = svc.stats()
    for label, raw in [
        ("坏时间", base_event(event_time="nope")),
        ("坏来源", base_event(source="mars")),
        ("非对象", ["x"]),
    ]:
        with pytest.raises(EventRejected):
            svc.ingest(raw)
        logger.info("用例=%s 输入=%r 拒绝后统计=%s", label, raw, svc.stats())
        assert svc.stats() == before, "失败请求不得写入任何状态"
    # WAL 中也不应出现事件记录
    rows = list(svc._wal.replay())
    assert all(r["kind"] != "event" for r in rows)
    svc.close()
