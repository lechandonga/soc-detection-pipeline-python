"""告警去重、抑制与生命周期状态流转。"""

import logging

import pytest

from app.errors import AlertTransitionRejected
from app.models import Config
from app.service import DetectionService

logger = logging.getLogger("soc.test.alerts")

RULE = {
    "rule_id": "r1",
    "name": "阈值",
    "rule_type": "threshold",
    "group_by": ["src_ip"],
    "suppression_key": ["src_ip"],
    "threshold": {"count": 1, "window_seconds": 10, "event_types": ["evt"]},
}


def make_service(tmp_path):
    svc = DetectionService(config=Config(data_dir=str(tmp_path)))
    svc.replace_rules([RULE])
    return svc


def fire(svc, event_id, t, src_ip="10.0.0.1"):
    return svc.ingest(
        {"event_id": event_id, "source": "ids", "event_type": "evt",
         "severity": "high", "event_time": t, "src_ip": src_ip}
    )


def test_dedupe_same_window(tmp_path):
    """同一窗口只产生一条告警（事件更多也不重复）。"""
    svc = make_service(tmp_path)
    r1 = fire(svc, "a", 1)["alerts"]
    r2 = fire(svc, "b", 2)["alerts"]
    logger.info("窗口内两次注入: 首次新建=%s 二次告警=%s",
                [a["alert_id"] for a in r1], [a["alert_id"] for a in r2])
    assert len(r1) == 1 and r2 == []
    assert len(svc.list_alerts()) == 1


def test_suppression_same_suppression_key(tmp_path):
    """不同窗口、相同 suppression_key(src_ip) 的新告警被抑制并记录来源。"""
    svc = make_service(tmp_path)
    first = fire(svc, "a", 1)["alerts"][0]
    second = fire(svc, "b", 20)["alerts"][0]
    logger.info("首告警 id=%s status=%s; 次告警 status=%s suppressed_by=%s",
                first["alert_id"], first["status"], second["status"],
                second["suppressed_by"])
    assert first["status"] == "open"
    assert second["status"] == "suppressed"
    assert second["suppressed_by"] == first["alert_id"]


def test_lifecycle_happy_path(tmp_path):
    svc = make_service(tmp_path)
    aid = fire(svc, "a", 1)["alerts"][0]["alert_id"]
    svc.transition_alert(aid, "suppress")
    svc.transition_alert(aid, "unsuppress")
    svc.transition_alert(aid, "resolve")
    closed = svc.transition_alert(aid, "close")
    assert closed["status"] == "closed"
    logger.info("生命周期轨迹=%s", [h["to"] for h in closed["history"]])
    assert [h["to"] for h in closed["history"]] == [
        "open", "suppressed", "open", "resolved", "closed"
    ]


@pytest.mark.parametrize(
    "setup_actions,bad_action,reason",
    [
        ([], "close", "must_resolve_before_close"),
        (["resolve", "close"], "resolve", "closed_is_terminal"),
        (["resolve", "close"], "close", "closed_is_terminal"),
        (["suppress"], "resolve", "suppressed_must_reopen_before_resolve"),
        (["resolve"], "unsuppress", "resolved_must_close_first"),
    ],
)
def test_illegal_transitions_are_distinct(tmp_path, setup_actions, bad_action, reason):
    svc = make_service(tmp_path)
    aid = fire(svc, "a", 1)["alerts"][0]["alert_id"]
    for act in setup_actions:
        svc.transition_alert(aid, act)
    with pytest.raises(AlertTransitionRejected) as ei:
        svc.transition_alert(aid, bad_action)
    logger.info("非法跳转 %s -> 动作=%s 判定 reason=%s",
                setup_actions, bad_action, ei.value.reason)
    assert ei.value.reason == reason


def test_recovery_keeps_resolve_before_close_coherent(tmp_path):
    """重启后状态与历史保持连贯，且不能绕过 resolve 直接关闭。"""
    svc = make_service(tmp_path)
    aid = fire(svc, "a", 1)["alerts"][0]["alert_id"]
    svc.transition_alert(aid, "resolve")
    svc.close()

    svc2 = make_service(tmp_path)
    restored = svc2.get_alert(aid)
    assert restored["status"] == "resolved"
    with pytest.raises(AlertTransitionRejected) as ei:
        svc2.transition_alert(aid, "resolve")
    logger.info("重启后重复 resolve 判定=%s", ei.value.reason)
    assert ei.value.reason == "same_status_no_op"
    assert svc2.transition_alert(aid, "close")["status"] == "closed"
