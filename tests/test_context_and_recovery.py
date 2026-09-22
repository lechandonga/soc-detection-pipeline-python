"""上下文补充（缺失显式标记）与重启一致性 / 重放幂等。"""

import logging

from app.context import ContextEnricher
from app.models import Config, Limits
from app.service import DetectionService

logger = logging.getLogger("soc.test.context")

RULE = {
    "rule_id": "r1",
    "name": "阈值",
    "rule_type": "threshold",
    "group_by": ["src_ip"],
    "threshold": {"count": 1, "window_seconds": 60, "event_types": ["evt"]},
}


def _svc(tmp_path, **cfgkw):
    return DetectionService(
        config=Config(limits=Limits(max_events=cfgkw.pop("max_events", 100_000), max_rules=1000, max_alerts=1000, max_group_members=cfgkw.pop("max_group_members", 10_000)), data_dir=str(tmp_path)),
        enricher=cfgkw.get("enricher"),
    )


def _fire(svc, eid, t, **kw):
    payload = {"event_id": eid, "source": "ids", "event_type": "evt",
               "severity": "high", "event_time": t}
    payload.update(kw)
    return svc.ingest(payload)


def test_context_missing_marked_unknown_not_hit(tmp_path):
    # 资产与情报都查不到、且情报源可用：未命中 != 未知
    svc = _svc(tmp_path, enricher=ContextEnricher(assets={}, intel=set()))
    svc.replace_rules([RULE])
    alert = _fire(svc, "e1", 1, src_ip="8.8.8.8", asset_id="ghost")["alerts"][0]
    logger.info("无补充信息输入 -> 上下文=%s", alert["context"])
    assert alert["context"]["owner"] == "UNKNOWN"
    assert alert["context"]["criticality"] == "UNKNOWN"
    assert alert["context"]["threat_intel"] == {"hit": False}


def test_context_intel_unavailable_distinct_from_clean(tmp_path):
    svc = _svc(tmp_path, enricher=ContextEnricher(intel_available=False))
    svc.replace_rules([RULE])
    alert = _fire(svc, "e1", 1, src_ip="8.8.8.8")["alerts"][0]
    logger.info("情报源不可用 -> 上下文=%s", alert["context"])
    assert alert["context"]["threat_intel"] == "NOT_AVAILABLE"


def test_context_hit(tmp_path):
    enricher = ContextEnricher(
        assets={"h1": {"owner": "soc-team", "criticality": "tier0"}},
        intel={"8.8.8.8"},
    )
    svc = _svc(tmp_path, enricher=enricher)
    svc.replace_rules([RULE])
    alert = _fire(svc, "e1", 1, src_ip="8.8.8.8", asset_id="h1")["alerts"][0]
    logger.info("命中输入 -> 上下文=%s", alert["context"])
    assert alert["context"]["owner"] == "soc-team"
    assert alert["context"]["threat_intel"]["hit"] is True


def test_restart_and_replay_are_consistent_and_idempotent(tmp_path):
    svc = _svc(tmp_path)
    svc.replace_rules([RULE])
    for i in range(3):
        _fire(svc, f"e{i}", float(i), src_ip="1.1.1.1")
    first_alerts = svc.list_alerts()
    assert len(first_alerts) == 1
    svc.transition_alert(first_alerts[0]["alert_id"], "resolve")
    first_alerts = svc.list_alerts()  # resolve 之后的最终形态
    svc.close()

    # 重启：状态从 WAL 重建
    svc2 = _svc(tmp_path)
    restored = svc2.list_alerts()
    logger.info("重启后告警=%s", restored)
    assert restored == first_alerts
    assert restored[0]["status"] == "resolved"
    assert svc2.stats()["events"] == 3

    # 再重放同一事件流：不产生新计数、新告警（重建幂等）
    summary = svc2.replay_all()
    logger.info("重放摘要=%s", summary)
    assert svc2.list_alerts() == first_alerts
    assert svc2.stats()["events"] == 3
    svc2.replay_all()
    assert svc2.list_alerts() == first_alerts
