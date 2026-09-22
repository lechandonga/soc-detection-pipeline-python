"""规则加载校验与运行中集合的原子更新：非法集合绝不产生半更新。"""

import logging

import pytest

from app.errors import RuleRejected
from app.models import Config, Limits
from app.rules import RuleRegistry, validate_rule
from app.service import DetectionService

logger = logging.getLogger("soc.test.rules")

GOOD_THRESHOLD = {
    "rule_id": "r1",
    "name": "阈值规则",
    "rule_type": "threshold",
    "group_by": ["src_ip"],
    "threshold": {"count": 2, "window_seconds": 60, "event_types": ["login.fail"]},
}
GOOD_SEQUENCE = {
    "rule_id": "s1",
    "name": "序列规则",
    "rule_type": "sequence",
    "group_by": ["src_ip", "attr.hostname"],
    "sequence": {
        "window_seconds": 30,
        "steps": [
            {"name": "a", "event_type": "evt.a"},
            {"name": "b", "event_type": "evt.b"},
        ],
    },
}


@pytest.mark.parametrize(
    "raw,reason",
    [
        ({"name": "x", "rule_type": "threshold"}, "invalid_rule_config"),  # 缺 rule_id
        ({"rule_id": "r", "name": "x", "rule_type": "weird",
          "threshold": {"count": 1, "window_seconds": 1}}, "invalid_rule_config"),
        ({"rule_id": "r", "name": "x", "rule_type": "threshold",
          "threshold": {"count": 0, "window_seconds": 10}}, "invalid_rule_config"),
        ({"rule_id": "r", "name": "x", "rule_type": "threshold",
          "threshold": {"count": 2, "window_seconds": 0}}, "invalid_rule_config"),
        ({"rule_id": "r", "name": "x", "rule_type": "threshold",
          "group_by": ["not_a_field"],
          "threshold": {"count": 1, "window_seconds": 10}}, "unknown_field_reference"),
        ({"rule_id": "r", "name": "x", "rule_type": "threshold",
          "threshold": {"count": 1, "window_seconds": 10, "filter_attr": "bogus.x"}},
         "unknown_field_reference"),
        ({"rule_id": "r", "name": "x", "rule_type": "sequence",
          "group_by": ["src_ip"],
          "sequence": {"window_seconds": 10,
                       "steps": [{"name": "only", "event_type": "evt.a"}]}},
         "invalid_rule_config"),
        ({"rule_id": "r", "name": "x", "rule_type": "threshold",
          "group_by": ["src_ip"],
          "threshold": {"count": 2, "window_seconds": 60, "event_types": []}},
         "invalid_rule_config"),
    ],
)
def test_invalid_rules_rejected_at_load(raw, reason):
    logger.info("规则输入=%r 期望原因=%s", raw, reason)
    with pytest.raises(RuleRejected) as ei:
        validate_rule(raw)
    logger.info("判定依据 reason=%s msg=%s", ei.value.reason, ei.value)
    assert ei.value.reason == reason


def test_valid_rules_load():
    assert validate_rule(GOOD_THRESHOLD).threshold.count == 2
    assert validate_rule(GOOD_SEQUENCE).sequence.steps[0].event_type == "evt.a"


def test_registry_replace_is_atomic():
    reg = RuleRegistry()
    reg.replace_all([GOOD_THRESHOLD])
    old_snapshot = reg.snapshot()
    # 新集合中含非法规则：整体拒绝，旧快照原封不动
    with pytest.raises(RuleRejected):
        reg.replace_all([GOOD_SEQUENCE, {**GOOD_THRESHOLD, "rule_id": "bad",
                                         "group_by": ["nope"]}])
    logger.info("非法替换后规则集合=%s", sorted(reg.snapshot()))
    assert "r1" in reg.snapshot() and "s1" not in reg.snapshot()
    # 进行中的检测持有的旧快照引用仍然完整可用
    assert old_snapshot["r1"].rule_id == "r1"


def test_service_rule_update_atomic_and_persisted(tmp_path):
    svc = DetectionService(
        config=Config(limits=Limits(max_rules=5), data_dir=str(tmp_path))
    )
    svc.replace_rules([GOOD_THRESHOLD])
    before = svc.stats()
    # 规则数超上限
    from app.errors import LimitExceeded

    with pytest.raises(LimitExceeded) as ei:
        svc.replace_rules([GOOD_THRESHOLD] * 6)
    logger.info("超上限判定 reason=%s", ei.value.reason)
    assert ei.value.reason == "rule_limit_exceeded"
    assert svc.stats() == before

    # 非法内容不影响现网规则
    with pytest.raises(RuleRejected):
        svc.replace_rules([{**GOOD_THRESHOLD, "group_by": ["nope"]}])
    assert svc.list_alerts() == []
    assert svc.stats()["rules"] == 1

    # 合法全量替换生效并可跨重启保持
    svc.replace_rules([GOOD_SEQUENCE])
    assert svc.stats()["rules"] == 1
    svc.close()
    svc2 = DetectionService(config=Config(data_dir=str(tmp_path)))
    assert svc2.stats()["rules"] == 1
    assert "s1" in svc2._registry.snapshot()
    svc2.close()
