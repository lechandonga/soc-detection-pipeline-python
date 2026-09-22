"""声明式规则的加载、校验与原子更新。

规则非法（结构错误、窗口/计数非法）或引用了不存在/不允许的字段，
都必须在 *加载阶段* 明确拒绝（RuleRejected），且不会替换运行中的集合。
运行中集合的更新是全量替换：先完整校验并构建新 dict，成功后一次性
替换引用——进行中的检测持有旧快照引用，永不观测到半更新状态。
"""

from __future__ import annotations

from typing import Any

from .errors import RuleRejected
from .models import (
    COMMON_FIELDS,
    INVALID_RULE_CONFIG,
    UNKNOWN_FIELD_REFERENCE,
    Rule,
    RuleType,
    SequenceSpec,
    SequenceStep,
    ThresholdSpec,
)


def _field_ref(raw: Any, name: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise RuleRejected(
            f"{name} 必须是非空字段引用字符串，得到 {raw!r}",
            reason=INVALID_RULE_CONFIG,
        )
    ref = raw.strip()
    # 公共字段或 attr.*；不允许其它形式（防止引用不存在的字段）
    if ref in COMMON_FIELDS or (ref.startswith("attr.") and len(ref) > len("attr.")):
        return ref
    raise RuleRejected(
        f"引用了不允许/不存在的字段: {raw!r}（可用: 公共字段或 attr.<name>）",
        reason=UNKNOWN_FIELD_REFERENCE,
    )


def _opt_ref(raw: Any, name: str) -> str | None:
    if raw is None:
        return None
    return _field_ref(raw, name)


def _as_positive_number(raw: Any, name: str) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw <= 0:
        raise RuleRejected(
            f"{name} 必须是正数，得到 {raw!r}", reason=INVALID_RULE_CONFIG
        )
    return float(raw)


def _as_positive_int(raw: Any, name: str) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or raw <= 0:
        raise RuleRejected(
            f"{name} 必须是正整数，得到 {raw!r}", reason=INVALID_RULE_CONFIG
        )
    return raw


def _build_threshold(raw: Any) -> ThresholdSpec:
    if not isinstance(raw, dict):
        raise RuleRejected("threshold 必须是对象", reason=INVALID_RULE_CONFIG)
    count = _as_positive_int(raw.get("count"), "threshold.count")
    window = _as_positive_number(raw.get("window_seconds"), "threshold.window_seconds")
    event_types = None
    et = raw.get("event_types")
    if et is not None:
        if not isinstance(et, list) or not et or not all(isinstance(x, str) and x for x in et):
            raise RuleRejected(
                "threshold.event_types 必须是非空字符串数组",
                reason=INVALID_RULE_CONFIG,
            )
        event_types = frozenset(et)
    align = raw.get("align_window", True)
    if not isinstance(align, bool):
        raise RuleRejected(
            "threshold.align_window 必须是布尔值", reason=INVALID_RULE_CONFIG
        )
    filter_attr = _opt_ref(raw.get("filter_attr"), "threshold.filter_attr")
    return ThresholdSpec(
        count=count,
        window_seconds=window,
        event_types=event_types,
        filter_attr=filter_attr,
        filter_value=raw.get("filter_value"),
        align_window=align,
    )


def _build_sequence(raw: Any) -> SequenceSpec:
    if not isinstance(raw, dict):
        raise RuleRejected("sequence 必须是对象", reason=INVALID_RULE_CONFIG)
    window = _as_positive_number(raw.get("window_seconds"), "sequence.window_seconds")
    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or len(steps_raw) < 2:
        raise RuleRejected(
            "sequence.steps 至少包含 2 个步骤", reason=INVALID_RULE_CONFIG
        )
    steps: list[SequenceStep] = []
    seen_names: set[str] = set()
    for i, step in enumerate(steps_raw):
        if not isinstance(step, dict):
            raise RuleRejected(f"steps[{i}] 必须是对象", reason=INVALID_RULE_CONFIG)
        sname = step.get("name")
        if not isinstance(sname, str) or not sname:
            raise RuleRejected(
                f"steps[{i}].name 必须是非空字符串", reason=INVALID_RULE_CONFIG
            )
        if sname in seen_names:
            raise RuleRejected(
                f"序列步骤名重复: {sname}", reason=INVALID_RULE_CONFIG
            )
        seen_names.add(sname)
        etype = step.get("event_type")
        if not isinstance(etype, str) or not etype:
            raise RuleRejected(
                f"steps[{i}].event_type 必须是非空字符串",
                reason=INVALID_RULE_CONFIG,
            )
        steps.append(
            SequenceStep(
                name=sname,
                event_type=etype,
                filter_attr=_opt_ref(step.get("filter_attr"), "steps.filter_attr"),
                filter_value=step.get("filter_value"),
            )
        )
    return SequenceSpec(steps=tuple(steps), window_seconds=window)


def validate_rule(raw: Any) -> Rule:
    """校验单条规则配置并产出不可变 Rule。"""
    if not isinstance(raw, dict):
        raise RuleRejected("规则必须是 JSON 对象", reason=INVALID_RULE_CONFIG)
    rule_id = raw.get("rule_id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise RuleRejected("rule_id 必须是非空字符串", reason=INVALID_RULE_CONFIG)
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise RuleRejected("name 必须是非空字符串", reason=INVALID_RULE_CONFIG)
    rtype = raw.get("rule_type")
    try:
        rule_type = RuleType(rtype)
    except ValueError:
        raise RuleRejected(
            f"未知 rule_type: {rtype!r}（合法: {[t.value for t in RuleType]}）",
            reason=INVALID_RULE_CONFIG,
        ) from None

    gb = raw.get("group_by", [])
    if not isinstance(gb, list) or not all(isinstance(x, str) for x in gb):
        raise RuleRejected(
            "group_by 必须是字段引用字符串数组", reason=INVALID_RULE_CONFIG
        )
    group_by = tuple(_field_ref(x, "group_by") for x in gb)

    sk = raw.get("suppression_key", [])
    if not isinstance(sk, list) or not all(isinstance(x, str) for x in sk):
        raise RuleRejected(
            "suppression_key 必须是字段引用字符串数组",
            reason=INVALID_RULE_CONFIG,
        )
    suppression_key = tuple(_field_ref(x, "suppression_key") for x in sk)

    threshold = sequence = None
    if rule_type is RuleType.THRESHOLD:
        threshold = _build_threshold(raw.get("threshold"))
    else:
        sequence = _build_sequence(raw.get("sequence"))

    return Rule(
        rule_id=rule_id,
        name=name,
        rule_type=rule_type,
        group_by=group_by,
        threshold=threshold,
        sequence=sequence,
        suppression_key=suppression_key,
    )


class RuleRegistry:
    """不可变规则快照持有者。

    ``_rules`` 指向一个永不在原地修改的 dict。更新时先构建新 dict，
    再原子地把属性指向新 dict。
    """

    def __init__(self, rules: dict[str, Rule] | None = None) -> None:
        self._rules: dict[str, Rule] = dict(rules or {})

    def snapshot(self) -> dict[str, Rule]:
        """返回当前快照（在被替换前，其内容恒不变）。"""
        return self._rules

    def get(self, rule_id: str) -> Rule:
        return self._rules[rule_id]

    def replace_all(self, rules: list[dict]) -> dict[str, Rule]:
        """全量原子替换。

        任一规则非法（含 rule_id 重复）即整体抛 RuleRejected，旧快照
        保持有效，不发生部分更新。返回新快照。
        """
        if not isinstance(rules, list):
            raise RuleRejected(
                "规则集合必须是数组", reason=INVALID_RULE_CONFIG
            )
        new_rules: dict[str, Rule] = {}
        for raw in rules:
            rule = validate_rule(raw)
            if rule.rule_id in new_rules:
                raise RuleRejected(
                    f"rule_id 重复: {rule.rule_id}", reason=INVALID_RULE_CONFIG
                )
            new_rules[rule.rule_id] = rule
        # 构建成功后才发布引用
        self._rules = new_rules
        return self._rules

    def __len__(self) -> int:
        return len(self._rules)
