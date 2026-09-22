"""时间窗口关联：阈值计数与跨事件序列。

确定性约定（乱序、重复、边界、迟到都有可复现结论）：

1. 一切判定基于事件的 ``event_time``，与请求到达顺序无关。同一事件流
   以任意（在 watermark 允许范围内的）顺序注入，最终命中集合相同。
2. 重复事件（相同 ``event_id``）在摄入层即被拒绝，绝不进入计数。
3. watermark = 已观测最大 event_time - allowed_lateness_seconds；
   event_time < watermark 的迟到事件 *不参与关联*（结论 LATE_IGNORED），
   但会被持久化，重放结论一致。
4. 阈值对齐窗口为左闭右开 ``[k*W, (k+1)*W)``，边界事件归属确定；
   每窗口只命中一次，命中键 = (规则, 分组, 窗口序号)。
5. 序列命中键 = 匹配到的事件 id 有序元组；同一组事件重复扫描只产生
   同一键，告警层据此去重。等时间戳用 event_id 字典序打破并列。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import LimitExceeded
from .models import (
    NormalizedEvent,
    Rule,
    RuleType,
    SequenceSpec,
    ThresholdSpec,
)

# 迟到事件的确定性结论
LATE_IGNORED = "late_ignored"
CORRELATED = "correlated"
NO_MATCH = "no_match"


@dataclass(frozen=True, slots=True)
class Match:
    """一次规则命中。"""

    rule_id: str
    rule_name: str
    group: tuple[Any, ...]
    dedupe_key: tuple[Any, ...]
    event_ids: tuple[str, ...]
    window_start: float
    window_end: float
    explanation: dict[str, Any]


@dataclass(slots=True)
class _GroupState:
    events: list[NormalizedEvent] = field(default_factory=list)
    sorted_added: bool = False  # 乱序注入后需要重排


@dataclass(frozen=True, slots=True)
class _Job:
    """一个规则分组上的待提交变更。"""

    gkey: tuple[str, tuple[Any, ...]]
    event: NormalizedEvent
    matches: tuple[Match, ...]


@dataclass(frozen=True, slots=True)
class Plan:
    """一次注入的完整判定结果（不可变，可先落 WAL 后 commit）。"""

    late: bool
    new_max: float | None
    jobs: tuple[_Job, ...]
    verdict: str = NO_MATCH

    @property
    def matches(self) -> list[Match]:
        out: list[Match] = []
        for job in self.jobs:
            out.extend(job.matches)
        return out


def _matches_filter(event: NormalizedEvent, attr: str | None, value: Any) -> bool:
    if attr is None:
        return True
    return event.field_value(attr) == value


def _threshold_participates(event: NormalizedEvent, spec: ThresholdSpec) -> bool:
    if spec.event_types is not None and event.event_type not in spec.event_types:
        return False
    return _matches_filter(event, spec.filter_attr, spec.filter_value)


def _sequence_participates(event: NormalizedEvent, spec: SequenceSpec) -> bool:
    for step in spec.steps:
        if event.event_type == step.event_type and _matches_filter(
            event, step.filter_attr, step.filter_value
        ):
            return True
    return False


def _sorted_events(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    return sorted(events, key=lambda e: (e.event_time, e.event_id))


class CorrelationEngine:
    """每个规则 × 每个分组维护独立的事件历史，互不串扰。"""

    def __init__(
        self,
        allowed_lateness_seconds: float = 300.0,
        max_group_members: int = 10_000,
    ) -> None:
        self._allowed_lateness = float(allowed_lateness_seconds)
        self._max_group_members = max_group_members
        self._max_event_time: float | None = None
        # (rule_id, group) -> _GroupState
        self._groups: dict[tuple[str, tuple[Any, ...]], _GroupState] = {}
        # 已发布命中的去重键：保证重复扫描/乱序补入不重复告警
        self._fired: set[tuple[Any, ...]] = set()

    # ---- 持久化重建支持 ----
    def reset(self) -> None:
        self._max_event_time = None
        self._groups.clear()
        self._fired.clear()

    @property
    def watermark(self) -> float | None:
        if self._max_event_time is None:
            return None
        return self._max_event_time - self._allowed_lateness

    def plan(
        self, event: NormalizedEvent, rules: dict[str, Rule]
    ) -> Plan:
        """纯判定：不修改任何状态。完成迟到裁决、上限预检查与命中计算。

        返回的 Plan 可随后交给 commit() 原子落地。这样调用方可以在
        WAL 落盘成功 *之后* 再改内存，落盘失败时不存在任何中间状态。
        """
        if self._max_event_time is not None:
            wm = self._max_event_time - self._allowed_lateness
            if event.event_time < wm:
                return Plan(late=True, new_max=self._max_event_time, jobs=())

        new_max = self._max_event_time
        if new_max is None or event.event_time > new_max:
            new_max = event.event_time

        jobs: list[_Job] = []
        produced_any = False
        for rule in rules.values():
            relevant = (
                _threshold_participates(event, rule.threshold)
                if rule.rule_type is RuleType.THRESHOLD
                else _sequence_participates(event, rule.sequence)
            )
            if not relevant:
                continue
            produced_any = True
            group = rule.group_value(event)
            gkey = (rule.rule_id, group)
            state = self._groups.get(gkey)
            size = len(state.events) if state is not None else 0
            if size >= self._max_group_members:
                # 变更前即拒绝：不写入、不计数，调用方也不会写 WAL
                raise LimitExceeded(
                    f"规则 {rule.rule_id} 分组 {group} 事件数超过上限 "
                    f"{self._max_group_members}",
                    reason="group_limit_exceeded",
                )
            candidate_events = list(state.events) if state is not None else []
            candidate_events.append(event)
            if rule.rule_type is RuleType.THRESHOLD:
                matches = self._eval_threshold(rule, group, candidate_events, event)
            else:
                matches = self._eval_sequence(rule, group, candidate_events)
            jobs.append(_Job(gkey=gkey, event=event, matches=matches))

        return Plan(
            late=False,
            new_max=new_max,
            jobs=tuple(jobs),
            verdict=CORRELATED if produced_any else NO_MATCH,
        )

    def commit(self, plan: Plan) -> list[Match]:
        """原子落地一个 Plan：更新水位、追加事件、登记命中键。"""
        self._max_event_time = plan.new_max
        new_matches: list[Match] = []
        for job in plan.jobs:
            state = self._groups.get(job.gkey)
            if state is None:
                state = _GroupState()
                self._groups[job.gkey] = state
            state.events.append(job.event)
            state.sorted_added = False
            for match in job.matches:
                self._fired.add(match.dedupe_key)
                new_matches.append(match)
        return new_matches

    def add(
        self, event: NormalizedEvent, rules: dict[str, Rule]
    ) -> tuple[list[Match], str]:
        """便捷方法：plan + commit（非持久化场景使用）。"""
        plan = self.plan(event, rules)
        if plan.late:
            return [], LATE_IGNORED
        return self.commit(plan), plan.verdict

    # ---- 阈值（纯函数：基于候选事件列表计算，不触碰 self 状态） ----
    def _eval_threshold(
        self,
        rule: Rule,
        group: tuple[Any, ...],
        candidate_events: list[NormalizedEvent],
        event: NormalizedEvent,
    ) -> tuple[Match, ...]:
        spec = rule.threshold
        assert spec is not None
        members = [e for e in candidate_events if _threshold_participates(e, spec)]

        if spec.align_window:
            w = spec.window_seconds
            idx = int(event.event_time // w)
            window_start = idx * w
            window_end = window_start + w
            in_window = [
                e for e in members if window_start <= e.event_time < window_end
            ]
            if len(in_window) < spec.count:
                return ()
            dedupe_key = ("threshold", rule.rule_id, group, idx)
            if dedupe_key in self._fired:
                return ()
        else:
            # 滑动窗口：以本事件为右端点 (t-W, t]；命中键取窗口内事件 id 集合，
            # 同一批事件重复扫描键不变；窗口滑到新事件集合后才会产生新键。
            w = spec.window_seconds
            in_window = [
                e
                for e in _sorted_events(members)
                if event.event_time - w < e.event_time <= event.event_time
            ]
            if len(in_window) < spec.count:
                return ()
            ids = tuple(sorted(e.event_id for e in in_window))
            dedupe_key = ("threshold-slide", rule.rule_id, group, ids)
            if dedupe_key in self._fired:
                return ()
            window_start = in_window[0].event_time
            window_end = event.event_time

        ids = tuple(sorted(e.event_id for e in in_window))
        return (
            Match(
                rule_id=rule.rule_id,
                rule_name=rule.name,
                group=group,
                dedupe_key=dedupe_key,
                event_ids=ids,
                window_start=window_start,
                window_end=window_end,
                explanation={
                    "criterion": "threshold",
                    "window": [window_start, window_end],
                    "observed_count": len(in_window),
                    "threshold": spec.count,
                    "matching_event_ids": ids,
                },
            ),
        )

    # ---- 序列（纯函数） ----
    def _eval_sequence(
        self,
        rule: Rule,
        group: tuple[Any, ...],
        candidate_events: list[NormalizedEvent],
    ) -> tuple[Match, ...]:
        spec = rule.sequence
        assert spec is not None
        members = _sorted_events(
            [e for e in candidate_events if _sequence_participates(e, spec)]
        )

        def step_match(e: NormalizedEvent, step_index: int) -> bool:
            step = spec.steps[step_index]
            return e.event_type == step.event_type and _matches_filter(
                e, step.filter_attr, step.filter_value
            )

        out: list[Match] = []
        n = len(spec.steps)
        # 以每个可能起点贪心求一次最早完成；命中键由事件 id 决定，天然去重
        for start in range(len(members)):
            if not step_match(members[start], 0):
                continue
            chosen = [members[start]]
            cursor = start
            ok = True
            for si in range(1, n):
                nxt = cursor + 1
                while nxt < len(members) and not step_match(members[nxt], si):
                    nxt += 1
                if nxt >= len(members):
                    ok = False
                    break
                chosen.append(members[nxt])
                cursor = nxt
            if not ok:
                continue
            span = chosen[-1].event_time - chosen[0].event_time
            if span > spec.window_seconds:
                continue
            ids = tuple(e.event_id for e in chosen)
            key = ("sequence", rule.rule_id, group, ids)
            if key in self._fired:
                continue
            out.append(
                Match(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    group=group,
                    dedupe_key=key,
                    event_ids=ids,
                    window_start=chosen[0].event_time,
                    window_end=chosen[-1].event_time,
                    explanation={
                        "criterion": "sequence",
                        "window": [chosen[0].event_time, chosen[-1].event_time],
                        "span_seconds": span,
                        "window_limit_seconds": spec.window_seconds,
                        "steps": [
                            {"name": s.name, "event_type": s.event_type}
                            for s in spec.steps
                        ],
                        "matching_event_ids": ids,
                    },
                )
            )
        return tuple(out)
