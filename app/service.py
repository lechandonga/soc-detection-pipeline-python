"""门面服务：摄入 -> 关联 -> 上下文 -> 告警 -> 持久化 的确定性闭环。

并发正确性：
- 进程内所有跨请求可变状态仅在一把可重入锁内变更；FastAPI 的线程池
  并发请求因此被串行化到状态层面，杜绝跨请求共享可变状态串扰。
- 规则更新是"构建新 dict -> WAL -> 引用替换"：进行中的检测在进入时
  拿到快照引用并全程使用它，永不观测到半更新集合。
- 事件处理是两阶段：plan（纯判定+全部上限预检查）-> WAL append
  （fsync）-> commit（内存变更）-> 建告警（含上限预检查）。
  任何一步在 WAL 之前失败，内存与磁盘均无写入；WAL 之后为纯内存操作，
  失败也能用 WAL 重放恢复，结论一致。
"""

from __future__ import annotations

import os
import threading
from typing import Any

from .alerts import Alert, AlertStore
from .context import ContextEnricher
from .correlation import CorrelationEngine, Match, Plan
from .errors import (
    EventRejected,
    LimitExceeded,
    PipelineError,
    RuleRejected,
)
from .ingestion import normalize
from .models import (
    DUPLICATE_EVENT,
    EVENT_LIMIT_EXCEEDED,
    RULE_LIMIT_EXCEEDED,
    Config,
    NormalizedEvent,
    Rule,
    RuleType,
)
from .rules import RuleRegistry, validate_rule
from .storage import JsonlStore


# ---- 序列化辅助（tuple/dict 都可 JSON 化） ----
def event_to_dict(e: NormalizedEvent) -> dict[str, Any]:
    return {
        "event_id": e.event_id,
        "source": e.source,
        "event_type": e.event_type,
        "event_time": e.event_time,
        "severity": e.severity,
        "src_ip": e.src_ip,
        "dst_ip": e.dst_ip,
        "user": e.user,
        "asset_id": e.asset_id,
        "attrs": e.attrs,
    }


def event_from_dict(d: dict[str, Any]) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=d["event_id"],
        source=d["source"],
        event_type=d["event_type"],
        event_time=float(d["event_time"]),
        severity=d["severity"],
        src_ip=d.get("src_ip"),
        dst_ip=d.get("dst_ip"),
        user=d.get("user"),
        asset_id=d.get("asset_id"),
        attrs=dict(d.get("attrs") or {}),
    )


def _jsonable(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_jsonable(v) for v in value]
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return value


def _rule_raw(rule: Rule) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "rule_id": rule.rule_id,
        "name": rule.name,
        "rule_type": rule.rule_type.value,
        "group_by": list(rule.group_by),
        "suppression_key": list(rule.suppression_key),
    }
    if rule.rule_type is RuleType.THRESHOLD:
        t = rule.threshold
        raw["threshold"] = {
            "count": t.count,
            "window_seconds": t.window_seconds,
            "event_types": sorted(t.event_types) if t.event_types else None,
            "filter_attr": t.filter_attr,
            "filter_value": t.filter_value,
            "align_window": t.align_window,
        }
    else:
        s = rule.sequence
        raw["sequence"] = {
            "window_seconds": s.window_seconds,
            "steps": [
                {
                    "name": st.name,
                    "event_type": st.event_type,
                    "filter_attr": st.filter_attr,
                    "filter_value": st.filter_value,
                }
                for st in s.steps
            ],
        }
    return raw


class DetectionService:
    def __init__(
        self,
        config: Config | None = None,
        enricher: ContextEnricher | None = None,
        wal_path: str | None = None,
    ) -> None:
        self._config = config or Config()
        lim = self._config.limits
        self._lock = threading.RLock()
        self._registry = RuleRegistry()
        self._engine = CorrelationEngine(
            allowed_lateness_seconds=self._config.allowed_lateness_seconds,
            max_group_members=lim.max_group_members,
        )
        self._alerts = AlertStore(max_alerts=lim.max_alerts)
        self._enricher = enricher or ContextEnricher()
        self._seen_ids: set[str] = set()
        self._seq = 0
        path = wal_path or os.path.join(self._config.data_dir, "wal.jsonl")
        self._wal = JsonlStore(path)
        self._recover()

    # ------------------------------------------------------------------
    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    # ------------------------------------------------------------------
    # 启动恢复 / 重放
    # ------------------------------------------------------------------
    def _recover(self) -> None:
        """从 WAL 重建全部内存状态。重复执行幂等：同日志 => 同状态。"""
        for rec in self._wal.replay():
            self._apply_record(rec, persist=False)

    def replay_all(self) -> dict[str, Any]:
        """显式重放：以 WAL 为唯一事实源重建状态。

        重复重放不产生额外计数/告警（状态从零重建，告警 ID 由去重键派生）。
        """
        with self._lock:
            self._registry = RuleRegistry()
            self._engine = CorrelationEngine(
                allowed_lateness_seconds=self._config.allowed_lateness_seconds,
                max_group_members=self._config.limits.max_group_members,
            )
            self._alerts = AlertStore(max_alerts=self._config.limits.max_alerts)
            self._seen_ids = set()
            self._seq = 0
            count = 0
            for rec in self._wal.replay():
                self._apply_record(rec, persist=False)
                count += 1
            return {
                "replayed_records": count,
                "rules": len(self._registry),
                "events": len(self._seen_ids),
                "alerts": len(self._alerts),
            }

    def _apply_record(self, rec: dict[str, Any], *, persist: bool) -> None:
        kind = rec.get("kind")
        seq = int(rec.get("seq", 0))
        self._seq = max(self._seq, seq)
        if kind == "rules_replaced":
            rules = [validate_rule(r) for r in rec["rules"]]
            self._install_rules(rules)
        elif kind == "event":
            self._apply_event_record(event_from_dict(rec["event"]), seq)
        elif kind == "alert_transition":
            from .models import AlertStatus

            self._alerts.transition(
                rec["alert_id"], AlertStatus(rec["to"]), seq
            )

    # ------------------------------------------------------------------
    # 摄入
    # ------------------------------------------------------------------
    def _apply_event_record(self, event: NormalizedEvent, seq: int) -> list[Match]:
        # 重放路径：重复事件（WAL 内不应出现）幂等忽略
        if event.event_id in self._seen_ids:
            return []
        self._seen_ids.add(event.event_id)
        snapshot = self._registry.snapshot()
        plan = self._engine.plan(event, snapshot)
        matches = self._engine.commit(plan)
        for match in matches:
            self._raise_alert_for(match, snapshot[match.rule_id], event, seq)
        return matches

    def _suppression_tuple(self, rule: Rule, event: NormalizedEvent) -> tuple[Any, ...]:
        return tuple(event.field_value(ref) for ref in rule.suppression_key)

    def _raise_alert_for(
        self, match: Match, rule: Rule, event: NormalizedEvent, seq: int
    ) -> Alert:
        context = self._enricher.enrich(event)
        supp = self._suppression_tuple(rule, event)
        alert, _created, _suppressed = self._alerts.raise_or_dedupe(
            match, context, supp, seq
        )
        return alert

    def ingest(self, raw: dict[str, Any]) -> dict[str, Any]:
        """摄入单条事件并跑完整闭环。任何失败都不留下部分状态。"""
        with self._lock:
            # 1) 归一化校验（纯函数，无副作用）
            event = normalize(raw)

            # 2) 幂等：重复 event_id 以可区分原因拒绝（不写任何状态）
            if event.event_id in self._seen_ids:
                raise EventRejected(
                    f"重复事件 event_id={event.event_id}",
                    reason=DUPLICATE_EVENT,
                )

            # 3) 规模上限（在任何写入前判定）
            if len(self._seen_ids) >= self._config.limits.max_events:
                raise LimitExceeded(
                    f"事件总数超过上限 {self._config.limits.max_events}",
                    reason=EVENT_LIMIT_EXCEEDED,
                )

            snapshot = self._registry.snapshot()

            # 4) 纯判定 + 分组上限预检查（不修改引擎状态）
            plan: Plan = self._engine.plan(event, snapshot)

            return self._ingest_commit(event, plan, snapshot)

    def _ingest_commit(
        self,
        event: NormalizedEvent,
        plan: Plan,
        snapshot: dict[str, Rule],
    ) -> dict[str, Any]:
        # 告警上限预检查（去重键已存在的命中不新建）
        if not plan.late:
            existing = len(self._alerts)
            new_keys = {
                m.dedupe_key
                for job in plan.jobs
                for m in job.matches
                if m.dedupe_key not in self._alerts._by_dedupe
            }
            if existing + len(new_keys) > self._config.limits.max_alerts:
                raise LimitExceeded(
                    f"告警数量将超过上限 {self._config.limits.max_alerts}",
                    reason="alert_limit_exceeded",
                )

        # 6) WAL 先落盘（fsync）；失败则以上所有预检查均未改状态
        seq = self._next_seq()
        self._wal.append({"kind": "event", "seq": seq, "event": event_to_dict(event)})

        # 7) 内存提交
        self._seen_ids.add(event.event_id)
        matches = self._engine.commit(plan)
        alerts_out: list[dict[str, Any]] = []
        for match in matches:
            rule = snapshot[match.rule_id]
            alert = self._raise_alert_for(match, rule, event, seq)
            alerts_out.append(alert.to_dict())

        verdict = "late_ignored" if plan.late else plan.verdict
        return {
            "status": "accepted",
            "event_id": event.event_id,
            "verdict": verdict,
            "watermark": self._engine.watermark,
            "alerts": alerts_out,
        }

    # ------------------------------------------------------------------
    # 规则原子更新
    # ------------------------------------------------------------------
    def replace_rules(self, rules: list[dict[str, Any]]) -> dict[str, Any]:
        with self._lock:
            if len(rules) > self._config.limits.max_rules:
                raise LimitExceeded(
                    f"规则数量超过上限 {self._config.limits.max_rules}",
                    reason=RULE_LIMIT_EXCEEDED,
                )
            # 先完整校验并构建新集合（不改任何共享状态）；
            # 任一规则非法即整体抛 RuleRejected，旧集合继续有效。
            built: list[Rule] = []
            seen: set[str] = set()
            for raw in rules:
                rule = validate_rule(raw)
                if rule.rule_id in seen:
                    raise RuleRejected(
                        f"rule_id 重复: {rule.rule_id}", reason="invalid_rule_config"
                    )
                seen.add(rule.rule_id)
                built.append(rule)
            # WAL 成功后才原子发布引用
            return self._publish_rules(built)

    def _publish_rules(self, rules: list[Rule]) -> dict[str, Any]:
        seq = self._next_seq()
        payload = [_rule_raw(r) for r in rules]
        self._wal.append({"kind": "rules_replaced", "seq": seq, "rules": payload})
        self._install_rules(rules)
        return {"status": "replaced", "rule_count": len(rules), "seq": seq}

    def _install_rules(self, rules: list[Rule]) -> None:
        """原子发布规则集合并重置进行中的关联窗口（确定性策略，见 README）。"""
        new_map = {r.rule_id: r for r in rules}
        self._registry._rules = new_map
        self._engine = CorrelationEngine(
            allowed_lateness_seconds=self._config.allowed_lateness_seconds,
            max_group_members=self._config.limits.max_group_members,
        )

    # ------------------------------------------------------------------
    # 告警生命周期
    # ------------------------------------------------------------------
    def transition_alert(self, alert_id: str, action: str) -> dict[str, Any]:
        from .models import AlertStatus

        mapping = {
            "suppress": AlertStatus.SUPPRESSED,
            "unsuppress": AlertStatus.OPEN,
            "resolve": AlertStatus.RESOLVED,
            "close": AlertStatus.CLOSED,
        }
        target = mapping.get(action)
        with self._lock:
            if target is None:
                raise PipelineError(
                    f"未知动作 {action!r}（合法: {sorted(mapping)}）",
                    reason="unknown_action",
                )
            # 先校验跳转（非法则在写 WAL 前被拒绝）
            current = self._alerts.get(alert_id)
            from .alerts import _ALLOWED

            if target not in _ALLOWED[current.status]:
                from .alerts import _reason_for
                from .errors import AlertTransitionRejected

                raise AlertTransitionRejected(
                    f"非法状态跳转 {current.status.value} -> {target.value}",
                    reason=_reason_for(current.status, target),
                )
            seq = self._next_seq()
            self._wal.append(
                {
                    "kind": "alert_transition",
                    "seq": seq,
                    "alert_id": alert_id,
                    "to": target.value,
                }
            )
            alert = self._alerts.transition(alert_id, target, seq)
            return alert.to_dict()

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        with self._lock:
            return self._alerts.get(alert_id).to_dict()

    def list_alerts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts.list_alerts()]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "events": len(self._seen_ids),
                "rules": len(self._registry),
                "alerts": len(self._alerts),
                "watermark": self._engine.watermark,
            }

    def close(self) -> None:
        with self._lock:
            self._wal.close()
