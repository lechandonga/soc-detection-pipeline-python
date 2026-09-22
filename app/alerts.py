"""告警去重、抑制与生命周期状态流转。

- 去重：alert 身份由关联命中的确定性 dedupe_key 派生（稳定哈希），
  同一命中无论重放多少次都对应同一条告警，绝不重复计数。
- 抑制：新命中若与同规则下仍活动的告警具有相同的非空 suppression 元组，
  则以 SUPPRESSED 状态产生并记录 suppressed_by，避免告警风暴。
- 生命周期状态机（非法跳转给可区分原因）：
    OPEN       -> SUPPRESSED                     (suppress)
    SUPPRESSED -> OPEN                           (unsuppress)
    OPEN       -> RESOLVED                       (resolve：恢复)
    RESOLVED   -> CLOSED                         (close：关闭)
  其余一律拒绝。特别地：
    OPEN -> CLOSED 拒绝（必须先恢复 RESOLVED，保证恢复→关闭结论连贯）；
    CLOSED -> *    拒绝（终态）；
    相同状态跳转   拒绝（no_op）。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .correlation import Match
from .errors import AlertTransitionRejected, LimitExceeded
from .models import AlertContext, AlertStatus

# 非法状态跳转的可区分原因
SAME_STATUS = "same_status_no_op"
CLOSED_IS_TERMINAL = "closed_is_terminal"
RESOLVE_BEFORE_CLOSE = "must_resolve_before_close"
SUPPRESSED_MUST_REOPEN = "suppressed_must_reopen_before_resolve"
UNRESOLVED_CANNOT_REOPEN = "resolved_must_close_first"
UNKNOWN_TARGET_STATUS = "unknown_target_status"

_ALLOWED: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.OPEN: frozenset({AlertStatus.SUPPRESSED, AlertStatus.RESOLVED}),
    AlertStatus.SUPPRESSED: frozenset({AlertStatus.OPEN}),
    AlertStatus.RESOLVED: frozenset({AlertStatus.CLOSED}),
    AlertStatus.CLOSED: frozenset(),
}


def _reason_for(current: AlertStatus, target: AlertStatus) -> str:
    if current is AlertStatus.CLOSED:
        return CLOSED_IS_TERMINAL  # 终态：任何目标（含自身）都不可达
    if current == target:
        return SAME_STATUS
    if current is AlertStatus.OPEN and target is AlertStatus.CLOSED:
        return RESOLVE_BEFORE_CLOSE
    if current is AlertStatus.SUPPRESSED and target is AlertStatus.RESOLVED:
        return SUPPRESSED_MUST_REOPEN
    if current is AlertStatus.RESOLVED and target is AlertStatus.OPEN:
        return UNRESOLVED_CANNOT_REOPEN
    return "illegal_transition"


@dataclass(slots=True)
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    status: AlertStatus
    dedupe_key: tuple[Any, ...]
    group: tuple[Any, ...]
    event_ids: tuple[str, ...]
    window_start: float
    window_end: float
    explanation: dict[str, Any]
    context: dict[str, Any]
    suppression_tuple: tuple[Any, ...]
    suppressed_by: str | None = None
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "status": self.status.value,
            "group": list(self.group),
            "event_ids": list(self.event_ids),
            "window": [self.window_start, self.window_end],
            "explanation": self.explanation,
            "context": self.context,
            "suppressed_by": self.suppressed_by,
            "history": list(self.history),
        }


def alert_id_for(dedupe_key: tuple[Any, ...]) -> str:
    """由去重键派生稳定告警 ID：同键永远同 ID（重放不产生新告警）。"""
    digest = hashlib.sha256(repr(dedupe_key).encode("utf-8")).hexdigest()[:16]
    return f"al-{digest}"


class AlertStore:
    def __init__(self, max_alerts: int = 50_000) -> None:
        self._alerts: dict[str, Alert] = {}
        self._by_dedupe: dict[tuple[Any, ...], str] = {}
        self._max_alerts = max_alerts

    def raise_or_dedupe(
        self,
        match: Match,
        context: AlertContext,
        suppression_tuple: tuple[Any, ...],
        seq: int,
    ) -> tuple[Alert, bool, bool]:
        """返回 (告警, 是否新建, 是否被抑制)。已存在同 dedupe_key 则去重复用。"""
        existing_id = self._by_dedupe.get(match.dedupe_key)
        if existing_id is not None:
            return self._alerts[existing_id], False, False

        if len(self._alerts) >= self._max_alerts:
            raise LimitExceeded(
                f"告警数量超过上限 {self._max_alerts}", reason="alert_limit_exceeded"
            )

        suppressed = False
        suppressed_by: str | None = None
        # 抑制：非空且不含 None 的 suppression 元组，与同规则活动告警相同即抑制
        if suppression_tuple and all(v is not None for v in suppression_tuple):
            for alert in self._alerts.values():
                if (
                    alert.rule_id == match.rule_id
                    and alert.status in (AlertStatus.OPEN, AlertStatus.SUPPRESSED)
                    and alert.suppression_tuple == suppression_tuple
                ):
                    suppressed = True
                    suppressed_by = alert.alert_id
                    break

        alert_id = alert_id_for(match.dedupe_key)
        status = AlertStatus.SUPPRESSED if suppressed else AlertStatus.OPEN
        alert = Alert(
            alert_id=alert_id,
            rule_id=match.rule_id,
            rule_name=match.rule_name,
            status=status,
            dedupe_key=match.dedupe_key,
            group=match.group,
            event_ids=match.event_ids,
            window_start=match.window_start,
            window_end=match.window_end,
            explanation=match.explanation,
            context=context.to_explain(),
            suppression_tuple=suppression_tuple,
            suppressed_by=suppressed_by,
            history=[
                {
                    "seq": seq,
                    "from": None,
                    "to": status.value,
                    "reason": "suppressed" if suppressed else "raised",
                }
            ],
        )
        self._alerts[alert_id] = alert
        self._by_dedupe[match.dedupe_key] = alert_id
        return alert, True, suppressed

    def transition(
        self, alert_id: str, target: AlertStatus, seq: int
    ) -> Alert:
        alert = self._alerts.get(alert_id)
        if alert is None:
            from .errors import AlertNotFound

            raise AlertNotFound(f"告警不存在: {alert_id}")
        if target not in _ALLOWED:
            raise AlertTransitionRejected(
                f"未知目标状态: {target!r}", reason=UNKNOWN_TARGET_STATUS
            )
        current = alert.status
        if target not in _ALLOWED[current]:
            raise AlertTransitionRejected(
                f"非法状态跳转 {current.value} -> {target.value}",
                reason=_reason_for(current, target),
            )
        alert.history.append(
            {"seq": seq, "from": current.value, "to": target.value, "reason": "operator"}
        )
        alert.status = target
        return alert

    def get(self, alert_id: str) -> Alert:
        from .errors import AlertNotFound

        alert = self._alerts.get(alert_id)
        if alert is None:
            raise AlertNotFound(f"告警不存在: {alert_id}")
        return alert

    def list_alerts(self) -> list[Alert]:
        return sorted(self._alerts.values(), key=lambda a: a.alert_id)

    def __len__(self) -> int:
        return len(self._alerts)
