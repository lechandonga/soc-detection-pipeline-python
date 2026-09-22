"""可区分的拒绝原因与异常类型。

每个异常都携带稳定的机器可读 ``reason``，使调用方（与测试）能够区分
"为什么被拒绝"，而不是只能得到一个模糊的 400。
"""

from __future__ import annotations


class PipelineError(Exception):
    """所有管线错误的基类。"""

    reason: str = "pipeline_error"

    def __init__(self, message: str = "", *, reason: str | None = None) -> None:
        super().__init__(message or self.reason)
        if reason is not None:
            self.reason = reason


class EventRejected(PipelineError):
    """事件在摄入阶段被拒绝（未产生任何部分写入）。"""

    reason = "event_rejected"


class RuleRejected(PipelineError):
    """规则配置非法，在加载阶段被拒绝。"""

    reason = "rule_rejected"


class AlertTransitionRejected(PipelineError):
    """告警生命周期状态跳转非法。"""

    reason = "alert_transition_rejected"


class LimitExceeded(PipelineError):
    """超出可配置规模上限。"""

    reason = "limit_exceeded"


class AlertNotFound(PipelineError):
    """目标告警不存在。"""

    reason = "alert_not_found"


class RuleNotFound(PipelineError):
    """目标规则不存在。"""

    reason = "rule_not_found"
