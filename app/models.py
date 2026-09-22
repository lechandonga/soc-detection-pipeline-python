"""核心领域模型：事件、规则、告警、配置、上下文。

时间统一用事件发生时刻（event_time）的 POSIX 秒（float，单调可比较）。
所有对象均为不可变数据（frozen dataclass），需要更新时整体替换，
从根上避免跨请求共享可变状态导致的串扰。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class RuleType(str, enum.Enum):
    """规则判据类型。"""

    THRESHOLD = "threshold"  # 窗口内计数阈值
    SEQUENCE = "sequence"  # 跨事件有序序列（允许乱序到达，按事件时间排序）


class AlertStatus(str, enum.Enum):
    """告警生命周期状态。

    合法流转（见 alerts 模块）：
        OPEN -> SUPPRESSED -> OPEN
        OPEN -> RESOLVED -> CLOSED
    非法跳转（如 OPEN -> CLOSED、RESOLVED -> OPEN、CLOSED -> *）一律拒绝。
    """

    OPEN = "open"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ---- 事件摄入拒绝原因（稳定字符串，便于测试断言） ----
MISSING_FIELD = "missing_field"
INVALID_TIME = "invalid_time"
UNKNOWN_SOURCE = "unknown_source"
DUPLICATE_EVENT = "duplicate_event"
EVENT_LIMIT_EXCEEDED = "event_limit_exceeded"
INVALID_PAYLOAD = "invalid_payload"

# ---- 规则拒绝原因 ----
INVALID_RULE_CONFIG = "invalid_rule_config"
UNKNOWN_FIELD_REFERENCE = "unknown_field_reference"
RULE_LIMIT_EXCEEDED = "rule_limit_exceeded"

# 支持的事件来源白名单（来源不可辨识的事件必须被拒绝）
KNOWN_SOURCES = frozenset({"firewall", "ids", "edr", "auth", "web_proxy", "dlp"})

# 归一化后的公共字段（规则 group_by / 序列步骤允许引用的字段域）。
# attrs 为自由字典，引用时写作 "attr.<name>"。
COMMON_FIELDS = frozenset(
    {"event_id", "source", "event_type", "event_time", "severity", "src_ip",
     "dst_ip", "user", "asset_id"}
)


@dataclass(frozen=True, slots=True)
class EventInput:
    """原始摄入请求（尚未校验/归一化）。"""

    raw: dict[str, Any]


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """归一化后的事件。"""

    event_id: str
    source: str
    event_type: str
    event_time: float
    severity: str
    src_ip: str | None
    dst_ip: str | None
    user: str | None
    asset_id: str | None
    attrs: dict[str, Any] = field(default_factory=dict)

    def field_value(self, ref: str) -> Any:
        """按规则引用名取值：公共字段直接取，attrs 取 'attr.x'。

        引用合法性应在规则加载阶段校验；运行时 attrs 键缺失返回 None。
        """
        if ref in COMMON_FIELDS:
            return getattr(self, ref)
        if ref.startswith("attr."):
            return self.attrs.get(ref[len("attr."):])
        return None


@dataclass(frozen=True, slots=True)
class ThresholdSpec:
    """阈值判据：window 秒窗口内，符合过滤条件的事件计数 >= count 即命中。

    align_window=True 时窗口按 epoch 边界对齐（确定性的窗口归属，
    用于窗口边界事件测试）；否则为以首条事件时间为起点的滑动窗口。
    """

    count: int
    window_seconds: float
    event_types: frozenset[str] | None = None  # None 表示不限类型
    filter_attr: str | None = None  # 形如 "attr.signature_id"
    filter_value: Any = None
    align_window: bool = True


@dataclass(frozen=True, slots=True)
class SequenceStep:
    """序列步骤：按事件时间先后发生的某类事件。"""

    name: str
    event_type: str
    filter_attr: str | None = None
    filter_value: Any = None


@dataclass(frozen=True, slots=True)
class SequenceSpec:
    """序列判据：window 秒内按事件时间依次出现全部步骤即命中。

    到达顺序可以乱序——判定始终基于 event_time 排序后的序列。
    """

    steps: tuple[SequenceStep, ...]
    window_seconds: float


@dataclass(frozen=True, slots=True)
class Rule:
    """一条声明式检测规则。"""

    rule_id: str
    name: str
    rule_type: RuleType
    group_by: tuple[str, ...]  # 关联分组字段引用，如 ("src_ip",)
    threshold: ThresholdSpec | None = None
    sequence: SequenceSpec | None = None
    suppression_key: tuple[str, ...] = ()  # 命中时若这些字段相同则去重抑制

    def group_value(self, event: NormalizedEvent) -> tuple[Any, ...]:
        """计算该规则在某事件上的分组键（缺失字段以 None 占位，确定可复现）。"""
        return tuple(event.field_value(ref) for ref in self.group_by)


@dataclass(frozen=True, slots=True)
class AlertContext:
    """本地上下文补充：缺失信息显式标记为未知/不可用，绝不静默丢弃。"""

    owner: str | None  # None => UNKNOWN
    criticality: str | None  # None => UNKNOWN
    intel_hit: bool | None  # None => NOT_AVAILABLE（情报源不可用）
    intel_detail: str | None = None

    def to_explain(self) -> dict[str, Any]:
        """以显式未知/不可用标记输出上下文，绝不静默丢弃，也绝不把未知当命中。"""
        if self.intel_hit is None:
            intel_repr: Any = "NOT_AVAILABLE"
        elif self.intel_hit:
            intel_repr = {"hit": True, "detail": self.intel_detail or ""}
        else:
            intel_repr = {"hit": False}
        return {
            "owner": self.owner if self.owner is not None else "UNKNOWN",
            "criticality": self.criticality if self.criticality is not None else "UNKNOWN",
            "threat_intel": intel_repr,
        }


@dataclass(frozen=True, slots=True)
class Limits:
    """可配置规模上限。超限按既定策略拒绝，且不残留中间状态。"""

    max_events: int = 100_000
    max_rules: int = 1_000
    max_alerts: int = 50_000
    max_group_members: int = 10_000  # 单个关联分组内最大事件数（降级保护）


@dataclass(frozen=True, slots=True)
class Config:
    """管线运行配置。"""

    limits: Limits = field(default_factory=Limits)
    allowed_lateness_seconds: float = 300.0  # 窗口外迟到事件的宽限
    data_dir: str = "./data"
