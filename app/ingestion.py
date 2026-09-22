"""事件摄入与归一化：严格校验，失败不产生任何部分写入。

本模块是纯函数：要么返回一个完整的 NormalizedEvent，要么抛 EventRejected，
绝不返回"半成品"。拒绝原因使用 models 中的稳定常量，调用方可以区分：
  MISSING_FIELD / INVALID_TIME / UNKNOWN_SOURCE / INVALID_PAYLOAD
"""

from __future__ import annotations

import datetime as _dt
import math
from typing import Any

from .errors import EventRejected
from .models import (
    INVALID_PAYLOAD,
    INVALID_TIME,
    KNOWN_SOURCES,
    MISSING_FIELD,
    UNKNOWN_SOURCE,
    NormalizedEvent,
)

# 必填的公共字段及其期望类型（None 表示接受任意非空值）
_REQUIRED: dict[str, tuple[type, ...] | None] = {
    "event_id": (str,),
    "source": (str,),
    "event_type": (str,),
    "severity": (str,),
}
_OPTIONAL_STR = ("src_ip", "dst_ip", "user", "asset_id")


def parse_event_time(value: object) -> float:
    """解析事件时间为 POSIX 秒（float）。

    接受：
      - int/float（非 NaN、有限、>0 的 epoch 秒）
      - 字符串：ISO-8601（含末尾 Z），或纯数字字符串
    其余一律抛 EventRejected(INVALID_TIME)。
    """
    if isinstance(value, bool):  # bool 是 int 的子类，显式排除
        raise EventRejected(f"非法时间值: {value!r}", reason=INVALID_TIME)
    if isinstance(value, (int, float)):
        ts = float(value)
        # epoch 0 是合法时刻；仅拒绝 NaN/无穷这类无法确定排序的值
        if not math.isfinite(ts):
            raise EventRejected(f"非法时间值: {value!r}", reason=INVALID_TIME)
        return ts
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise EventRejected("空时间字符串", reason=INVALID_TIME)
        # 纯数字字符串按 epoch 秒处理
        try:
            return parse_event_time(float(text))
        except ValueError:
            pass
        try:
            normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
            dt = _dt.datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise EventRejected(
                f"无法解析时间: {value!r}", reason=INVALID_TIME
            ) from exc
        if dt.tzinfo is None:
            # 朴素时间戳语义有歧义，按非法处理，避免不确定结论
            raise EventRejected(
                f"时间缺少时区信息: {value!r}", reason=INVALID_TIME
            )
        return dt.timestamp()
    raise EventRejected(f"非法时间值: {value!r}", reason=INVALID_TIME)


def _require_str(raw: dict, key: str, *, required: bool) -> str | None:
    if key not in raw or raw[key] is None:
        if required:
            raise EventRejected(f"缺少必填字段: {key}", reason=MISSING_FIELD)
        return None
    val = raw[key]
    if not isinstance(val, str) or not val.strip():
        raise EventRejected(
            f"字段 {key} 必须是非空字符串，得到 {val!r}", reason=INVALID_PAYLOAD
        )
    return val


def normalize(raw: Any) -> NormalizedEvent:
    """校验并归一化单条事件。

    任何失败都在写入存储之前发生（由 service 保证顺序），因此不会留下
    部分写入状态。
    """
    if not isinstance(raw, dict):
        raise EventRejected("请求体必须是 JSON 对象", reason=INVALID_PAYLOAD)

    # 必填字段
    values: dict[str, str] = {}
    for key in _REQUIRED:
        values[key] = _require_str(raw, key, required=True)  # type: ignore[assignment]

    source = values["source"]
    if source not in KNOWN_SOURCES:
        raise EventRejected(
            f"不可辨识的事件来源: {source!r}（合法来源: {sorted(KNOWN_SOURCES)}）",
            reason=UNKNOWN_SOURCE,
        )

    event_time = parse_event_time(raw.get("event_time"))

    optional: dict[str, str | None] = {
        key: _require_str(raw, key, required=False) for key in _OPTIONAL_STR
    }

    attrs_raw = raw.get("attrs", {})
    if attrs_raw is None:
        attrs_raw = {}
    if not isinstance(attrs_raw, dict):
        raise EventRejected("attrs 必须是对象", reason=INVALID_PAYLOAD)
    # attrs 只允许标量值，保证可 JSON 持久化、可复现
    attrs: dict[str, Any] = {}
    for k, v in attrs_raw.items():
        if not isinstance(k, str) or not k:
            raise EventRejected(f"非法 attrs 键: {k!r}", reason=INVALID_PAYLOAD)
        if isinstance(v, bool) or v is None or isinstance(v, (str, int, float)):
            attrs[k] = v
        else:
            raise EventRejected(
                f"attrs.{k} 的值必须是标量，得到 {type(v).__name__}",
                reason=INVALID_PAYLOAD,
            )

    return NormalizedEvent(
        event_id=values["event_id"],
        source=source,
        event_type=values["event_type"],
        event_time=event_time,
        severity=values["severity"],
        src_ip=optional["src_ip"],
        dst_ip=optional["dst_ip"],
        user=optional["user"],
        asset_id=optional["asset_id"],
        attrs=attrs,
    )
