"""配置加载：默认配置 + 可选 JSON 覆盖，非法配置立即拒绝。"""

from __future__ import annotations

import json
from typing import Any

from .errors import PipelineError
from .models import Config, Limits


def _positive_int(data: dict[str, Any], key: str, default: int) -> int:
    val = data.get(key, default)
    if isinstance(val, bool) or not isinstance(val, int) or val <= 0:
        raise PipelineError(
            f"配置项 {key} 必须是正整数，得到 {val!r}", reason="invalid_config"
        )
    return val


def _positive_float(data: dict[str, Any], key: str, default: float) -> float:
    val = data.get(key, default)
    if isinstance(val, bool) or not isinstance(val, (int, float)) or val <= 0:
        raise PipelineError(
            f"配置项 {key} 必须是正数，得到 {val!r}", reason="invalid_config"
        )
    return float(val)


def load_config(path: str | None = None) -> Config:
    default_limits = Limits()
    if path is None:
        return Config()
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise PipelineError("配置文件根必须是 JSON 对象", reason="invalid_config")
    limits_raw = data.get("limits", {})
    if not isinstance(limits_raw, dict):
        raise PipelineError("limits 必须是对象", reason="invalid_config")
    limits = Limits(
        max_events=_positive_int(limits_raw, "max_events", default_limits.max_events),
        max_rules=_positive_int(limits_raw, "max_rules", default_limits.max_rules),
        max_alerts=_positive_int(limits_raw, "max_alerts", default_limits.max_alerts),
        max_group_members=_positive_int(
            limits_raw, "max_group_members", default_limits.max_group_members
        ),
    )
    return Config(
        limits=limits,
        allowed_lateness_seconds=_positive_float(
            data, "allowed_lateness_seconds", Config.allowed_lateness_seconds
        ),
        data_dir=str(data.get("data_dir", "./data")),
    )
