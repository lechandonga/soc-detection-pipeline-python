"""Pipeline configuration: windows, lateness policy and size limits.

Every limit is explicit and overridable. When a limit is exceeded the
pipeline rejects (or, for correlation windows, degrades) deterministically
and never leaves partially written state behind.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PipelineConfig:
    # Correlation window in seconds. Events whose ts is older than
    # ``watermark - allowed_lateness`` are concluded as TOO_LATE.
    window_seconds: float = 300.0
    allowed_lateness_seconds: float = 60.0
    # Events further than this many seconds in the future are rejected.
    max_future_skew_seconds: float = 5.0

    # Hard capacity limits.
    max_events: int = 100_000
    max_rules: int = 1_000
    max_alerts: int = 50_000
    max_raw_fields_per_event: int = 50

    # Degradation: at most this many events are scanned per correlated group;
    # older ones are pruned (they can no longer fall in any active window).
    max_group_scan: int = 10_000

    @classmethod
    def from_dict(cls, data: dict | None) -> "PipelineConfig":
        if not data:
            return cls()
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        return cls(**data)

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if self.allowed_lateness_seconds < 0:
            raise ValueError("allowed_lateness_seconds must be >= 0")
        if self.max_future_skew_seconds < 0:
            raise ValueError("max_future_skew_seconds must be >= 0")
        for name in ("max_events", "max_rules", "max_alerts",
                     "max_raw_fields_per_event", "max_group_scan"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
