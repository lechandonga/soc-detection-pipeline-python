"""本地上下文补充：资产归属表与威胁情报匹配。

规则：
- 资产按 asset_id 精确查；查不到时 owner/criticality 标记为 UNKNOWN，
  绝不当作命中、也不静默丢弃。
- 情报按 src_ip（备选 dst_ip）精确匹配；情报源整体不可用（available=False）
  时 intel_hit=None，输出 NOT_AVAILABLE，而不是 False（不可用 != 未命中）。
"""

from __future__ import annotations

from typing import Any

from .models import AlertContext, NormalizedEvent


class ContextEnricher:
    def __init__(
        self,
        assets: dict[str, dict[str, Any]] | None = None,
        intel: set[str] | None = None,
        intel_available: bool = True,
    ) -> None:
        self._assets = dict(assets or {})
        self._intel: set[str] = set(intel or ())
        self._intel_available = bool(intel_available)

    def enrich(self, event: NormalizedEvent) -> AlertContext:
        asset = None
        if event.asset_id is not None:
            asset = self._assets.get(event.asset_id)
        owner = asset.get("owner") if asset else None
        criticality = asset.get("criticality") if asset else None
        if isinstance(owner, str) and not owner.strip():
            owner = None
        if isinstance(criticality, str) and not criticality.strip():
            criticality = None

        if not self._intel_available:
            return AlertContext(owner=owner, criticality=criticality, intel_hit=None)

        hit_ip = None
        for ip in (event.src_ip, event.dst_ip):
            if ip is not None and ip in self._intel:
                hit_ip = ip
                break
        if hit_ip is None:
            return AlertContext(owner=owner, criticality=criticality, intel_hit=False)
        return AlertContext(
            owner=owner,
            criticality=criticality,
            intel_hit=True,
            intel_detail=f"indicator:{hit_ip}",
        )
