"""Local context enrichment: asset ownership and threat intelligence.

Enrichment never silently drops a missing lookup and never treats "no data"
as a hit. Every lookup returns one of three explicit statuses:

* ``hit``         - context found
* ``miss``        - queried successfully, no match (definitely not listed)
* ``unavailable`` - the data source is unavailable / errored
* ``unknown``     - the field needed for lookup was absent on the event
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


class EnrichmentError(Exception):
    """Raised internally by providers; converted to 'unavailable' results."""


@dataclass(frozen=True)
class LookupResult:
    source: str
    key: str | None
    status: str  # hit | miss | unknown | unavailable
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"source": self.source, "key": self.key,
                "status": self.status, "data": dict(self.data)}


class Provider(Protocol):
    name: str

    def lookup_asset(self, host: str | None) -> LookupResult: ...

    def lookup_threat(self, ip: str | None) -> LookupResult: ...


@dataclass
class LocalIntelProvider:
    """Static in-memory asset/ti tables - the 'local context' source."""

    assets: dict[str, dict] = field(default_factory=dict)
    threat_ips: dict[str, dict] = field(default_factory=dict)
    # When True, simulate an unavailable backend (explicitly marked, not hit)
    asset_source_available: bool = True
    threat_source_available: bool = True
    name: str = "local"

    def lookup_asset(self, host: str | None) -> LookupResult:
        if not host:
            return LookupResult(self.name, None, "unknown",
                                {"reason": "event has no host"})
        if not self.asset_source_available:
            return LookupResult(self.name, host, "unavailable",
                                {"reason": "asset source unavailable"})
        if host in self.assets:
            return LookupResult(self.name, host, "hit", dict(self.assets[host]))
        return LookupResult(self.name, host, "miss",
                            {"reason": "no asset record for host"})

    def lookup_threat(self, ip: str | None) -> LookupResult:
        if not ip:
            return LookupResult(self.name, None, "unknown",
                                {"reason": "event has no src_ip"})
        if not self.threat_source_available:
            return LookupResult(self.name, ip, "unavailable",
                                {"reason": "threat source unavailable"})
        if ip in self.threat_ips:
            return LookupResult(self.name, ip, "hit", dict(self.threat_ips[ip]))
        return LookupResult(self.name, ip, "miss",
                            {"reason": "ip not on threat list"})


def enrich(alert, provider: Provider) -> dict:
    """Attach asset + threat context to an alert, based on representative event.

    A miss / unknown / unavailable status is recorded explicitly; it can
    never be mistaken for a positive intelligence match.
    """
    event = alert.representative_event
    host = event.host if event is not None else None
    ip = event.src_ip if event is not None else None
    try:
        asset = provider.lookup_asset(host)
    except Exception as exc:  # a failing source degrades, never crashes
        asset = LookupResult(provider.name, host, "unavailable",
                             {"reason": f"provider error: {exc}"})
    try:
        threat = provider.lookup_threat(ip)
    except Exception as exc:
        threat = LookupResult(provider.name, ip, "unavailable",
                              {"reason": f"provider error: {exc}"})
    context = {
        "asset": asset.to_dict(),
        "threat_intel": threat.to_dict(),
        "threat_hit": threat.status == "hit",
        "asset_hit": asset.status == "hit",
    }
    alert.enrichment = context
    return context
