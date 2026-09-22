"""Missing context must be explicitly unknown/unavailable, never a hit."""
from __future__ import annotations

from soc.alerts import Alert, AlertState
from soc.enrichment import LocalIntelProvider, enrich
from soc.models import Event
from tests.conftest import log


def make_alert(event):
    return Alert(id="a1", dedup_key="r1|h", rule_id="r1", severity="high",
                 state=AlertState.OPEN, created_ts=1.0, updated_ts=1.0,
                 representative_event=event)


def test_enrichment_statuses_are_explicit():
    provider = LocalIntelProvider(
        assets={"db-1": {"owner": "dba", "criticality": "critical"}},
        threat_ips={"10.0.0.66": {"campaign": "c-x"}},
    )
    hit_ev = Event(id="e", source="ids", event_type="x", severity="high",
                   ts=1.0, host="db-1", src_ip="10.0.0.66")
    miss_ev = Event(id="e", source="ids", event_type="x", severity="high",
                    ts=1.0, host="laptop-9", src_ip="8.8.8.8")
    unknown_ev = Event(id="e", source="ids", event_type="x",
                       severity="high", ts=1.0)

    for label, ev in [("hit", hit_ev), ("miss", miss_ev),
                      ("unknown", unknown_ev)]:
        ctx = enrich(make_alert(ev), provider)
        log.info("[%s] asset=%s threat=%s threat_hit=%s", label,
                 ctx["asset"]["status"], ctx["threat_intel"]["status"],
                 ctx["threat_hit"])
        if label == "hit":
            assert ctx["asset"]["status"] == "hit"
            assert ctx["threat_intel"]["status"] == "hit"
            assert ctx["threat_hit"] is True
        elif label == "miss":
            assert ctx["asset"]["status"] == "miss"
            assert ctx["threat_intel"]["status"] == "miss"
            assert ctx["threat_hit"] is False
        else:
            assert ctx["asset"]["status"] == "unknown"
            assert ctx["threat_intel"]["status"] == "unknown"
            assert ctx["threat_hit"] is False


def test_unavailable_source_is_not_a_hit():
    down = LocalIntelProvider(threat_source_available=False,
                              asset_source_available=False)
    ev = Event(id="e", source="ids", event_type="x", severity="high",
               ts=1.0, host="db-1", src_ip="10.0.0.66")
    ctx = enrich(make_alert(ev), down)
    log.info("downstream asset=%s threat=%s",
             ctx["asset"]["status"], ctx["threat_intel"]["status"])
    assert ctx["asset"]["status"] == "unavailable"
    assert ctx["threat_intel"]["status"] == "unavailable"
    assert ctx["threat_hit"] is False
