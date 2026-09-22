"""Event intake and normalization.

Every incoming payload is validated *before* any state is touched. Each
failure mode maps to a distinct ``reason``:

===========================  =================================================
reason                       failure
===========================  =================================================
malformed_payload            body is not a JSON object
missing_field                a required field is absent/null
invalid_field_value          wrong type or illegal enumerated value
invalid_timestamp            timestamp cannot be parsed / NaN
event_too_far_in_future      timestamp beyond allowed future skew
unknown_source               source id not in the known registry
capacity_exceeded            too many custom raw fields
duplicate_event              id already ingested (checked by the service)
===========================  =================================================
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from soc.config import PipelineConfig
from soc.errors import (
    InvalidFieldValueError,
    InvalidTimestampError,
    EventInFutureError,
    MalformedPayloadError,
    MissingFieldError,
    UnknownSourceError,
    CapacityExceededError,
)
from soc.models import KNOWN_SOURCES, VALID_SEVERITIES, Event

REQUIRED_FIELDS = ("id", "source", "event_type", "severity", "ts")
OPTIONAL_STR_FIELDS = ("src_ip", "dst_ip", "user", "host", "action")


def parse_timestamp(value: Any) -> float:
    """Accept epoch seconds (int/float) or ISO-8601 text; return epoch seconds."""
    if isinstance(value, bool):
        raise InvalidTimestampError(
            "ts must be a number or ISO-8601 string, got boolean",
            details={"value": value})
    if isinstance(value, (int, float)):
        ts = float(value)
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        # Accept a trailing Z (zulu) which fromisoformat does not handle.
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            raise InvalidTimestampError(
                "ts is not a valid ISO-8601 timestamp",
                details={"value": value})
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ts = dt.timestamp()
    else:
        raise InvalidTimestampError(
            "ts must be a number or ISO-8601 string",
            details={"got": type(value).__name__})
    if not math.isfinite(ts):
        raise InvalidTimestampError("ts must be finite",
                                    details={"value": value})
    return ts


def normalize_event(
    payload: Any,
    *,
    now: float,
    config: PipelineConfig,
) -> Event:
    """Validate and normalize a raw payload. Raises on any problem.

    No state lookup happens here (sequence number, dedupe, capacity); the
    caller performs those atomically after this function returns, which
    guarantees rejected requests never perform a partial write.
    """
    if not isinstance(payload, dict):
        raise MalformedPayloadError(
            "event payload must be a JSON object",
            details={"got": type(payload).__name__})

    # 1) required presence --------------------------------------------------
    for name in REQUIRED_FIELDS:
        if name not in payload or payload[name] is None or payload[name] == "":
            raise MissingFieldError(
                f"required field '{name}' is missing or empty",
                details={"field": name})

    # 2) id ------------------------------------------------------------------
    eid = payload["id"]
    if not isinstance(eid, str):
        raise InvalidFieldValueError("id must be a string",
                                     details={"field": "id"})

    # 3) source --------------------------------------------------------------
    source = payload["source"]
    if not isinstance(source, str):
        raise InvalidFieldValueError("source must be a string",
                                     details={"field": "source"})
    if source not in KNOWN_SOURCES:
        raise UnknownSourceError(
            "source is not registered / not recognizable",
            details={"source": source, "known_sources": sorted(KNOWN_SOURCES)})

    # 4) event_type / severity ----------------------------------------------
    event_type = payload["event_type"]
    if not isinstance(event_type, str):
        raise InvalidFieldValueError("event_type must be a string",
                                     details={"field": "event_type"})
    severity = payload["severity"]
    if not isinstance(severity, str):
        raise InvalidFieldValueError("severity must be a string",
                                     details={"field": "severity"})
    if severity not in VALID_SEVERITIES:
        raise InvalidFieldValueError(
            "severity must be one of the allowed levels",
            details={"field": "severity", "value": severity,
                     "valid": sorted(VALID_SEVERITIES)})

    # 5) timestamp -----------------------------------------------------------
    ts = parse_timestamp(payload["ts"])
    if ts > now + config.max_future_skew_seconds:
        raise EventInFutureError(
            "event ts is further in the future than the allowed clock skew",
            details={"ts": ts, "now": now,
                     "max_skew": config.max_future_skew_seconds})

    # 6) optional scalar fields (strictly strings when present) ------------
    norm: dict[str, str | None] = {}
    for name in OPTIONAL_STR_FIELDS:
        val = payload.get(name)
        if val is None:
            norm[name] = None
        elif isinstance(val, str):
            norm[name] = val
        else:
            raise InvalidFieldValueError(
                f"{name} must be a string", details={"field": name,
                                                     "got": type(val).__name__})

    # 7) unknown keys become source-specific raw extras ---------------------
    known = set(REQUIRED_FIELDS) | set(OPTIONAL_STR_FIELDS)
    extras = {k: v for k, v in payload.items() if k not in known}
    if len(extras) > config.max_raw_fields_per_event:
        raise CapacityExceededError(
            "too many custom raw fields on event",
            details={"count": len(extras),
                     "max": config.max_raw_fields_per_event})
    raw: dict[str, str] = {}
    for key, val in extras.items():
        if not isinstance(key, str):
            raise InvalidFieldValueError("raw field names must be strings")
        if isinstance(val, (str, int, float)) and not isinstance(val, bool):
            raw[key] = str(val) if not isinstance(val, str) else val
        elif val is None:
            continue  # explicit null extras carry no information
        else:
            raise InvalidFieldValueError(
                f"raw field '{key}' must be a scalar",
                details={"field": key})

    return Event(
        id=eid, source=source, event_type=event_type, severity=severity,
        ts=ts, src_ip=norm["src_ip"], dst_ip=norm["dst_ip"],
        user=norm["user"], host=norm["host"], action=norm["action"],
        raw=raw)
