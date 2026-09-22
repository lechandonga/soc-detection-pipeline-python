"""Declarative detection rules: schema, validation, immutable rule set.

Two rule kinds are supported:

* ``threshold``  - fires when ``count`` matching events occur within
  ``window_seconds`` for the same ``group_by`` key.
* ``sequence``   - fires when the ordered ``steps`` filters are matched by
  distinct events within ``window_seconds`` for the same group key.

A rule document is fully validated at *load time*. An invalid document or a
reference to a non-existent normalized field aborts the whole load, so a
running pipeline never observes a half-valid rule collection. The live rule
set itself is an immutable snapshot replaced atomically.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from soc.errors import DuplicateRuleError, InvalidRuleError, UnknownFieldReferenceError
from soc.models import EVENT_FIELDS

VALID_OPERATORS = frozenset({"eq", "ne", "in", "notin", "contains",
                             "prefix", "regex", "exists", "gt", "lt", "gte", "lte"})
VALID_KINDS = frozenset({"threshold", "sequence"})


@dataclass(frozen=True)
class Filter:
    """A single field predicate applied to a normalized event."""

    field: str
    op: str
    value: Any = None

    @classmethod
    def from_dict(cls, data: Any) -> "Filter":
        if not isinstance(data, dict):
            raise InvalidRuleError("filter must be an object",
                                   details={"got": type(data).__name__})
        missing = {"field", "op"} - set(data)
        if missing:
            raise InvalidRuleError(
                "filter missing required keys",
                details={"missing": sorted(missing)})
        fld = data["field"]
        op = data["op"]
        if not isinstance(fld, str) or not fld:
            raise InvalidRuleError("filter.field must be a non-empty string")
        if op not in VALID_OPERATORS:
            raise InvalidRuleError(
                "unknown operator",
                details={"op": op, "valid": sorted(VALID_OPERATORS)})
        if op in {"in", "notin"}:
            val = data.get("value")
            if not isinstance(val, list) or not val:
                raise InvalidRuleError(
                    f"operator {op} requires a non-empty list value",
                    details={"field": fld})
        elif op != "exists":
            if "value" not in data or data["value"] is None:
                raise InvalidRuleError(
                    f"operator {op} requires a value", details={"field": fld})
            val = data["value"]
            # Only string/scalar comparison is supported declaratively.
            if not isinstance(val, (str, int, float, bool)):
                raise InvalidRuleError(
                    "filter value must be a scalar", details={"field": fld})
        else:
            val = data.get("value", True)
            if not isinstance(val, bool):
                raise InvalidRuleError(
                    "exists value must be boolean", details={"field": fld})
        _validate_field_ref(fld)
        return cls(field=fld, op=op, value=val)

    def matches(self, event: Any) -> bool:
        actual = event.get(self.field)
        op, expected = self.op, self.value
        if op == "exists":
            return (actual is not None and actual != "") == expected
        if actual is None:
            return False
        if op == "eq":
            return str(actual) == str(expected)
        if op == "ne":
            return str(actual) != str(expected)
        if op == "in":
            return str(actual) in {str(v) for v in expected}
        if op == "notin":
            return str(actual) not in {str(v) for v in expected}
        if op == "contains":
            return str(expected) in str(actual)
        if op == "prefix":
            return str(actual).startswith(str(expected))
        if op == "regex":
            import re
            return re.search(str(expected), str(actual)) is not None
        # Numeric comparisons on normalised scalar fields.
        try:
            a, b = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        if op == "gt":
            return a > b
        if op == "lt":
            return a < b
        if op == "gte":
            return a >= b
        if op == "lte":
            return a <= b
        return False

    def to_dict(self) -> dict:
        return {"field": self.field, "op": self.op, "value": self.value}


def _validate_field_ref(fld: str) -> None:
    """Normalized fields must exist; ``raw.`` extras are accepted by name."""
    if fld.startswith("raw."):
        return
    if "." in fld:
        raise UnknownFieldReferenceError(
            "unknown dotted field reference", details={"field": fld})
    if fld not in EVENT_FIELDS:
        raise UnknownFieldReferenceError(
            "rule references a field that is not part of the event schema",
            details={"field": fld, "known_fields": sorted(EVENT_FIELDS)})


def _validate_group_fields(fields: tuple[str, ...]) -> None:
    for fld in fields:
        _validate_field_ref(fld)


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    name: str
    filters: tuple[Filter, ...] = field(default_factory=tuple)
    # threshold
    count: int = 1
    # sequence
    steps: tuple[tuple[Filter, ...], ...] = field(default_factory=tuple)
    group_by: tuple[str, ...] = ()
    window_seconds: float | None = None
    severity: str = "medium"
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: Any) -> "Rule":
        if not isinstance(data, dict):
            raise InvalidRuleError("rule must be an object",
                                   details={"got": type(data).__name__})
        missing = {"id", "kind"} - set(data)
        if missing:
            raise InvalidRuleError("rule missing required keys",
                                   details={"missing": sorted(missing)})
        rid = data["id"]
        kind = data["kind"]
        if not isinstance(rid, str) or not rid:
            raise InvalidRuleError("rule.id must be a non-empty string")
        if kind not in VALID_KINDS:
            raise InvalidRuleError(
                "unknown rule kind",
                details={"kind": kind, "valid": sorted(VALID_KINDS)})
        window = data.get("window_seconds")
        if window is not None and (not isinstance(window, (int, float))
                                   or window <= 0):
            raise InvalidRuleError(
                "window_seconds must be a positive number",
                details={"rule_id": rid})
        gb = data.get("group_by", [])
        if isinstance(gb, str):
            gb = [gb]
        if not isinstance(gb, list) or not all(isinstance(g, str) for g in gb):
            raise InvalidRuleError(
                "group_by must be a list of field names",
                details={"rule_id": rid})
        _validate_group_fields(tuple(gb))

        filters = tuple(Filter.from_dict(f) for f in data.get("filters", []))

        count, steps = 1, ()
        if kind == "threshold":
            count = data.get("count", 1)
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                raise InvalidRuleError(
                    "threshold count must be an integer >= 1",
                    details={"rule_id": rid})
        else:  # sequence
            raw_steps = data.get("steps")
            if not isinstance(raw_steps, list) or len(raw_steps) < 2:
                raise InvalidRuleError(
                    "sequence rule requires at least 2 steps",
                    details={"rule_id": rid})
            steps = tuple(
                tuple(Filter.from_dict(f) for f in (step if isinstance(step, list)
                                                    else [step]))
                for step in raw_steps)

        return cls(
            id=rid, kind=kind, name=str(data.get("name", rid)),
            filters=filters, count=count, steps=steps,
            group_by=tuple(gb), window_seconds=window,
            severity=str(data.get("severity", "medium")),
            enabled=bool(data.get("enabled", True)),
        )

    def effective_window(self, default: float) -> float:
        return self.window_seconds if self.window_seconds else default

    def matches_filters(self, event: Any) -> bool:
        return all(f.matches(event) for f in self.filters)

    def group_key(self, event: Any) -> str:
        if not self.group_by:
            return "_global"
        return "|".join(f"{f}={event.get(f)}" for f in self.group_by)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "name": self.name,
            "filters": [f.to_dict() for f in self.filters],
            "count": self.count,
            "steps": [[f.to_dict() for f in step] for step in self.steps],
            "group_by": list(self.group_by),
            "window_seconds": self.window_seconds,
            "severity": self.severity, "enabled": self.enabled,
        }


@dataclass(frozen=True)
class RuleSet:
    """Immutable snapshot of all rules. Replacements are atomic."""

    rules: tuple[Rule, ...] = ()
    version: int = 0

    def get(self, rule_id: str) -> Rule | None:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def to_dict(self) -> dict:
        return {"version": self.version,
                "rules": [r.to_dict() for r in self.rules]}


def build_ruleset(docs: list[dict], *, version: int,
                  max_rules: int = 1000) -> RuleSet:
    """Validate every document first; return an immutable set.

    Validation is all-or-nothing: any invalid document raises before a
    RuleSet is constructed, so callers cannot partially update rules.
    """
    parsed: list[Rule] = []
    seen: set[str] = set()
    for doc in docs:
        rule = Rule.from_dict(doc)
        if rule.id in seen:
            raise DuplicateRuleError("duplicate rule id",
                                     details={"rule_id": rule.id})
        seen.add(rule.id)
        parsed.append(rule)
    if len(parsed) > max_rules:
        from soc.errors import CapacityExceededError
        raise CapacityExceededError(
            "rule count exceeds configured maximum",
            details={"count": len(parsed), "max": max_rules})
    return RuleSet(rules=tuple(parsed), version=version)
