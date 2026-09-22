"""Domain errors with distinct, stable reason codes.

Each error exposes a machine-readable ``reason`` so that callers (and tests)
can distinguish *why* a request was rejected instead of relying on message
text matching.
"""
from __future__ import annotations


class SocError(Exception):
    """Base error carrying a machine-readable ``reason`` code."""

    reason: str = "soc_error"

    def __init__(self, message: str = "", *, reason: str | None = None,
                 details: dict | None = None) -> None:
        super().__init__(message or self.reason)
        if reason is not None:
            self.reason = reason
        self.message = message or self.reason
        self.details: dict = details or {}

    def to_dict(self) -> dict:
        return {"reason": self.reason, "message": self.message,
                "details": self.details}


# ---------------------------------------------------------------- ingestion
class EventRejectedError(SocError):
    """Base class for events rejected at intake (no state is written)."""

    reason = "event_rejected"


class MalformedPayloadError(EventRejectedError):
    """Request body is not a well-formed event object."""

    reason = "malformed_payload"


class MissingFieldError(EventRejectedError):
    """A required field is absent or null."""

    reason = "missing_field"


class InvalidFieldValueError(EventRejectedError):
    """A field has the wrong type or an illegal value."""

    reason = "invalid_field_value"


class InvalidTimestampError(EventRejectedError):
    """The timestamp cannot be parsed / is not a valid epoch time."""

    reason = "invalid_timestamp"


class EventInFutureError(EventRejectedError):
    """The event timestamp lies beyond the allowed future skew."""

    reason = "event_too_far_in_future"


class UnknownSourceError(EventRejectedError):
    """The event source identifier is not registered / not recognizable."""

    reason = "unknown_source"


class DuplicateEventError(EventRejectedError):
    """An event with the same id has already been ingested."""

    reason = "duplicate_event"


class CapacityExceededError(EventRejectedError):
    """A configured size limit has been reached."""

    reason = "capacity_exceeded"


# -------------------------------------------------------------------- rules
class RuleError(SocError):
    reason = "rule_error"


class InvalidRuleError(RuleError):
    """A rule document violates the declarative schema."""

    reason = "invalid_rule"


class UnknownFieldReferenceError(InvalidRuleError):
    """A rule references a field that is not part of the event schema."""

    reason = "unknown_field_reference"


class DuplicateRuleError(RuleError):
    reason = "duplicate_rule"


class RuleNotFoundError(RuleError):
    reason = "rule_not_found"


# ------------------------------------------------------------------- alerts
class AlertError(SocError):
    reason = "alert_error"


class AlertNotFoundError(AlertError):
    reason = "alert_not_found"


class InvalidStateTransitionError(AlertError):
    """Requested lifecycle transition is not permitted from the current state."""

    reason = "invalid_state_transition"


class SuppressionError(RuleError):
    reason = "invalid_suppression"
