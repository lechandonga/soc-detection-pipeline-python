"""FastAPI HTTP layer.

All state lives behind one :class:`DetectionService`; handlers only
translate HTTP <-> domain calls, so concurrency and atomicity guarantees
come from the service. Distinct domain errors map to distinct HTTP responses
with their machine-readable ``reason`` preserved.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from soc.config import PipelineConfig
from soc.errors import (
    AlertNotFoundError,
    DuplicateEventError,
    EventRejectedError,
    RuleError,
    SocError,
)
from soc.service import DetectionService
from soc.store import Store


def create_app(*, data_dir: str | None = None,
               config: PipelineConfig | None = None,
               service: DetectionService | None = None) -> FastAPI:
    app = FastAPI(title="SOC Detection Pipeline", version="0.1.0")

    data_dir = data_dir or os.environ.get("SOC_DATA_DIR")
    if service is None:
        cfg = config or PipelineConfig()
        service = DetectionService(config=cfg, store=Store(data_dir))
    app.state.service = service

    # ---------------------------------------------------------- error map
    def error_response(exc: SocError, status: int) -> JSONResponse:
        return JSONResponse(status_code=status,
                            content={"error": exc.to_dict()})

    @app.exception_handler(EventRejectedError)
    async def _event_rejected(_: Request, exc: EventRejectedError):
        code = 409 if isinstance(exc, DuplicateEventError) else 422
        return error_response(exc, code)

    @app.exception_handler(RuleError)
    async def _rule_error(_: Request, exc: RuleError):
        return error_response(exc, 400)

    @app.exception_handler(AlertNotFoundError)
    async def _alert_missing(_: Request, exc: AlertNotFoundError):
        return error_response(exc, 404)

    @app.exception_handler(SocError)
    async def _soc_error(_: Request, exc: SocError):
        return error_response(exc, 409)

    # -------------------------------------------------------------- health
    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # ------------------------------------------------------------- events
    @app.post("/api/v1/events")
    async def ingest_event(request: Request) -> dict:
        # Parse manually so a malformed JSON body becomes malformed_payload,
        # rather than FastAPI's generic 422.
        try:
            payload = await request.json()
        except Exception:
            from soc.errors import MalformedPayloadError
            raise MalformedPayloadError("request body is not valid JSON")
        result = service.ingest(payload)
        # too_late is an accepted-for-archival conclusion, not an error
        status = 202 if result["status"] == "too_late" else 201
        return JSONResponse(status_code=status, content=result)

    @app.get("/api/v1/events/{event_id}")
    def get_event(event_id: str) -> dict:
        return service.event_status(event_id)

    # -------------------------------------------------------------- rules
    @app.get("/api/v1/rules")
    def get_rules() -> dict:
        return service.rules_snapshot()

    @app.put("/api/v1/rules")
    async def replace_rules(request: Request) -> dict:
        try:
            body = await request.json()
        except Exception:
            from soc.errors import MalformedPayloadError
            raise MalformedPayloadError("request body is not valid JSON")
        rules = body.get("rules") if isinstance(body, dict) else None
        suppressions = body.get("suppressions", []) if isinstance(body, dict) else []
        if not isinstance(rules, list):
            from soc.errors import InvalidRuleError
            raise InvalidRuleError(
                "body must be an object with a 'rules' list")
        return service.replace_rules(rules, suppressions)

    # ------------------------------------------------------------- alerts
    @app.get("/api/v1/alerts")
    def list_alerts(state: str | None = None) -> list[dict]:
        return service.list_alerts(state)

    @app.get("/api/v1/alerts/{alert_id}")
    def get_alert(alert_id: str) -> dict:
        return service.get_alert(alert_id)

    @app.post("/api/v1/alerts/{alert_id}/transition")
    async def transition_alert(alert_id: str, request: Request) -> dict:
        try:
            body = await request.json()
        except Exception:
            body = {}
        action = body.get("action") if isinstance(body, dict) else None
        reason = body.get("reason", "") if isinstance(body, dict) else ""
        if not action:
            from soc.errors import InvalidStateTransitionError
            raise InvalidStateTransitionError(
                "body must contain an 'action'",
                details={"alert_id": alert_id})
        return service.transition_alert(alert_id, action, reason=reason)

    return app


app = create_app()
