"""HTTP 层：把领域异常翻译为带稳定 reason 的确定性响应。

所有状态变更都经由 DetectionService（内部加锁、两阶段提交），
因此本层只做参数解析与错误映射，不持有可变状态。
"""

from __future__ import annotations

import json

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .errors import (
    AlertNotFound,
    AlertTransitionRejected,
    EventRejected,
    LimitExceeded,
    PipelineError,
    RuleNotFound,
    RuleRejected,
)
from .service import DetectionService


def _error(status_code: int, reason: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": True, "reason": reason, "message": message},
    )


def create_app(service: DetectionService | None = None) -> FastAPI:
    app = FastAPI(title="SOC Detection Pipeline", version="0.1.0")
    svc = service

    def get_service() -> DetectionService:
        if svc is None:
            raise RuntimeError("DetectionService 尚未初始化")
        return svc

    @app.exception_handler(EventRejected)
    async def _event_rejected(_req: Request, exc: EventRejected) -> JSONResponse:
        return _error(422, exc.reason, str(exc))

    @app.exception_handler(RuleRejected)
    async def _rule_rejected(_req: Request, exc: RuleRejected) -> JSONResponse:
        return _error(422, exc.reason, str(exc))

    @app.exception_handler(AlertTransitionRejected)
    async def _transition_rejected(
        _req: Request, exc: AlertTransitionRejected
    ) -> JSONResponse:
        return _error(409, exc.reason, str(exc))

    @app.exception_handler(LimitExceeded)
    async def _limit(_req: Request, exc: LimitExceeded) -> JSONResponse:
        return _error(429, exc.reason, str(exc))

    @app.exception_handler(AlertNotFound)
    @app.exception_handler(RuleNotFound)
    async def _not_found(_req: Request, exc: PipelineError) -> JSONResponse:
        return _error(404, exc.reason, str(exc))

    @app.exception_handler(PipelineError)
    async def _pipeline(_req: Request, exc: PipelineError) -> JSONResponse:
        return _error(400, exc.reason, str(exc))

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", **get_service().stats()}

    @app.post("/events")
    async def ingest(request: Request) -> dict:
        try:
            raw = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return _error(422, "invalid_payload", f"请求体不是合法 JSON: {exc}")
        return get_service().ingest(raw)

    @app.put("/rules")
    async def replace_rules(request: Request) -> dict:
        try:
            raw = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return _error(422, "invalid_payload", f"请求体不是合法 JSON: {exc}")
        if not isinstance(raw, list):
            return _error(422, "invalid_rule_config", "规则集合必须是 JSON 数组")
        return get_service().replace_rules(raw)

    @app.get("/alerts")
    async def list_alerts() -> dict:
        return {"alerts": get_service().list_alerts()}

    @app.get("/alerts/{alert_id}")
    async def get_alert(alert_id: str) -> dict:
        return get_service().get_alert(alert_id)

    @app.post("/alerts/{alert_id}/transition")
    async def transition_alert(alert_id: str, request: Request) -> dict:
        try:
            body = await request.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = {}
        action = body.get("action") if isinstance(body, dict) else None
        return get_service().transition_alert(alert_id, action)

    @app.post("/replay")
    async def replay() -> dict:
        return get_service().replay_all()

    return app
