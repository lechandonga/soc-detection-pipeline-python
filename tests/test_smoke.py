"""骨架冒烟测试：导入所有模块、实例化应用。"""

import tempfile
from dataclasses import replace


def test_imports():
    import importlib

    for name in [
        "app.errors", "app.models", "app.config", "app.context",
        "app.ingestion", "app.rules", "app.correlation", "app.alerts",
        "app.storage", "app.service", "app.api",
    ]:
        importlib.import_module(name)


def test_app_health():
    from fastapi.testclient import TestClient

    from app.api import create_app
    from app.models import Config
    from app.service import DetectionService

    svc = DetectionService(config=replace(Config(), data_dir=tempfile.mkdtemp()))
    client = TestClient(create_app(svc))
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
