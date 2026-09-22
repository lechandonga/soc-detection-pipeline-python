"""服务入口：uvicorn main:app

检测服务的数据目录由环境变量 SOC_DATA_DIR 覆盖（默认 ./data）。
"""

from __future__ import annotations

import os

from app.api import create_app
from app.config import load_config
from app.service import DetectionService

_config = load_config(os.environ.get("SOC_CONFIG"))
if os.environ.get("SOC_DATA_DIR"):
    from dataclasses import replace

    _config = replace(_config, data_dir=os.environ["SOC_DATA_DIR"])

service = DetectionService(config=_config)
app = create_app(service)
