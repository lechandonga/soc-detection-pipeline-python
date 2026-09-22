"""持久化：每行一个 JSON 的仅追加 WAL。

原子性：先把完整的一行（以 \\n 结尾）写入临时缓冲再 flush+fsync；
调用方在 *任何内存状态变更之前* 完成 append，因此 append 失败时
内存尚未改动，不存在半写入状态；行一旦 fsync 即完整可读，重放时
只承认以换行结尾的完整行（崩溃留下的半行被确定性地忽略）。
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator


class JsonlStore:
    def __init__(self, path: str) -> None:
        self._path = path
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        # 行缓冲禁用：自己控制 flush/fsync，避免跨调用共享的部分行
        self._fh = open(path, "a", encoding="utf-8", buffering=1, newline="\n")  # noqa: SIM115 长生命周期 WAL 句柄

    def append(self, record: dict) -> None:
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        # 完整行一次性写入并落盘
        self._fh.write(line + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())

    def replay(self) -> Iterator[dict]:
        # 从磁盘重新顺序读取，只产出完整行，保证可复现
        with open(self._path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.endswith("\n"):
                    # 崩溃残留的半行：确定性忽略
                    continue
                line = line.strip()
                if line:
                    yield json.loads(line)

    def close(self) -> None:
        try:
            self._fh.flush()
            os.fsync(self._fh.fileno())
        finally:
            self._fh.close()
