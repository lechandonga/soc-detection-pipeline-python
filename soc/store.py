"""Append-only persistence.

Durability model
----------------
* ``events.jsonl``  - one line per *intake attempt* (accepted or too_late;
  rejected requests are never written, so they cannot leave partial state).
* ``alerts.jsonl``  - one line per alert lifecycle command, appended
  *before* the in-memory state change becomes observable. Every line carries
  the rule-set version and firing ``match_key`` that caused it, so replay is
  deterministic.
* ``rules.json``     - the declarative rule + suppression config, written to
  a temp file and atomically renamed (readers never see a half-written file).

Because alert commands are derived deterministically from the event stream,
rebuilding state by replay always yields the same alerts, counts and
lifecycle states.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterator
from typing import Any


class Store:
    def __init__(self, directory: str | None = None) -> None:
        self.directory = directory
        if directory:
            os.makedirs(directory, exist_ok=True)
            self._events_path = os.path.join(directory, "events.jsonl")
            self._alerts_path = os.path.join(directory, "alerts.jsonl")
            self._rules_path = os.path.join(directory, "rules.json")
        else:
            self._events_path = self._alerts_path = self._rules_path = None
        self._events_f = self._open_append(self._events_path)
        self._alerts_f = self._open_append(self._alerts_path)

    @staticmethod
    def _open_append(path: str | None):
        if path is None:
            return None
        return open(path, "a", encoding="utf-8")

    # ------------------------------------------------------------- writes
    def append_event(self, record: dict) -> None:
        self._append(self._events_f, record)

    def append_alert_command(self, record: dict) -> None:
        self._append(self._alerts_f, record)

    @staticmethod
    def _append(handle, record: dict) -> None:
        if handle is None:
            return
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())  # durable before the caller proceeds

    def save_rules(self, payload: dict) -> None:
        """Atomic write of rule configuration (temp file + os.replace)."""
        if self._rules_path is None:
            return
        fd, tmp = tempfile.mkstemp(dir=self.directory, prefix=".rules-",
                                   suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._rules_path)  # atomic on POSIX/Windows
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # ------------------------------------------------------------- reads
    def read_events(self) -> Iterator[dict[str, Any]]:
        yield from self._read_jsonl(self._events_path)

    def read_alert_commands(self) -> Iterator[dict[str, Any]]:
        yield from self._read_jsonl(self._alerts_path)

    @staticmethod
    def _read_jsonl(path: str | None) -> Iterator[dict[str, Any]]:
        if not path or not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    yield json.loads(line)

    def load_rules_raw(self) -> dict | None:
        if not self._rules_path or not os.path.exists(self._rules_path):
            return None
        with open(self._rules_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def close(self) -> None:
        for handle in (self._events_f, self._alerts_f):
            if handle is not None:
                handle.close()
        self._events_f = self._alerts_f = None

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
