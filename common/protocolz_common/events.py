"""Append-only JSON-lines security event log (owner-only permissions)."""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


class EventLog:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event_type: str, **fields) -> dict:
        record = {"ts": datetime.now(timezone.utc).isoformat(), "type": event_type, **fields}
        line = json.dumps(record, sort_keys=True, default=str)
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return record
