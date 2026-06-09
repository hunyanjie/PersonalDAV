"""Structured JSON logging."""

import json
import logging
import sys
from datetime import datetime, timezone


class StructuredLogger:
    """Minimal structured logger — outputs JSON lines when json_mode=True."""

    def __init__(self, json_mode: bool = False):
        self._json_mode = json_mode
        self._logger = logging.getLogger("personaldavd")

    def _log(self, level: str, message: str, extra: dict | None = None):
        if self._json_mode:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": level,
                "message": message,
                **(extra or {}),
            }
            print(json.dumps(record, ensure_ascii=False), file=sys.stderr)
        else:
            prefix = f"[{datetime.now().isoformat()}] [{level}]"
            extra_str = f" {extra}" if extra else ""
            print(f"{prefix} {message}{extra_str}", file=sys.stderr)

    def info(self, message: str, **extra):
        self._log("INFO", message, extra or None)

    def warning(self, message: str, **extra):
        self._log("WARNING", message, extra or None)

    def error(self, message: str, **extra):
        self._log("ERROR", message, extra or None)

    def debug(self, message: str, **extra):
        self._log("DEBUG", message, extra or None)
