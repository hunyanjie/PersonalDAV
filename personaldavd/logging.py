"""Structured JSON logging."""

import json
import logging
import sys
import queue
from datetime import datetime, timezone

# Global log buffer for WebUI
LOG_QUEUE = queue.Queue(maxsize=1000)

class LogBufferHandler(logging.Handler):
    """Handler that pushes logs to a global queue."""
    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            if LOG_QUEUE.full():
                try: LOG_QUEUE.get_nowait()
                except queue.Empty: pass
            LOG_QUEUE.put_nowait({
                "time": datetime.fromtimestamp(record.created).isoformat(),
                "level": record.levelname,
                "name": record.name,
                "message": record.getMessage(),
            })
        except Exception:
            self.handleError(record)

class StructuredLogger:
    """Minimal structured logger — outputs JSON lines when json_mode=True."""

    def __init__(self, json_mode: bool = False):
        self._json_mode = json_mode
        self._logger = logging.getLogger("personaldavd")
        
        # Ensure our buffer handler is attached to the root logger or personaldavd logger
        if not any(isinstance(h, LogBufferHandler) for h in logging.getLogger().handlers):
            h = LogBufferHandler()
            h.setFormatter(logging.Formatter('%(message)s'))
            logging.getLogger().addHandler(h)

    def _log(self, level: str, message: str, extra: dict | None = None):
        # Also log via standard logging so LogBufferHandler picks it up
        level_num = getattr(logging, level.upper(), logging.INFO)
        self._logger.log(level_num, message, extra=extra)

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
