"""Structured JSON logging."""

import json
import logging
import os
import sys
import queue
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

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

def setup_file_logging(log_path: str | None = None):
    """Add RotatingFileHandler to the root logger for persistence."""
    if not log_path:
        log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "log", "personaldavd.log")
    root = logging.getLogger()
    for h in root.handlers:
        if isinstance(h, RotatingFileHandler):
            return
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    fh = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
    fh.setLevel(logging.DEBUG)
    root.addHandler(fh)


class StructuredLogger:
    """Minimal structured logger — outputs JSON lines when json_mode=True."""

    def __init__(self, json_mode: bool = False):
        self._json_mode = json_mode
        self._logger = logging.getLogger("personaldavd")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = True
        
        # Suppress noisy but harmless asyncio ConnectionResetError tracebacks
        logging.getLogger("asyncio").setLevel(logging.WARNING)

        root = logging.getLogger()
        if not any(isinstance(h, LogBufferHandler) for h in root.handlers):
            h = LogBufferHandler()
            h.setFormatter(logging.Formatter('%(message)s'))
            root.addHandler(h)
        for name in ("personaldavd", "PersonalDAV"):
            lg = logging.getLogger(name)
            if not any(isinstance(h, LogBufferHandler) for h in lg.handlers):
                buf = LogBufferHandler()
                buf.setFormatter(logging.Formatter('%(message)s'))
                lg.addHandler(buf)
        if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
            setup_file_logging()

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
