"""personaldavd daemon — FastAPI app factory."""

import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import DaemonConfig
from .dav import dav_router
from .api import api_router
from .auth import AuthMiddleware
from .logging import StructuredLogger
from .mcp import create_mcp_app

logger: StructuredLogger | None = None


# Ensure database & WebDAV root exist before first request
def _init_environment(cfg: "DaemonConfig"):
    import sqlite3
    os.makedirs(os.path.dirname(cfg.db_path) or ".", exist_ok=True)
    os.makedirs(cfg.dav_root, exist_ok=True)
    # Touch DB so tables are created on first service access
    conn = sqlite3.connect(cfg.db_path)
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global logger
    cfg: DaemonConfig = app.state.config
    logger = StructuredLogger(cfg.log_json)
    _init_environment(cfg)
    logger.info("PersonalDAV daemon starting", extra={"version": "3.0.0", "host": cfg.host, "port": cfg.port})
    yield
    logger.info("PersonalDAV daemon stopped")


def create_app(config: DaemonConfig | None = None) -> FastAPI:
    cfg = config or DaemonConfig()
    app = FastAPI(
        title="PersonalDAV",
        description="Personal Infrastructure Platform — CardDAV + CalDAV + WebDAV + REST API",
        version="3.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.state.config = cfg
    app.add_middleware(AuthMiddleware)
    app.include_router(api_router, prefix="/api")
    app.include_router(dav_router)
    app.mount("/mcp", create_mcp_app(), name="mcp")
    return app


def run_daemon(config: DaemonConfig | None = None):
    import uvicorn
    cfg = config or DaemonConfig()
    app = create_app(cfg)
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level=cfg.log_level.lower())
