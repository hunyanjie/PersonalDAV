"""personaldavd daemon — FastAPI app factory."""

import os
import sys
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.routing import APIRoute

from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_DESCRIPTION
from .config import DaemonConfig
from .dav import dav_router
from .api import api_router
from .files import files_router
from .auth import AuthMiddleware
from .logging import StructuredLogger
from .mcp import create_mcp_app


def _unique_id(route: APIRoute) -> str:
    path = route.path.replace("{", "").replace("}", "").replace("/", "_")
    methods = "_".join(sorted(route.methods - {"HEAD", "OPTIONS"})) if route.methods else "any"
    return f"{path}_{methods}".lower()

logger: StructuredLogger | None = None

# Custom uvicorn log config: propagate uvicorn.access to root logger
# so HTTP access lines are captured by LogBufferHandler, RotatingFileHandler, and GUIHandler.
UVICORN_LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
            "use_colors": None,
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
            "use_colors": None,
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
    },
    "loggers": {
        "uvicorn": {"handlers": ["default"], "level": "INFO"},
        "uvicorn.error": {"level": "INFO"},
        "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": True},
    },
}


# Ensure database & WebDAV root exist before first request
def _init_environment(cfg: "DaemonConfig"):
    import sqlite3
    os.makedirs(os.path.dirname(cfg.db_path) or ".", exist_ok=True)
    if cfg.dav_root:
        os.makedirs(cfg.dav_root, exist_ok=True)
    conn = sqlite3.connect(cfg.db_path)
    conn.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global logger
    cfg: DaemonConfig = app.state.config
    logger = StructuredLogger(cfg.log_json)
    _init_environment(cfg)
    logger.info(f"{SOFTWARE_NAME} daemon starting", extra={"version": SOFTWARE_VERSION, "host": cfg.host, "port": cfg.port})
    yield
    logger.info(f"{SOFTWARE_NAME} daemon stopped")


def create_app(config: DaemonConfig | None = None) -> FastAPI:
    cfg = config or DaemonConfig()
    app = FastAPI(
        title=SOFTWARE_NAME,
        description=SOFTWARE_DESCRIPTION,
        version=SOFTWARE_VERSION,
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
        generate_unique_id_function=_unique_id,
        swagger_ui_parameters={"displayRequestDuration": True, "defaultModelsExpandDepth": -1},
    )
    app.state.config = cfg
    app.add_middleware(AuthMiddleware)

    if cfg.webui_enabled:
        app.include_router(api_router, prefix="/api")
        app.include_router(files_router, prefix="/api")
        app.mount("/mcp", create_mcp_app(), name="mcp")

        webui_dist = os.path.join(os.path.dirname(__file__), "..", "webui", "dist")
        if os.path.isdir(webui_dist):
            from fastapi.responses import FileResponse
            app.mount("/assets", StaticFiles(directory=os.path.join(webui_dist, "assets")), name="spa_assets")
            @app.get("/", include_in_schema=False)
            async def serve_spa():
                return FileResponse(os.path.join(webui_dist, "index.html"))

    app.include_router(dav_router)
    return app


class DaemonServer:
    """统一 FastAPI 服务器封装，接口与旧 DAVServer 兼容。

    start() / stop() 生命周期管理，内部使用 uvicorn.Server 程序化启停，
    同时提供 REST API、MCP、Web UI SPA 以及传统 DAV 协议。
    支持双端口：HTTP + HTTPS（若启用 SSL）。
    """

    def __init__(self, config: DaemonConfig):
        self.config = config
        self._servers = []
        self.start_time = 0.0
        self._secondary_threads = []

    def start(self):
        import time as _time
        import uvicorn
        self.start_time = _time.time()
        app = create_app(self.config)
        self._servers.clear()
        self._secondary_threads.clear()

        # HTTP — always started
        uv_config_http = uvicorn.Config(
            app,
            host=self.config.host,
            port=self.config.port,
            log_level=self.config.log_level.lower(),
            log_config=UVICORN_LOG_CONFIG,
        )
        server_http = uvicorn.Server(uv_config_http)
        self._servers.append(server_http)

        # HTTPS — if SSL enabled (port = config.port + 1)
        if self.config.ssl_enabled and self.config.ssl_keyfile and self.config.ssl_certfile:
            ssl_port = self.config.port + 1
            uv_config_https = uvicorn.Config(
                app,
                host=self.config.host,
                port=ssl_port,
                log_level=self.config.log_level.lower(),
                ssl_keyfile=self.config.ssl_keyfile,
                ssl_certfile=self.config.ssl_certfile,
                log_config=UVICORN_LOG_CONFIG,
            )
            server_https = uvicorn.Server(uv_config_https)
            self._servers.append(server_https)
            t = threading.Thread(target=server_https.run, daemon=True)
            t.start()
            self._secondary_threads.append(t)
            self.ssl_port = ssl_port
        else:
            self.ssl_port = None

        # Block on HTTP (headless mode), or just run (GUI background thread)
        server_http.run()

    def stop(self):
        for srv in self._servers:
            srv.should_exit = True
        self._servers.clear()
        self._secondary_threads.clear()
        self.ssl_port = None


def run_daemon(config: DaemonConfig | None = None):
    cfg = config or DaemonConfig()
    server = DaemonServer(cfg)
    server.start()
