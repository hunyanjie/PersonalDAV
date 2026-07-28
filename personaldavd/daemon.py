"""personaldavd daemon — FastAPI app factory."""

import os
import sys
import threading
from contextlib import asynccontextmanager
from logging import getLogger

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
    
    # 同步回收站索引
    from services.trash_service import TrashService
    TrashService.startup_init()
    
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

    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        import traceback
        tb = traceback.format_exc()
        logger = getLogger("personaldavd")
        logger.error("未捕获异常 [%s %s]: %s\n%s", request.method, request.url.path, exc, tb)
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=500,
            content={"detail": f"{type(exc).__name__}: {exc}", "path": request.url.path}
        )

    if cfg.webui_enabled:
        app.include_router(api_router, prefix="/api")
        app.include_router(files_router, prefix="/api")
        app.mount("/mcp", create_mcp_app(), name="mcp")

        webui_dist = os.path.join(os.path.dirname(__file__), "..", "webui", "dist")
        if os.path.isdir(webui_dist):
            from fastapi.responses import FileResponse
            app.mount("/assets", StaticFiles(directory=os.path.join(webui_dist, "assets")), name="spa_assets")
            icons_dir = os.path.join(webui_dist, "icons")
            if os.path.isdir(icons_dir):
                app.mount("/icons", StaticFiles(directory=icons_dir), name="spa_icons")

            @app.get("/", include_in_schema=False)
            async def serve_spa():
                return FileResponse(os.path.join(webui_dist, "index.html"))

            @app.get("/manifest.json", include_in_schema=False)
            async def serve_manifest():
                return FileResponse(os.path.join(webui_dist, "manifest.json"))

            @app.get("/sw.js", include_in_schema=False)
            async def serve_sw():
                return FileResponse(os.path.join(webui_dist, "sw.js"))

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
        import logging as _logging
        self.start_time = _time.time()
        self._servers.clear()
        self._secondary_threads.clear()
        self.ssl_port = None
        self.http_port = None
        protocol = getattr(self.config, 'server_protocol', 'http_https')
        can_https = self.config.ssl_enabled and self.config.ssl_keyfile and self.config.ssl_certfile

        if protocol != 'https_only':
            app_http = create_app(self.config)
            uv_config_http = uvicorn.Config(
                app_http,
                host=self.config.host,
                port=self.config.port,
                log_level=self.config.log_level.lower(),
                log_config=UVICORN_LOG_CONFIG,
            )
            server_http = uvicorn.Server(uv_config_http)
            self._servers.append(server_http)
            self.http_port = self.config.port

        # HTTPS — if SSL enabled (port = config.port + 1)
        if protocol != 'http_only' and can_https:
            import os as _os
            if not _os.path.isfile(self.config.ssl_certfile):
                _logging.warning("HTTPS 服务未启动: 证书文件不存在 (%s)", self.config.ssl_certfile)
            elif not _os.path.isfile(self.config.ssl_keyfile):
                _logging.warning("HTTPS 服务未启动: 密钥文件不存在 (%s)", self.config.ssl_keyfile)
            else:
                ssl_port = self.config.port + 1
                app_https = create_app(self.config)
                uv_config_https = uvicorn.Config(
                    app_https,
                    host=self.config.host,
                    port=ssl_port,
                    log_level=self.config.log_level.lower(),
                    ssl_keyfile=self.config.ssl_keyfile,
                    ssl_certfile=self.config.ssl_certfile,
                    log_config=UVICORN_LOG_CONFIG,
                )
                server_https = uvicorn.Server(uv_config_https)
                self._servers.append(server_https)

                def _run_https(srv):
                    try:
                        srv.run()
                    except Exception as exc:
                        _logging.error("HTTPS 服务启动失败 (端口 %s): %s", ssl_port, exc)

                t = threading.Thread(target=_run_https, args=(server_https,), daemon=True)
                t.start()
                self._secondary_threads.append(t)
                self.ssl_port = ssl_port
                _logging.info("HTTPS 服务已启动 (端口 %s)", ssl_port)

        if protocol == 'https_only':
            if can_https:
                _logging.info("仅 HTTPS 模式，HTTP 服务已跳过。请通过 https://127.0.0.1:%s 访问", self.ssl_port or (self.config.port + 1))
            else:
                _logging.warning("HTTPS 仅模式但 SSL 未正确配置，无法启动任何服务")
            # Run HTTPS thread blocking if no HTTP
            if self._servers:
                self._run_with_retry(lambda: self._servers[0])
        else:
            self._run_with_retry(lambda: server_http)

    def stop(self):
        for srv in self._servers:
            srv.should_exit = True
        self._servers.clear()
        self._secondary_threads.clear()
        self.ssl_port = None

    @staticmethod
    def _run_with_retry(server_factory, max_retries: int = 5):
        import time as _time
        last_exc = None
        for attempt in range(max_retries):
            try:
                srv = server_factory()
                srv.run()
                return
            except OSError as e:
                if "address already in use" in str(e).lower() and attempt < max_retries - 1:
                    _time.sleep(0.3 * (2 ** attempt))
                    last_exc = e
                    continue
                raise
        if last_exc:
            raise last_exc


def run_daemon(config: DaemonConfig | None = None):
    cfg = config or DaemonConfig()
    server = DaemonServer(cfg)
    server.start()
