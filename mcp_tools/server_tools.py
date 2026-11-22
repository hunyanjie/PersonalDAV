import threading
import time

from mcp_tools._state import server_instance
from mcp_tools.helpers import safe_json, check_readonly
from utils.logger import logger


def _status_of(server) -> dict:
    if server is None:
        return {"running": False, "port": None, "ssl_port": None}
    port = getattr(server, "http_port", None)
    ssl_port = getattr(server, "ssl_port", None)
    if port is None and ssl_port is None:
        port = getattr(server, "port", None)
    return {"running": True, "port": port or ssl_port, "ssl_port": ssl_port}


def register(mcp):
    @mcp.tool(description="启动 DAV 服务器（统一 HTTP/WebUI/MCP 服务，后台线程运行）")
    def server_start(port: int = 0) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: server_start port={port}")
        try:
            if server_instance[0] is not None:
                result = _status_of(server_instance[0])
                logger.info(f"MCP 返回: server_start -> 已在运行 {result}")
                return safe_json(result)

            from personaldavd.config import DaemonConfig
            from personaldavd.daemon import DaemonServer
            from database.db_manager import Database
            from services.settings_service import SettingsService
            s = SettingsService()
            db_path = Database._instance.db_path if Database._instance else s.get_setting("db_path", "data/dav_data.db")
            cfg = DaemonConfig(
                host=s.get_setting("default_host", "127.0.0.1"),
                port=port or int(s.get_setting("default_port", "8000")),
                db_path=db_path,
                data_dir=s.get_setting("data_dir", ""),
                dav_root=s.get_setting("dav_root", ""),
                ssl_enabled=s.get_setting("ssl_enabled", "False") == "True",
                ssl_certfile=s.get_setting("ssl_certfile", ""),
                ssl_keyfile=s.get_setting("ssl_keyfile", ""),
                server_protocol=s.get_setting("server_protocol", "http_https"),
            )
            srv = DaemonServer(cfg)
            server_instance[0] = srv
            threading.Thread(target=srv.start, daemon=True).start()

            # 等待 uvicorn 真正开始监听，避免返回一个尚未就绪的端口。
            for _ in range(30):
                if srv.http_port or srv.ssl_port:
                    break
                time.sleep(0.1)

            result = _status_of(srv)
            logger.info(f"MCP 返回: server_start -> {result}")
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: server_start")
            server_instance[0] = None
            return safe_json({"error": str(e)})

    @mcp.tool(description="停止正在运行的 DAV 服务器")
    def server_stop() -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info("MCP 调用: server_stop")
        try:
            s = server_instance[0]
            if s is None:
                msg = "DAV 服务器未运行"
                logger.info(f"MCP 返回: server_stop -> {msg}")
                return msg
            s.stop()
            server_instance[0] = None
            logger.info("MCP 返回: server_stop -> DAV 服务器已停止")
            return "DAV 服务器已停止"
        except Exception as e:
            logger.exception("MCP 异常: server_stop")
            return safe_json({"error": str(e)})

    @mcp.tool(description="查询 DAV 服务器当前运行状态")
    def server_status() -> str:
        try:
            result = _status_of(server_instance[0])
            logger.debug(f"MCP 调用: server_status -> {result}")
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: server_status")
            return safe_json({"error": str(e)})
