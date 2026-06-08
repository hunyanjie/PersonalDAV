import threading
import time

from mcp_tools._state import server_instance
from mcp_tools.helpers import safe_json, check_readonly
from network.dav_server import DAVServer
from utils.logger import logger


def register(mcp):
    @mcp.tool(description="启动 DAV 服务器（后台线程运行）")
    def server_start(port: int = 8080) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: server_start port={port}")
        try:
            if server_instance[0] is not None:
                msg = "DAV 服务器已在运行"
                logger.info(f"MCP 返回: server_start -> {msg}")
                return msg
            s = DAVServer(port)
            server_instance[0] = s
            threading.Thread(target=s.start, daemon=True).start()
            time.sleep(0.5)
            msg = f"DAV 服务器已启动，监听端口 {port}"
            logger.info(f"MCP 返回: server_start -> {msg}")
            return msg
        except Exception as e:
            logger.exception(f"MCP 异常: server_start")
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
            result = {"running": server_instance[0] is not None, "port": 8080 if server_instance[0] else None}
            logger.debug(f"MCP 调用: server_status -> {result}")
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: server_status")
            return safe_json({"error": str(e)})
