"""
MCP（Model Context Protocol）服务器——可嵌入类 + 独立 CLI。

嵌入 GUI：
    from services.mcp_server import MCPServer
    srv = MCPServer()
    srv.start(port=8100)
    srv.stop()

独立运行（调试）：
    python -m services.mcp_server
"""

import argparse
import threading
import time as _time

from mcp.server.fastmcp import FastMCP
import json as _json

from services.auth_service import AuthService
from utils.logger import logger


class _AuthASGIMiddleware:
    """ASGI 中间件 — 对 /sse 和 /messages/ 路径做鉴权（兼容 SSE 流式响应）"""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path not in ('/sse', '/messages/') and not path.startswith('/messages/'):
            await self.app(scope, receive, send)
            return

        headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
        client_ip = scope.get("client", ("unknown", 0))[0]
        svc = AuthService()

        if not svc.check_ip(client_ip):
            svc.log_auth(False, client_ip, "MCP", "IP被拒绝")
            return await _send_json(send, 403, {"error": "forbidden"})

        if not svc.check_rate_limit(client_ip):
            return await _send_json(send, 429, {"error": "too many requests"})

        if svc.ip_bypasses_auth(client_ip):
            svc.log_auth(True, client_ip, "MCP", "免密 IP")
            await self.app(scope, receive, send)
            return

        if not svc.is_password_required():
            await self.app(scope, receive, send)
            return

        auth = headers.get('authorization', '')
        if not auth.startswith('Bearer '):
            svc.log_auth(False, client_ip, "MCP", "无令牌")
            return await _send_json(send, 401, {"error": "missing token"})
        if not svc.verify_mcp_token(auth[7:]):
            svc.log_auth(False, client_ip, "MCP", "令牌无效")
            return await _send_json(send, 401, {"error": "invalid token"})

        svc.log_auth(True, client_ip, "MCP", "")
        await self.app(scope, receive, send)


async def _send_json(send, status, data):
    body = _json.dumps(data).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({
        "type": "http.response.body",
        "body": body,
    })


class MCPServer:
    """可在后台线程运行的 MCP SSE 服务器"""

    def __init__(self):
        self._mcp = FastMCP("PersonalDAV")
        self._uvicorn_server = None
        self._thread: threading.Thread | None = None
        self._tools_registered = False
        logger.info("MCPServer 实例已创建（工具延迟到 start 时注册）")

    def start(self, host: str = "127.0.0.1", port: int = 8100,
              on_ready: callable = None) -> bool:
        if self._uvicorn_server is not None:
            logger.warning(f"MCP 服务器已在运行，忽略重复启动请求")
            return False

        logger.info(f"MCP 服务器后台启动中，监听 {host}:{port}")

        def _run():
            if not self._tools_registered:
                self._register_tools()
                self._tools_registered = True
            import uvicorn
            app = self._mcp.sse_app()
            app = _AuthASGIMiddleware(app)
            config = uvicorn.Config(app, host=host, port=port, log_level="warning")
            self._uvicorn_server = uvicorn.Server(config)
            logger.info(f"MCP 服务器已启动，端口 {port}")
            if on_ready:
                on_ready()
            self._uvicorn_server.run()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        if self._uvicorn_server is not None:
            logger.info("MCP 服务器正在关闭")
            self._uvicorn_server.should_exit = True
            self._uvicorn_server = None
            self._thread = None
            logger.info("MCP 服务器已关闭")
        else:
            logger.debug("MCP 服务器停止请求被忽略（未运行）")

    @property
    def is_running(self) -> bool:
        return self._uvicorn_server is not None

    def _register_tools(self) -> None:
        from mcp_tools import server_tools, contact_tools, event_tools
        from mcp_tools import config_tools, webdav_tools, ftp_tools, smb_tools

        server_tools.register(self._mcp)
        contact_tools.register(self._mcp)
        event_tools.register(self._mcp)
        config_tools.register(self._mcp)
        webdav_tools.register(self._mcp)
        ftp_tools.register(self._mcp)
        smb_tools.register(self._mcp)
        logger.info("MCP 工具注册完成")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PersonalDAV MCP 服务器")
    parser.add_argument("--port", type=int, default=8100, help="SSE 模式端口（默认 8100）")
    args = parser.parse_args()

    srv = MCPServer()
    srv.start(host="127.0.0.1", port=args.port)
    print(f"MCP SSE 服务器已启动: http://127.0.0.1:{args.port}/sse", flush=True)
    try:
        while True:
            _time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
        print("MCP 服务器已停止", flush=True)
