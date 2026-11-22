"""共享的 DAV 服务器实例引用。

GUI、无头 daemon 和 MCP 工具需要看到同一个正在运行的服务实例，
避免 MCP 另外启动一个旧版 DAVServer 或返回错误端口。
"""

from typing import Any

server_instance: list[Any | None] = [None]
