from mcp_tools._state import SMBService
from mcp_tools.helpers import safe_json, check_readonly
from utils.logger import logger


def register(mcp):
    @mcp.tool(description="启动 SMB/CIFS 文件共享服务")
    def smb_servers_start() -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info("MCP 调用: smb_servers_start")
        try:
            svc = SMBService()
            ok = svc.start()
            logger.info(f"MCP 返回: smb_servers_start -> {ok}")
            return safe_json({"success": ok})
        except Exception as e:
            logger.exception("MCP 异常: smb_servers_start")
            return safe_json({"error": str(e)})

    @mcp.tool(description="停止 SMB/CIFS 文件共享服务")
    def smb_servers_stop() -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info("MCP 调用: smb_servers_stop")
        try:
            svc = SMBService()
            svc.stop()
            return safe_json({"success": True})
        except Exception as e:
            logger.exception("MCP 异常: smb_servers_stop")
            return safe_json({"error": str(e)})

    @mcp.tool(description="查询 SMB/CIFS 服务运行状态")
    def smb_servers_status() -> str:
        try:
            svc = SMBService()
            result = {"running": svc.is_running()}
            logger.debug(f"MCP 调用: smb_servers_status -> {result}")
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: smb_servers_status")
            return safe_json({"error": str(e)})

    @mcp.tool(description="列出 SMB 服务器上的共享目录")
    def smb_list_shares(host: str, username: str = "guest", password: str = "") -> str:
        logger.info(f"MCP 调用: smb_list_shares {host}")
        try:
            svc = SMBService()
            result = svc.list_shares(host, username, password)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: smb_list_shares")
            return safe_json({"error": str(e)})

    @mcp.tool(description="列出 SMB 共享中的文件和目录")
    def smb_list_files(host: str, share: str = "", path: str = "/",
                       username: str = "guest", password: str = "") -> str:
        logger.info(f"MCP 调用: smb_list_files {host}/{share}{path}")
        try:
            svc = SMBService()
            result = svc.list_files(host, share, path, username, password)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: smb_list_files")
            return safe_json({"error": str(e)})
