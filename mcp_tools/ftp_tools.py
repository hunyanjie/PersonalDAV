from mcp_tools._state import FTP_SVC
from mcp_tools.helpers import safe_json, check_readonly
from services.ftp_client_service import FTPClientService
from utils.logger import logger


def register(mcp):
    @mcp.tool(description="启动 FTP/SFTP/TFTP 文件传输服务")
    def ftp_servers_start() -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info("MCP 调用: ftp_servers_start")
        try:
            ok = FTP_SVC.start()
            logger.info(f"MCP 返回: ftp_servers_start -> {ok}")
            return safe_json({"success": ok})
        except Exception as e:
            logger.exception("MCP 异常: ftp_servers_start")
            return safe_json({"error": str(e)})

    @mcp.tool(description="停止 FTP/SFTP/TFTP 文件传输服务")
    def ftp_servers_stop() -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info("MCP 调用: ftp_servers_stop")
        try:
            FTP_SVC.stop()
            logger.info("MCP 返回: ftp_servers_stop -> 已停止")
            return safe_json({"success": True})
        except Exception as e:
            logger.exception("MCP 异常: ftp_servers_stop")
            return safe_json({"error": str(e)})

    @mcp.tool(description="查询 FTP/SFTP/TFTP 服务运行状态")
    def ftp_servers_status() -> str:
        try:
            result = {"running": FTP_SVC.is_running}
            logger.debug(f"MCP 调用: ftp_servers_status -> {result}")
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: ftp_servers_status")
            return safe_json({"error": str(e)})

    @mcp.tool(description="浏览远程 FTP/FTPS 目录")
    def ftp_list_dir(
        host: str, port: int = 21, username: str = "anonymous",
        password: str = "", path: str = "/", protocol: str = "ftp",
        encoding: str = "utf-8"
    ) -> str:
        logger.info(f"MCP 调用: ftp_list_dir {protocol}://{host}:{port}{path}")
        try:
            client = FTPClientService()
            result = client.list_dir(protocol, host, port, username, password, path, encoding)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: ftp_list_dir")
            return safe_json({"error": str(e)})

    @mcp.tool(description="从远程 FTP/SFTP 服务器下载文件")
    def ftp_download(
        host: str, port: int = 21, username: str = "anonymous",
        password: str = "", remote_path: str = "", local_path: str = "",
        protocol: str = "ftp", encoding: str = "utf-8"
    ) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: ftp_download {protocol}://{host}:{port}{remote_path}")
        try:
            client = FTPClientService()
            result = client.download(protocol, host, port, username, password, remote_path, local_path, encoding)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: ftp_download")
            return safe_json({"error": str(e)})

    @mcp.tool(description="上传文件到远程 FTP/SFTP 服务器")
    def ftp_upload(
        host: str, port: int = 21, username: str = "anonymous",
        password: str = "", local_path: str = "", remote_path: str = "",
        protocol: str = "ftp", encoding: str = "utf-8"
    ) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: ftp_upload {protocol}://{host}:{port}{remote_path}")
        try:
            client = FTPClientService()
            result = client.upload(protocol, host, port, username, password, local_path, remote_path, encoding)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: ftp_upload")
            return safe_json({"error": str(e)})

    @mcp.tool(description="删除远程 FTP/SFTP 文件")
    def ftp_delete(
        host: str, port: int = 21, username: str = "anonymous",
        password: str = "", path: str = "", protocol: str = "ftp",
        encoding: str = "utf-8"
    ) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: ftp_delete {protocol}://{host}:{port}{path}")
        try:
            client = FTPClientService()
            result = client.delete(protocol, host, port, username, password, path, encoding)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: ftp_delete")
            return safe_json({"error": str(e)})

    @mcp.tool(description="重命名远程 FTP/SFTP 文件或目录")
    def ftp_rename(
        host: str, port: int = 21, username: str = "anonymous",
        password: str = "", old_path: str = "", new_path: str = "",
        protocol: str = "ftp", encoding: str = "utf-8"
    ) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: ftp_rename {protocol}://{host}:{port} {old_path} -> {new_path}")
        try:
            client = FTPClientService()
            result = client.rename(protocol, host, port, username, password, old_path, new_path, encoding)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: ftp_rename")
            return safe_json({"error": str(e)})

    @mcp.tool(description="在远程 FTP/SFTP 服务器创建目录")
    def ftp_mkdir(
        host: str, port: int = 21, username: str = "anonymous",
        password: str = "", path: str = "", protocol: str = "ftp",
        encoding: str = "utf-8"
    ) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: ftp_mkdir {protocol}://{host}:{port}{path}")
        try:
            client = FTPClientService()
            result = client.mkdir(protocol, host, port, username, password, path, encoding)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: ftp_mkdir")
            return safe_json({"error": str(e)})

    @mcp.tool(description="删除远程 FTP/SFTP 服务器上的空目录")
    def ftp_rmdir(
        host: str, port: int = 21, username: str = "anonymous",
        password: str = "", path: str = "", protocol: str = "ftp",
        encoding: str = "utf-8"
    ) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: ftp_rmdir {protocol}://{host}:{port}{path}")
        try:
            client = FTPClientService()
            result = client.rmdir(protocol, host, port, username, password, path, encoding)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: ftp_rmdir")
            return safe_json({"error": str(e)})
