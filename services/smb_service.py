import threading
import os
import socket
from typing import Any
from smb.SMBConnection import SMBConnection
from utils.logger import logger


class SMBService:
    _instance: "SMBService | None" = None
    _lock = threading.Lock()
    _initialized: bool
    _mounts: dict[str, dict[str, str]]
    _mounts_lock: threading.Lock

    def __new__(cls) -> "SMBService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        self._mounts = {}
        self._mounts_lock = threading.Lock()

    def _create_connection(self, server: str, username: str, password: str) -> SMBConnection:
        my_name = socket.gethostname()
        return SMBConnection(username, password, my_name, server, use_ntlm_v2=True)

    def _connect(self, conn: SMBConnection, server: str, timeout: int = 10) -> bool:
        return conn.connect(server, timeout=timeout)

    def list_shares(self, server: str, username: str = "guest", password: str = "") -> dict[str, Any]:
        try:
            conn = self._create_connection(server, username, password)
            if not self._connect(conn, server):
                return {"success": False, "error": "Failed to connect to SMB server"}
            shares = conn.listShares(timeout=10)
            conn.close()
            data = [
                {
                    "name": share.name,
                    "type": share.type,
                    "comment": share.comments,
                }
                for share in shares
            ]
            return {"success": True, "data": data}
        except Exception as e:
            logger.error(f"SMB list_shares error: {e}")
            return {"success": False, "error": str(e)}

    def list_files(self, server: str, share: str, path: str = "/",
                   username: str = "guest", password: str = "") -> dict[str, Any]:
        try:
            conn = self._create_connection(server, username, password)
            if not self._connect(conn, server):
                return {"success": False, "error": "Failed to connect to SMB server"}
            files = conn.listPath(share, path, timeout=10)
            conn.close()
            data = [
                {
                    "name": f.filename,
                    "is_directory": f.isDirectory,
                    "size": f.file_size,
                    "last_modified": str(f.last_modified_time) if hasattr(f, 'last_modified_time') else None,
                }
                for f in files
            ]
            return {"success": True, "data": data}
        except Exception as e:
            logger.error(f"SMB list_files error: {e}")
            return {"success": False, "error": str(e)}

    def mount(self, server: str, share: str, mount_point: str,
              username: str = "guest", password: str = "") -> dict[str, Any]:
        with self._mounts_lock:
            if mount_point in self._mounts:
                return {"success": False, "error": f"挂载点 '{mount_point}' 已被使用"}
            try:
                os.makedirs(mount_point, exist_ok=True)
            except OSError as e:
                return {"success": False, "error": f"创建挂载点目录失败: {e}"}
            self._mounts[mount_point] = {
                "server": server,
                "share": share,
                "mount_point": mount_point,
                "username": username,
                "password": password,
            }
            logger.info(f"SMB share mounted: {server}/{share} -> {mount_point}")
            return {"success": True, "data": self._mounts[mount_point].copy()}

    def unmount(self, mount_point: str) -> dict[str, Any]:
        with self._mounts_lock:
            if mount_point not in self._mounts:
                return {"success": False, "error": f"挂载点 '{mount_point}' 不存在"}
            info = self._mounts.pop(mount_point)
            logger.info(f"SMB share unmounted: {mount_point}")
            return {"success": True, "data": info}

    def get_mounted_shares(self) -> dict[str, Any]:
        with self._mounts_lock:
            return {"success": True, "data": list(self._mounts.values())}
