import os
import stat
import time
from ftplib import FTP, FTP_TLS, error_perm
import paramiko
from typing import Any
from utils.logger import logger


class FTPClientService:

    def _connect_ftp(self, host: str, port: int, username: str, password: str, protocol: str, encoding: str = "utf-8") -> FTP | FTP_TLS:
        if protocol == "ftps":
            ftp = FTP_TLS(encoding=encoding)
        else:
            ftp = FTP(encoding=encoding)
        ftp.connect(host, port, timeout=30)
        ftp.login(username, password)
        if protocol == "ftps":
            ftp.prot_p()
        return ftp

    def _connect_sftp(self, host: str, port: int, username: str, password: str) -> tuple[paramiko.Transport, paramiko.SFTPClient]:
        transport = paramiko.Transport((host, port))
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        return transport, sftp

    def _parse_dir_line(self, line: str) -> dict[str, Any] | None:
        parts = line.split()
        if len(parts) < 9:
            return None
        perms = parts[0]
        is_dir = perms.startswith("d")
        try:
            size = int(parts[4])
        except ValueError:
            size = 0
        modified = f"{parts[5]} {parts[6]} {parts[7]}"
        name = " ".join(parts[8:])
        return {
            "name": name,
            "is_directory": is_dir,
            "size": size,
            "modified": modified,
        }

    @staticmethod
    def _error_msg(e: Exception, fallback: str = "") -> str:
        msg = str(e) or type(e).__name__ or ""
        return msg or fallback or "未知错误"

    def list_dir(self, protocol: str, host: str, port: int, username: str, password: str, path: str, encoding: str = "utf-8") -> dict[str, Any]:
        try:
            if protocol in ("ftp", "ftps"):
                ftp = self._connect_ftp(host, port, username, password, protocol, encoding)
                try:
                    try:
                        raw = list(ftp.mlsd(path))
                        data = [
                            {
                                "name": name,
                                "is_directory": facts.get("type") == "dir",
                                "size": int(facts.get("size", 0)),
                                "modified": facts.get("modify", ""),
                            }
                            for name, facts in raw
                        ]
                    except error_perm:
                        lines: list[str] = []
                        ftp.dir(path, lines.append)
                        data = [entry for line in lines if (entry := self._parse_dir_line(line)) is not None]
                    return {"success": True, "data": data}
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        ftp.close()
            elif protocol == "sftp":
                transport, sftp = self._connect_sftp(host, port, username, password)
                try:
                    attrs_list = sftp.listdir_attr(path)
                    data = [
                        {
                            "name": attr.filename,
                            "is_directory": stat.S_ISDIR(attr.st_mode),
                            "size": attr.st_size,
                            "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(attr.st_mtime)) if attr.st_mtime else "",
                        }
                        for attr in attrs_list
                    ]
                    return {"success": True, "data": data}
                finally:
                    sftp.close()
                    transport.close()
            else:
                return {"success": False, "error": f"Unsupported protocol: {protocol}"}
        except Exception as e:
            logger.error(f"FTP list_dir error: {e}")
            return {"success": False, "error": self._error_msg(e)}

    def download(self, protocol: str, host: str, port: int, username: str, password: str, remote_path: str, local_path: str, encoding: str = "utf-8") -> dict[str, Any]:
        tmp_path = local_path + ".tmp"
        try:
            if protocol in ("ftp", "ftps"):
                ftp = self._connect_ftp(host, port, username, password, protocol, encoding)
                try:
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    with open(tmp_path, "wb") as f:
                        ftp.retrbinary(f"RETR {remote_path}", f.write)
                    os.replace(tmp_path, local_path)
                    return {"success": True, "data": {"local_path": local_path}}
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        ftp.close()
            elif protocol == "sftp":
                transport, sftp = self._connect_sftp(host, port, username, password)
                try:
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    sftp.get(remote_path, tmp_path)
                    os.replace(tmp_path, local_path)
                    return {"success": True, "data": {"local_path": local_path}}
                finally:
                    sftp.close()
                    transport.close()
            else:
                return {"success": False, "error": f"Unsupported protocol: {protocol}"}
        except Exception as e:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            logger.error(f"FTP download error: {e}")
            return {"success": False, "error": self._error_msg(e)}

    def upload(self, protocol: str, host: str, port: int, username: str, password: str, local_path: str, remote_path: str, encoding: str = "utf-8") -> dict[str, Any]:
        try:
            if protocol in ("ftp", "ftps"):
                ftp = self._connect_ftp(host, port, username, password, protocol, encoding)
                try:
                    with open(local_path, "rb") as f:
                        ftp.storbinary(f"STOR {remote_path}", f)
                    return {"success": True, "data": {"remote_path": remote_path}}
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        ftp.close()
            elif protocol == "sftp":
                transport, sftp = self._connect_sftp(host, port, username, password)
                try:
                    sftp.put(local_path, remote_path)
                    return {"success": True, "data": {"remote_path": remote_path}}
                finally:
                    sftp.close()
                    transport.close()
            else:
                return {"success": False, "error": f"Unsupported protocol: {protocol}"}
        except Exception as e:
            logger.error(f"FTP upload error: {e}")
            return {"success": False, "error": self._error_msg(e)}

    def delete(self, protocol: str, host: str, port: int, username: str, password: str, path: str, encoding: str = "utf-8") -> dict[str, Any]:
        try:
            if protocol in ("ftp", "ftps"):
                ftp = self._connect_ftp(host, port, username, password, protocol, encoding)
                try:
                    ftp.delete(path)
                    return {"success": True, "data": {"path": path}}
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        ftp.close()
            elif protocol == "sftp":
                transport, sftp = self._connect_sftp(host, port, username, password)
                try:
                    sftp.remove(path)
                    return {"success": True, "data": {"path": path}}
                finally:
                    sftp.close()
                    transport.close()
            else:
                return {"success": False, "error": f"Unsupported protocol: {protocol}"}
        except Exception as e:
            logger.error(f"FTP delete error: {e}")
            return {"success": False, "error": self._error_msg(e)}

    def rename(self, protocol: str, host: str, port: int, username: str, password: str, old_path: str, new_path: str, encoding: str = "utf-8") -> dict[str, Any]:
        try:
            if protocol in ("ftp", "ftps"):
                ftp = self._connect_ftp(host, port, username, password, protocol, encoding)
                try:
                    ftp.rename(old_path, new_path)
                    return {"success": True, "data": {"old_path": old_path, "new_path": new_path}}
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        ftp.close()
            elif protocol == "sftp":
                transport, sftp = self._connect_sftp(host, port, username, password)
                try:
                    sftp.rename(old_path, new_path)
                    return {"success": True, "data": {"old_path": old_path, "new_path": new_path}}
                finally:
                    sftp.close()
                    transport.close()
            else:
                return {"success": False, "error": f"Unsupported protocol: {protocol}"}
        except Exception as e:
            logger.error(f"FTP rename error: {e}")
            return {"success": False, "error": self._error_msg(e)}

    def mkdir(self, protocol: str, host: str, port: int, username: str, password: str, path: str, encoding: str = "utf-8") -> dict[str, Any]:
        try:
            if protocol in ("ftp", "ftps"):
                ftp = self._connect_ftp(host, port, username, password, protocol, encoding)
                try:
                    ftp.mkd(path)
                    return {"success": True, "data": {"path": path}}
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        ftp.close()
            elif protocol == "sftp":
                transport, sftp = self._connect_sftp(host, port, username, password)
                try:
                    sftp.mkdir(path)
                    return {"success": True, "data": {"path": path}}
                finally:
                    sftp.close()
                    transport.close()
            else:
                return {"success": False, "error": f"Unsupported protocol: {protocol}"}
        except Exception as e:
            logger.error(f"FTP mkdir error: {e}")
            return {"success": False, "error": self._error_msg(e)}

    def rmdir(self, protocol: str, host: str, port: int, username: str, password: str, path: str, encoding: str = "utf-8") -> dict[str, Any]:
        try:
            if protocol in ("ftp", "ftps"):
                ftp = self._connect_ftp(host, port, username, password, protocol, encoding)
                try:
                    ftp.rmd(path)
                    return {"success": True, "data": {"path": path}}
                finally:
                    try:
                        ftp.quit()
                    except Exception:
                        ftp.close()
            elif protocol == "sftp":
                transport, sftp = self._connect_sftp(host, port, username, password)
                try:
                    sftp.rmdir(path)
                    return {"success": True, "data": {"path": path}}
                finally:
                    sftp.close()
                    transport.close()
            else:
                return {"success": False, "error": f"Unsupported protocol: {protocol}"}
        except Exception as e:
            logger.error(f"FTP rmdir error: {e}")
            return {"success": False, "error": self._error_msg(e)}
