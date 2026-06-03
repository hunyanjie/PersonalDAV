import threading
import os
import logging
import stat as stat_module
from concurrent.futures import ThreadPoolExecutor
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer as PyFTPD
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
import paramiko
from paramiko import ServerInterface, RSAKey
import socket
from tftpy import TftpServer
from services.settings_service import SettingsService
from services.auth_service import AuthService
from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED
from utils.logger import logger




_THUMBNAIL_DIR = ".thumbnails"


def _generate_thumbnail(filepath: str, max_size: int = 128) -> str | None:
    try:
        from PIL import Image
        thumb_dir = os.path.join(os.path.dirname(filepath), _THUMBNAIL_DIR)
        os.makedirs(thumb_dir, exist_ok=True)
        thumb_path = os.path.join(thumb_dir, os.path.basename(filepath) + ".png")
        if os.path.exists(thumb_path):
            return thumb_path
        img = Image.open(filepath)
        img.thumbnail((max_size, max_size), Image.LANCZOS)
        img.save(thumb_path, "PNG")
        return thumb_path
    except Exception:
        return None


class AuthServiceAuthorizer:
    def validate_authentication(self, username: str, password: str, handler: object) -> bool:
        ftp_pass = SettingsService().get_setting("ftp_password", "")
        if ftp_pass:
            if password == ftp_pass:
                return True
            raise AuthenticationFailed("Invalid credentials")
        stored = SettingsService().get_setting("access_password_hash", "")
        if not stored:
            return True
        if '$' in stored:
            salt, pw_hash = stored.split('$', 1)
            from hashlib import pbkdf2_hmac
            from secrets import compare_digest
            if compare_digest(pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex(), pw_hash):
                return True
        raise AuthenticationFailed("Invalid credentials")

    def get_msg_login(self, username: str) -> str:
        return f"Welcome, {username}!"

    def get_msg_quit(self, username: str) -> str:
        return "Goodbye."

    def get_perms(self, username: str) -> str:
        return "elradfmw"

    def has_perm(self, username: str, perm: str, path: str | None = None) -> bool:
        return True

    def get_home_dir(self, username: str) -> str:
        return os.path.abspath(
            SettingsService().get_setting("ftp_root", "./ftp_root")
        )

    def impersonate_user(self, username: str, password: str) -> None:
        pass

    def terminate_impersonation(self, username: str) -> None:
        pass


class LoggedFTPHandler(FTPHandler):  # type: ignore[misc]
    # 被动模式端口范围
    passive_ports = range(60000, 60100)
    # 允许主动模式
    enable_active_mode = True
    # 最大并发连接数
    max_cons = 256
    max_cons_per_ip = 32
    # 传输超时（秒）
    timeout = 300

    def on_connect(self) -> None:
        logger.info(f"FTP connection from {self.remote_ip}")
        super().on_connect()

    def on_disconnect(self) -> None:
        logger.info(f"FTP disconnection from {self.remote_ip}")
        super().on_disconnect()

    def on_login(self, username: str) -> None:
        logger.info(f"FTP login success from {self.remote_ip}")
        super().on_login(username)

    def on_login_failed(self, username: str, password: str) -> None:
        logger.warning(f"FTP login failed from {self.remote_ip}")
        super().on_login_failed(username, password)

    def on_file_received(self, filepath: str) -> None:
        try:
            os.chmod(filepath, 0o644)
        except Exception:
            pass
        _generate_thumbnail(filepath)
        logger.info(f"FTP file received: {filepath}")
        super().on_file_received(filepath)

    def on_file_sent(self, filepath: str) -> None:
        logger.info(f"FTP file sent: {filepath}")
        super().on_file_sent(filepath)


class StubSFTPHandle(paramiko.SFTPHandle):  # type: ignore[misc]
    fileobj: int

    def __init__(self, fileobj: int) -> None:
        super().__init__()
        self.fileobj = fileobj

    def read(self, offset: int, length: int) -> bytes:
        os.lseek(self.fileobj, offset, os.SEEK_SET)
        return os.read(self.fileobj, length)

    def write(self, offset: int, data: bytes) -> int:
        os.lseek(self.fileobj, offset, os.SEEK_SET)
        return os.write(self.fileobj, data)

    def close(self) -> int:
        os.close(self.fileobj)
        return paramiko.SFTP_OK


class StubSFTPServer(paramiko.SFTPServerInterface):  # type: ignore[misc]
    def __init__(self, transport: paramiko.Transport, root: str) -> None:
        super().__init__(transport)
        self.root: str = os.path.abspath(root)

    def _resolve(self, path: str) -> str:
        abs_path = os.path.normpath(os.path.join(self.root, path.lstrip("/")))
        if not abs_path.startswith(self.root):
            raise PermissionError("Path traversal denied")
        return abs_path

    def list_folder(self, path: str) -> list[paramiko.SFTPAttributes] | int:
        abs_path = self._resolve(path)
        try:
            entries: list[paramiko.SFTPAttributes] = []
            for name in os.listdir(abs_path):
                full = os.path.join(abs_path, name)
                attr = paramiko.SFTPAttributes.from_stat(os.stat(full))
                attr.filename = name
                entries.append(attr)
            return entries
        except OSError:
            return paramiko.SFTP_FAILURE

    def stat(self, path: str) -> paramiko.SFTPAttributes | int:
        abs_path = self._resolve(path)
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(abs_path))
        except OSError:
            return paramiko.SFTP_FAILURE

    def lstat(self, path: str) -> paramiko.SFTPAttributes | int:
        abs_path = self._resolve(path)
        try:
            return paramiko.SFTPAttributes.from_stat(os.lstat(abs_path))
        except OSError:
            return paramiko.SFTP_FAILURE

    def open(self, path: str, flags: int, attr: paramiko.SFTPAttributes) -> StubSFTPHandle | int:
        abs_path = self._resolve(path)
        try:
            binary_flags: int = os.O_RDONLY
            if flags & paramiko.SFTP_FLAG_WRITE:
                binary_flags = os.O_WRONLY
            if flags & (paramiko.SFTP_FLAG_RDWR | paramiko.SFTP_FLAG_READ | paramiko.SFTP_FLAG_WRITE) == (
                paramiko.SFTP_FLAG_READ | paramiko.SFTP_FLAG_WRITE
            ):
                binary_flags = os.O_RDWR
            if flags & paramiko.SFTP_FLAG_CREAT:
                binary_flags |= os.O_CREAT
            if flags & paramiko.SFTP_FLAG_TRUNC:
                binary_flags |= os.O_TRUNC
            if flags & paramiko.SFTP_FLAG_APPEND:
                binary_flags |= os.O_APPEND

            fd = os.open(abs_path, binary_flags, 0o644)
            if attr and attr.st_mode:
                os.chmod(abs_path, attr.st_mode & 0o777)
            return StubSFTPHandle(fd)
        except OSError:
            return paramiko.SFTP_FAILURE

    def read(self, handle: StubSFTPHandle, offset: int, length: int) -> bytes | int:
        return handle.read(offset, length)

    def write(self, handle: StubSFTPHandle, offset: int, data: bytes) -> int:
        return handle.write(offset, data)

    def close(self, handle: StubSFTPHandle) -> int:
        return handle.close()

    def remove(self, path: str) -> int:
        abs_path = self._resolve(path)
        try:
            os.remove(abs_path)
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFTP_FAILURE

    def mkdir(self, path: str, attr: paramiko.SFTPAttributes) -> int:
        abs_path = self._resolve(path)
        try:
            os.makedirs(abs_path, exist_ok=True)
            if attr and attr.st_mode:
                os.chmod(abs_path, attr.st_mode & 0o777)
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFTP_FAILURE

    def rmdir(self, path: str) -> int:
        abs_path = self._resolve(path)
        try:
            os.rmdir(abs_path)
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFTP_FAILURE

    def rename(self, oldpath: str, newpath: str) -> int:
        old_abs = self._resolve(oldpath)
        new_abs = self._resolve(newpath)
        try:
            os.rename(old_abs, new_abs)
            return paramiko.SFTP_OK
        except OSError:
            return paramiko.SFTP_FAILURE


class SFTPAuthInterface(ServerInterface):  # type: ignore[misc]
    def __init__(self, auth_service: AuthService) -> None:
        super().__init__()
        self.auth_service = auth_service

    def check_auth_password(self, username: str, password: str) -> int:
        ftp_pass = SettingsService().get_setting("ftp_password", "")
        if ftp_pass:
            return paramiko.AUTH_SUCCESSFUL if password == ftp_pass else paramiko.AUTH_FAILED
        stored = SettingsService().get_setting("access_password_hash", "")
        if not stored:
            return paramiko.AUTH_SUCCESSFUL
        if '$' in stored:
            salt, pw_hash = stored.split('$', 1)
            from hashlib import pbkdf2_hmac
            from secrets import compare_digest
            if compare_digest(pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex(), pw_hash):
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username: str) -> str:
        return "password"


class FTPService:
    _instance: "FTPService | None" = None
    _lock = threading.Lock()

    _ftp_server: PyFTPD | None
    _sftp_socket: socket.socket | None
    _sftp_key: RSAKey | None
    _tftp_server: TftpServer | None
    _ftp_thread: threading.Thread | None
    _sftp_thread: threading.Thread | None
    _tftp_thread: threading.Thread | None
    _stop_event: threading.Event
    _running: bool

    def __new__(cls) -> "FTPService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not hasattr(self, "_initialized"):
            with self._lock:
                if not hasattr(self, "_initialized"):
                    self._initialized = True
                    self._ftp_server = None
                    self._sftp_socket = None
                    self._sftp_key = None
                    self._tftp_server = None
                    self._ftp_thread = None
                    self._sftp_thread = None
                    self._tftp_thread = None
                    self._stop_event = threading.Event()
                    self._running = False
                    event_bus.subscribe(EVENT_SETTINGS_CHANGED, self._on_settings_changed)

    def _on_settings_changed(self, *args: object) -> None:
        if self._running:
            logger.info("Settings changed, restarting FTP/SFTP services...")
            self.stop()
            self.start()

    def start(self) -> bool:
        with self._lock:
            if self._running:
                return True

            self._stop_event.clear()
            settings = SettingsService()
            auth = AuthService()
            started_any = False

            if settings.get_setting("ftp_enabled", "True") == "True":
                try:
                    port = int(settings.get_setting("ftp_port", "21"))
                    root = settings.get_setting("ftp_root", "./ftp_root")
                    os.makedirs(root, exist_ok=True)
                    self._ftp_thread = threading.Thread(
                        target=self._run_ftp,
                        args=(port, root),
                        daemon=True,
                        name="ftp-server",
                    )
                    self._ftp_thread.start()
                    started_any = True
                    logger.info(f"FTP server thread started on port {port}")
                except Exception as e:
                    logger.error(f"Failed to start FTP server: {e}")

            if settings.get_setting("sftp_enabled", "False") == "True":
                try:
                    port = int(settings.get_setting("sftp_port", "22"))
                    root = settings.get_setting("sftp_root", "./sftp_root")
                    os.makedirs(root, exist_ok=True)
                    self._sftp_key = RSAKey.generate(bits=2048)
                    self._sftp_thread = threading.Thread(
                        target=self._run_sftp,
                        args=(port, root, auth),
                        daemon=True,
                        name="sftp-server",
                    )
                    self._sftp_thread.start()
                    started_any = True
                    logger.info(f"SFTP server thread started on port {port}")
                except Exception as e:
                    logger.error(f"Failed to start SFTP server: {e}")

            if settings.get_setting("tftp_enabled", "False") == "True":
                try:
                    port = int(settings.get_setting("tftp_port", "69"))
                    root = settings.get_setting("tftp_root", "./tftp_root")
                    os.makedirs(root, exist_ok=True)
                    self._tftp_thread = threading.Thread(
                        target=self._run_tftp,
                        args=(port, root),
                        daemon=True,
                        name="tftp-server",
                    )
                    self._tftp_thread.start()
                    started_any = True
                    logger.info(f"TFTP server thread started on port {port}")
                except Exception as e:
                    logger.error(f"Failed to start TFTP server: {e}")

            if started_any:
                self._running = True
            return self._running

    def stop(self) -> None:
        with self._lock:
            if not self._running:
                return
            self._stop_event.set()
            self._running = False

            if self._ftp_server:
                try:
                    self._ftp_server.close_all()
                except Exception:
                    pass
                self._ftp_server = None

            if self._sftp_socket:
                try:
                    self._sftp_socket.close()
                except Exception:
                    pass
                self._sftp_socket = None

            self._sftp_key = None

            if self._tftp_server:
                try:
                    self._tftp_server.stop()
                except Exception:
                    pass
                self._tftp_server = None

            for thread in (self._ftp_thread, self._sftp_thread, self._tftp_thread):
                if thread and thread.is_alive():
                    thread.join(timeout=5)

            self._ftp_thread = None
            self._sftp_thread = None
            self._tftp_thread = None
            logger.info("FTP/SFTP/TFTP services stopped")

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._running

    def _run_ftp(self, port: int, root: str) -> None:
        authorizer = AuthServiceAuthorizer()
        handler: type[FTPHandler] = LoggedFTPHandler
        handler.authorizer = authorizer
        handler.banner = "Welcome to PersonalDAV FTP Server"
        encoding = SettingsService().get_setting("ftp_encoding", "utf-8")
        handler.encoding = encoding
        try:
            server = PyFTPD(("0.0.0.0", port), handler)
            self._ftp_server = server
            server.max_cons = 256
            server.max_cons_per_ip = 32
            logger.info(f"FTP server listening on 0.0.0.0:{port} "
                        f"(passive ports 60000-60099, active mode enabled, encoding={encoding})")
            server.serve_forever()
        except OSError as e:
            logger.error(f"FTP server bind error on port {port}: {e}")
        except Exception as e:
            logger.error(f"FTP server error: {e}")
        finally:
            logger.info("FTP server stopped")

    def _run_sftp(self, port: int, root: str, auth: AuthService) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", port))
            sock.listen(5)
            sock.settimeout(1.0)
            self._sftp_socket = sock
            logger.info(f"SFTP server listening on 0.0.0.0:{port}")

            while not self._stop_event.is_set():
                try:
                    client, addr = sock.accept()
                    logger.info(f"SFTP connection from {addr[0]}:{addr[1]}")
                    threading.Thread(
                        target=self._handle_sftp_client,
                        args=(client, addr, root, auth),
                        daemon=True,
                        name=f"sftp-client-{addr[0]}",
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    break
                except Exception as e:
                    logger.error(f"SFTP accept error: {e}")
        except OSError as e:
            logger.error(f"SFTP server bind error on port {port}: {e}")
        except Exception as e:
            logger.error(f"SFTP server error: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
            logger.info("SFTP server stopped")

    def _run_tftp(self, port: int, root: str) -> None:
        try:
            server = TftpServer(root)
            self._tftp_server = server
            logger.info(f"TFTP server listening on 0.0.0.0:{port}")
            server.listen("0.0.0.0", port)
        except Exception as e:
            logger.error(f"TFTP server error: {e}")
        finally:
            logger.info("TFTP server stopped")

    def _handle_sftp_client(self, client: socket.socket, addr: tuple[str, int], root: str, auth: AuthService) -> None:
        transport = paramiko.Transport(client)
        try:
            transport.add_server_key(self._sftp_key)
            auth_iface = SFTPAuthInterface(auth)
            transport.start_server(server=auth_iface)
            sftp_server = paramiko.SFTPServer(transport, StubSFTPServer, root)
            sftp_server.serve_forever()
            logger.info(f"SFTP client disconnected: {addr[0]}:{addr[1]}")
        except Exception as e:
            logger.error(f"SFTP client error [{addr[0]}]: {e}")
        finally:
            try:
                transport.close()
            except Exception:
                pass
            try:
                client.close()
            except Exception:
                pass
