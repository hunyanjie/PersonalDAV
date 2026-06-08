import os
import shutil
import email.utils
import time
from services.settings_service import SettingsService
from network.webdav_helper import propfind_response


class WebDAVFileHandler:
    """WebDAV 文件服务（/dav/ 路径）请求处理"""

    @staticmethod
    def get_dav_root() -> str:
        return SettingsService().get_setting("dav_root", "./dav_root")

    @staticmethod
    def resolve_dav_path(path: str) -> str | None:
        root = os.path.abspath(WebDAVFileHandler.get_dav_root())
        clean = os.path.normpath(path.lstrip("/dav").lstrip("/").replace("\\", "/"))
        abs_path = os.path.normpath(os.path.join(root, clean))
        if not abs_path.startswith(root):
            return None
        return abs_path

    @staticmethod
    def list_dav_entries(fs_path: str) -> list[dict[str, any]]:
        entries = []
        try:
            for name in sorted(os.listdir(fs_path)):
                full = os.path.join(fs_path, name)
                st = os.stat(full)
                entries.append({
                    "name": name,
                    "is_directory": os.path.isdir(full),
                    "size": st.st_size,
                    "modified": email.utils.formatdate(timeval=st.st_mtime, localtime=False, usegmt=True),
                })
        except OSError:
            pass
        return entries

    @staticmethod
    def handle_PROPFIND(handler):
        fs_path = WebDAVFileHandler.resolve_dav_path(handler.path)
        if fs_path is None or not os.path.exists(fs_path):
            handler._send_error(404, "Not found")
            return
        if not os.path.isdir(fs_path):
            handler._send_error(400, "PROPFIND on non-collection")
            return
        entries = WebDAVFileHandler.list_dav_entries(fs_path)
        body = propfind_response(handler.path, entries)
        handler.send_response(207)
        handler.send_header('Content-Type', 'text/xml; charset="utf-8"')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    @staticmethod
    def handle_GET(handler):
        fs_path = WebDAVFileHandler.resolve_dav_path(handler.path)
        if fs_path is None:
            handler._send_error(404, "Not found")
            return
        if os.path.isdir(fs_path):
            handler._send_error(400, "Is a directory, use PROPFIND")
            return
        if not os.path.isfile(fs_path):
            handler._send_error(404, "File not found")
            return
        st = os.stat(fs_path)
        _, ext = os.path.splitext(fs_path)
        ext_map = {".txt": "text/plain", ".html": "text/html", ".json": "application/json",
                   ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                   ".gif": "image/gif", ".pdf": "application/pdf", ".xml": "text/xml",
                   ".zip": "application/zip", ".mp3": "audio/mpeg", ".mp4": "video/mp4",
                   ".vcf": "text/vcard", ".ics": "text/calendar"}
        mime = ext_map.get(ext.lower(), "application/octet-stream")
        handler.send_response(200)
        handler.send_header('Content-Type', mime)
        handler.send_header('Content-Length', str(st.st_size))
        handler.send_header('Last-Modified', email.utils.formatdate(timeval=st.st_mtime, localtime=False, usegmt=True))
        handler.end_headers()
        with open(fs_path, "rb") as f:
            shutil.copyfileobj(f, handler.wfile)

    @staticmethod
    def handle_PUT(handler):
        fs_path = WebDAVFileHandler.resolve_dav_path(handler.path)
        if fs_path is None:
            handler._send_error(400, "Invalid path")
            return
        try:
            content_length = int(handler.headers.get('Content-Length', 0))
            os.makedirs(os.path.dirname(fs_path), exist_ok=True)
            with open(fs_path, "wb") as f:
                if content_length > 0:
                    chunk_size = 65536
                    remaining = content_length
                    while remaining > 0:
                        chunk = handler.rfile.read(min(chunk_size, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
            handler.send_response(201)
            handler.send_header('Content-Type', 'text/plain')
            handler.end_headers()
            handler.wfile.write(b"Created")
        except Exception as e:
            handler._send_error(500, str(e))

    @staticmethod
    def handle_DELETE(handler):
        fs_path = WebDAVFileHandler.resolve_dav_path(handler.path)
        if fs_path is None or not os.path.exists(fs_path):
            handler._send_error(404, "Not found")
            return
        try:
            if os.path.isdir(fs_path):
                shutil.rmtree(fs_path)
            else:
                os.remove(fs_path)
            handler.send_response(204)
            handler.end_headers()
        except Exception as e:
            handler._send_error(500, str(e))

    @staticmethod
    def handle_MKCOL(handler):
        fs_path = WebDAVFileHandler.resolve_dav_path(handler.path)
        if fs_path is None:
            handler._send_error(400, "Invalid path")
            return
        if os.path.exists(fs_path):
            handler._send_error(405, "Already exists")
            return
        try:
            os.makedirs(fs_path)
            handler.send_response(201)
            handler.end_headers()
        except Exception as e:
            handler._send_error(500, str(e))

    @staticmethod
    def handle_HEAD(handler):
        fs_path = WebDAVFileHandler.resolve_dav_path(handler.path)
        if fs_path is None or not os.path.exists(fs_path):
            handler._send_error(404)
            return
        if os.path.isdir(fs_path):
            handler.send_response(200)
            handler.send_header('Content-Type', 'httpd/unix-directory')
            handler.end_headers()
            return
        st = os.stat(fs_path)
        handler.send_response(200)
        handler.send_header('Content-Length', str(st.st_size))
        handler.send_header('Last-Modified', email.utils.formatdate(timeval=st.st_mtime, localtime=False, usegmt=True))
        handler.end_headers()

    @staticmethod
    def handle_COPY_MOVE(handler, src_path, dst_path, move):
        src_fs = WebDAVFileHandler.resolve_dav_path(src_path)
        dst_fs = WebDAVFileHandler.resolve_dav_path(dst_path)
        if src_fs is None or dst_fs is None:
            handler._send_error(400, "Invalid path")
            return
        if not os.path.exists(src_fs):
            handler._send_error(404, "Source not found")
            return
        try:
            if os.path.isdir(src_fs):
                shutil.copytree(src_fs, dst_fs, dirs_exist_ok=True)
                if move:
                    shutil.rmtree(src_fs)
            else:
                shutil.copy2(src_fs, dst_fs)
                if move:
                    os.remove(src_fs)
            handler.send_response(201)
            handler.end_headers()
        except Exception as e:
            handler._send_error(500, str(e))
