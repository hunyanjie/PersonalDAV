import os
import ssl
import hashlib
import shutil
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from services.contact_service import ContactService
from services.event_service import EventService
from utils.logger import logger
from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_DESCRIPTION
from network.auth_middleware import AuthMiddleware
from network.carddav_handler import CardDAVHandler
from network.caldav_handler import CalDAVHandler
from network.webdav_file_handler import WebDAVFileHandler
from network.attachment_handler import AttachmentHandler


class DAVHandler(BaseHTTPRequestHandler):
    """WebDAV 请求处理器 — 路由分发至各协议处理器"""
    contact_service = None
    event_service = None

    def __init__(self, *args, **kwargs):
        if DAVHandler.contact_service is None:
            DAVHandler.contact_service = ContactService()
        if DAVHandler.event_service is None:
            DAVHandler.event_service = EventService()
        super().__init__(*args, **kwargs)

    # ── 认证 ────────────────────────────────────────────────────

    def _check_auth(self) -> bool:
        return AuthMiddleware.check_auth(self)

    def _send_401(self):
        AuthMiddleware._send_401(self)

    # ── HTTP 方法分发 ─────────────────────────────────────────────

    def do_OPTIONS(self):
        try:
            self.log_message(f"处理OPTIONS请求: {self.path}")
            self.send_response(200)
            self.send_header('Allow', 'OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, MKCOL, REPORT, COPY, MOVE')
            if self.path.startswith("/dav"):
                self.send_header('DAV', '1, 2')
            elif self.path.startswith("/contacts/"):
                self.send_header('DAV', '1, 2, addressbook')
            elif self.path.startswith("/events/"):
                self.send_header('DAV', '1, 2, calendar-access')
            else:
                self.send_header('DAV', '1, 2')
            self.end_headers()
        except Exception as e:
            self._send_error(500, str(e))

    def do_GET(self):
        try:
            self.log_message(f"处理GET请求: {self.path}")
            if not self._check_auth():
                return
            if self.path.startswith("/contacts/"):
                CardDAVHandler.do_GET(self)
            elif self.path.startswith("/events/"):
                CalDAVHandler.do_GET(self)
            elif self.path.startswith("/attachments/"):
                AttachmentHandler.do_GET(self)
            elif self.path == "/":
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                content = f"<h1>{SOFTWARE_NAME} v{SOFTWARE_VERSION}</h1><p>{SOFTWARE_DESCRIPTION}</p>"
                content += "<p>CardDAV endpoint: <a href='/contacts/'>/contacts/</a></p>"
                content += "<p>CalDAV endpoint: <a href='/events/'>/events/</a></p>"
                content += "<p>WebDAV endpoint: <a href='/dav/'>/dav/</a></p>"
                self.wfile.write(content.encode('utf-8'))
            elif self.path.startswith("/dav"):
                WebDAVFileHandler.handle_GET(self)
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_PUT(self):
        try:
            self.log_message(f"处理PUT请求: {self.path}")
            if not self._check_auth():
                return
            if self.path.startswith("/dav"):
                WebDAVFileHandler.handle_PUT(self)
                return
            content_length = int(self.headers['Content-Length'])
            data = self.rfile.read(content_length).decode('utf-8')
            if self.path.startswith("/contacts/"):
                CardDAVHandler.do_PUT(self, data)
            elif self.path.startswith("/events/"):
                CalDAVHandler.do_PUT(self, data)
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_PROPFIND(self):
        try:
            self.log_message(f"处理PROPFIND请求: {self.path}")
            if not self._check_auth():
                return
            self.send_response(207)
            self.send_header('Content-Type', 'text/xml; charset="utf-8"')
            self.end_headers()
            depth = self.headers.get('Depth', '0')
            is_collection = self.path.endswith('/')
            if self.path.startswith("/contacts/"):
                body = CardDAVHandler.do_PROPFIND(self, depth, is_collection)
            elif self.path.startswith("/events/"):
                body = CalDAVHandler.do_PROPFIND(self, depth, is_collection)
            elif self.path.startswith("/dav"):
                WebDAVFileHandler.handle_PROPFIND(self)
                return
            else:
                ns = ''
                rtype = ''
                from network.dav_xml_builder import wrap_multistatus
                body = wrap_multistatus(
                    [f'    <D:response>\n        <D:href>{self.path}</D:href>\n        <D:propstat>\n            <D:prop>\n                <D:resourcetype>{rtype}</D:resourcetype>\n                <D:getetag>""</D:getetag>\n                <D:getcontenttype>text/html</D:getcontenttype>\n                <D:getcontentlength>0</D:getcontentlength>\n            </D:prop>\n            <D:status>HTTP/1.1 200 OK</D:status>\n        </D:propstat>\n    </D:response>'],
                    ns
                )
            self.wfile.write(body)
        except Exception as e:
            self._send_error(500, str(e))

    def do_HEAD(self):
        try:
            self.log_message(f"处理HEAD请求: {self.path}")
            if not self._check_auth():
                return
            if self.path.startswith("/contacts/") and self.path.endswith(".vcf"):
                CardDAVHandler.do_HEAD(self)
            elif self.path.startswith("/events/") and self.path.endswith(".ics"):
                CalDAVHandler.do_HEAD(self)
            elif self.path.startswith("/dav"):
                WebDAVFileHandler.handle_HEAD(self)
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_DELETE(self):
        try:
            self.log_message(f"处理DELETE请求: {self.path}")
            if not self._check_auth():
                return
            if self.path.startswith("/contacts/"):
                CardDAVHandler.do_DELETE(self)
            elif self.path.startswith("/events/"):
                CalDAVHandler.do_DELETE(self)
            elif self.path.startswith("/dav"):
                WebDAVFileHandler.handle_DELETE(self)
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_MKCOL(self):
        try:
            self.log_message(f"处理MKCOL请求: {self.path}")
            if not self._check_auth():
                return
            if self.path.startswith("/dav"):
                WebDAVFileHandler.handle_MKCOL(self)
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_POST(self):
        try:
            self.log_message(f"处理POST请求: {self.path}")
            if not self._check_auth():
                return
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
            if self.path.startswith("/contacts/"):
                CardDAVHandler.do_POST(self, data)
            elif self.path.startswith("/events/"):
                CalDAVHandler.do_POST(self, data)
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_REPORT(self):
        try:
            self.log_message(f"处理REPORT请求: {self.path}")
            if not self._check_auth():
                return
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b""
            import xml.etree.ElementTree as ET
            root = ET.fromstring(body)
            ns = {"D": "DAV:", "C": "urn:ietf:params:xml:ns:carddav",
                  "CAL": "urn:ietf:params:xml:ns:caldav"}
            hrefs = [h.text for h in root.findall(".//D:href", ns) if h.text]
            if self.path.startswith("/contacts/"):
                body = CardDAVHandler.do_REPORT(self, hrefs)
            elif self.path.startswith("/events/"):
                body = CalDAVHandler.do_REPORT(self, hrefs)
            else:
                self._send_error(400, "Unsupported REPORT target")
                return
            self.send_response(207)
            self.send_header('Content-Type', 'text/xml; charset="utf-8"')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            logger.error(f"REPORT 错误: {e}")
            self._send_error(500, str(e))

    def do_COPY(self):
        dst = self.headers.get("Destination", "")
        if not dst:
            self._send_error(400, "Destination header required")
            return
        self.log_message(f"处理COPY请求: {self.path} -> {dst}")
        if not self._check_auth():
            return
        self._copy_or_move(self.path, dst, move=False)

    def do_MOVE(self):
        dst = self.headers.get("Destination", "")
        if not dst:
            self._send_error(400, "Destination header required")
            return
        self.log_message(f"处理MOVE请求: {self.path} -> {dst}")
        if not self._check_auth():
            return
        self._copy_or_move(self.path, dst, move=True)

    def _copy_or_move(self, src_path: str, dst_path: str, move: bool = False):
        if src_path.startswith("/dav"):
            WebDAVFileHandler.handle_COPY_MOVE(self, src_path, dst_path, move)
        elif src_path.startswith("/contacts/") or src_path.startswith("/events/"):
            if src_path.startswith("/contacts/"):
                svc = self.contact_service
                add_fn = lambda d: self.contact_service.add_contact(d)
                ext = ".vcf"
            else:
                svc = self.event_service
                add_fn = lambda d: self.event_service.add_event(d)
                ext = ".ics"
            src_uid = os.path.basename(src_path).replace(ext, "")
            dst_uid = os.path.basename(dst_path).replace(ext, "")
            raw = svc.get_by_uid(src_uid)
            if not raw:
                self._send_error(404, "Source not found")
                return
            add_fn(raw)
            if move and src_uid != dst_uid:
                svc.delete(src_uid)
            self.send_response(201)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"{'Moved' if move else 'Copied'} to {dst_uid}".encode())
        else:
            self._send_error(400, "Unsupported path")

    # ── 工具方法 ────────────────────────────────────────────────

    def _collection_ctag(self, service) -> str:
        tags = []
        if service:
            for uid, _ in service.get_all_items():
                etag = service.get_etag(uid) or ""
                tags.append(etag)
        return f'"ctag-{hashlib.md5("|".join(sorted(tags)).encode("utf-8")).hexdigest()[:16]}"'

    def _send_error(self, code, message=None):
        self.send_response(code)
        self.end_headers()
        if message:
            self.wfile.write(message.encode('utf-8'))
        self.log_message(f"错误 {code}: {message if message else ''}")

    def log_message(self, format, *args):
        message = format % args
        client_ip = self.client_address[0]
        method = self.command
        path = self.path
        log_line = f"[{client_ip}] {method} {path} - {message}"
        if len(args) >= 2:
            status_code = str(args[1])
            if status_code.startswith("1") or status_code.startswith("2"):
                logger.info(log_line)
            elif status_code.startswith("3"):
                logger.warning(log_line)
            elif status_code.startswith("4"):
                logger.error(log_line)
            else:
                logger.critical(log_line)
        else:
            logger.info(log_line)


class DAVServer:
    """WebDAV 服务器封装（支持可选 SSL/TLS）"""
    def __init__(self, port, ssl_enabled=False, ssl_certfile='', ssl_keyfile=''):
        self.port = port
        self.ssl_enabled = ssl_enabled
        self.ssl_certfile = ssl_certfile
        self.ssl_keyfile = ssl_keyfile
        self.server = None
        self.start_time = 0.0

    def start(self):
        self.start_time = time.time()
        self.server = HTTPServer(('', self.port), DAVHandler)
        self.server.sslmode = self.ssl_enabled and bool(self.ssl_certfile)
        scheme = "HTTPS" if self.server.sslmode else "HTTP"
        if self.ssl_enabled and self.ssl_certfile:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.ssl_certfile, self.ssl_keyfile if self.ssl_keyfile else None)
                self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
                logger.info(f"SSL/TLS 已启用，证书: {self.ssl_certfile}")
            except Exception as e:
                logger.error(f"SSL/TLS 配置失败: {e}")
                self.server.server_close()
                self.server = None
                raise
        logger.info(f"DAVServer 开始监听 {scheme} 端口 {self.port}")
        self.server.serve_forever()

    def stop(self):
        if self.server:
            logger.info("DAVServer 正在关闭...")
            self.server.shutdown()
            self.server.server_close()
            self.server = None
            logger.info("DAVServer 已关闭")
