import os
import ssl
import base64
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from services.contact_service import ContactService
from services.event_service import EventService
from utils.logger import logger
from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_DESCRIPTION

class DAVHandler(BaseHTTPRequestHandler):
    """WebDAV 请求处理器"""
    contact_service = None
    event_service = None

    def __init__(self, *args, **kwargs):
        if DAVHandler.contact_service is None:
            DAVHandler.contact_service = ContactService()
        if DAVHandler.event_service is None:
            DAVHandler.event_service = EventService()
        super().__init__(*args, **kwargs)

    def _check_auth(self) -> bool:
        from services.auth_service import AuthService
        svc = AuthService()
        client_ip = self.client_address[0]
        ua = self.headers.get('User-Agent', '')

        if not svc.check_ip(client_ip):
            svc.log_auth(False, client_ip, "WebDAV", f"IP被拒绝 UA={ua}")
            self._send_401()
            return False

        if not svc.check_rate_limit(client_ip):
            self.send_response(429)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Too Many Requests")
            return False

        if not svc.is_enabled():
            return True

        if svc.ip_bypasses_auth(client_ip):
            svc.log_auth(True, client_ip, "WebDAV", f"免密 IP UA={ua}")
            return True

        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Basic '):
            svc.log_auth(False, client_ip, "WebDAV", f"无凭证 UA={ua}")
            self._send_401()
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            _, password = decoded.split(':', 1)
        except Exception:
            svc.log_auth(False, client_ip, "WebDAV", f"凭证格式错误 UA={ua}")
            self._send_401()
            return False
        if not svc.verify_password(password):
            svc.log_auth(False, client_ip, "WebDAV", f"密码错误 UA={ua}")
            self._send_401()
            return False

        svc.log_auth(True, client_ip, "WebDAV", f"UA={ua}")
        return True

    def _send_401(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="PersonalDAV"')
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"Authorization required")

    def do_OPTIONS(self):
        try:
            self.log_message(f"处理OPTIONS请求: {self.path}")
            self.send_response(200)
            self.send_header('Allow', 'OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND')
            if self.path.startswith("/contacts/"):
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

            # 处理联系人请求
            if self.path.startswith("/contacts/"):
                if self.path.endswith(".vcf"):
                    uid = os.path.basename(self.path).replace(".vcf", "")
                    vcard = self.contact_service.get_by_uid(uid)
                    if vcard:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/vcard')
                        self.send_header('ETag', self.contact_service.get_etag(uid) or '')
                        self.end_headers()
                        self.wfile.write(vcard.encode('utf-8'))
                    else:
                        self._send_error(404, "Contact not found")
                elif self.path == "/contacts/":
                    self.send_response(200)
                    self.send_header('Content-type', 'text/directory')
                    self.end_headers()
                    all_vcards = self.contact_service.get_all_raw()
                    for vcard in all_vcards:
                        self.wfile.write(vcard.encode('utf-8'))
                        self.wfile.write(b"\n")
                else:
                    self._send_error(404)

            # 处理日历请求
            elif self.path.startswith("/events/"):
                if self.path.endswith(".ics"):
                    uid = os.path.basename(self.path).replace(".ics", "")
                    event = self.event_service.get_by_uid(uid)
                    if event:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/calendar')
                        self.send_header('ETag', self.event_service.get_etag(uid) or '')
                        self.end_headers()
                        self.wfile.write(event.encode('utf-8'))
                    else:
                        self._send_error(404, "Event not found")
                elif self.path == "/events/":
                    self.send_response(200)
                    self.send_header('Content-type', 'text/calendar')
                    self.end_headers()
                    all_events = self.event_service.get_all_raw()
                    calendar_data = self.event_service.combine_raw_events(all_events)
                    self.wfile.write(calendar_data.encode('utf-8'))
                else:
                    self._send_error(404)

            # 根路径
            elif self.path == "/":
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                content = f"<h1>{SOFTWARE_NAME} v{SOFTWARE_VERSION}</h1><p>{SOFTWARE_DESCRIPTION}</p>"
                content += "<p>CardDAV endpoint: <a href='/contacts/'>/contacts/</a></p>"
                content += "<p>CalDAV endpoint: <a href='/events/'>/events/</a></p>"
                self.wfile.write(content.encode('utf-8'))
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_PUT(self):
        try:
            self.log_message(f"处理PUT请求: {self.path}")
            if not self._check_auth():
                return
            content_length = int(self.headers['Content-Length'])
            data = self.rfile.read(content_length).decode('utf-8')

            if self.path.startswith("/contacts/"):
                uid = os.path.basename(self.path).replace(".vcf", "")
                self.contact_service.add_contact(data)
                self.send_response(201)
                self.send_header('Content-type', 'text/plain')
                self.send_header('ETag', self.contact_service.get_etag(uid) or '')
                self.end_headers()
                self.wfile.write(f"Contact {uid} created/updated".encode())
            elif self.path.startswith("/events/"):
                uid = os.path.basename(self.path).replace(".ics", "")
                self.event_service.add_event(data)
                self.send_response(201)
                self.send_header('Content-type', 'text/plain')
                self.send_header('ETag', self.event_service.get_etag(uid) or '')
                self.end_headers()
                self.wfile.write(f"Event {uid} created/updated".encode())
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
                ns = 'xmlns:C="urn:ietf:params:xml:ns:carddav"'
                rtype = '<C:addressbook/>'
                svc = self.contact_service
                ext = '.vcf'
                ctype = 'text/vcard'
            elif self.path.startswith("/events/"):
                ns = 'xmlns:C="urn:ietf:params:xml:ns:caldav"'
                rtype = '<C:calendar/>'
                svc = self.event_service
                ext = '.ics'
                ctype = 'text/calendar'
            else:
                ns = ''
                rtype = ''
                svc = None
                ext = ''
                ctype = ''

            responses = []

            def resource_xml(href, rtype_xml, etag_val, ctype_val, res_size):
                return f"""    <D:response>
        <D:href>{href}</D:href>
        <D:propstat>
            <D:prop>
                <D:resourcetype>{rtype_xml}</D:resourcetype>
                <D:getetag>{etag_val}</D:getetag>
                <D:getcontenttype>{ctype_val}</D:getcontenttype>
                <D:getcontentlength>{res_size}</D:getcontentlength>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>"""

            if svc and is_collection:
                etag = svc.get_etag("") or '"dummy"'
                responses.append(resource_xml(self.path, rtype, etag, ctype, "0"))
                if depth != '0':
                    for uid, raw in svc.get_all_items():
                        child_href = f"{self.path}{uid}{ext}"
                        child_etag = svc.get_etag(uid) or f'"{hashlib.md5(raw.encode("utf-8")).hexdigest()}"'
                        responses.append(resource_xml(child_href, '', child_etag, ctype, str(len(raw.encode('utf-8')))))
            elif svc and not is_collection:
                uid = os.path.basename(self.path).replace(ext, '')
                etag = svc.get_etag(uid) or '""'
                responses.append(resource_xml(self.path, '', etag, ctype, "0"))
            else:
                responses.append(resource_xml(self.path, rtype, '""', 'text/html', "0"))

            response_xml = f"""<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:" {ns}>
{chr(10).join(responses)}
</D:multistatus>"""
            self.wfile.write(response_xml.encode('utf-8'))
        except Exception as e:
            self._send_error(500, str(e))

    def do_HEAD(self):
        """处理 HEAD 请求 - 1:1 还原 main_old.py 缺失方法"""
        try:
            self.log_message(f"处理HEAD请求: {self.path}")
            if not self._check_auth():
                return
            
            if self.path.startswith("/contacts/") and self.path.endswith(".vcf"):
                uid = os.path.basename(self.path).replace(".vcf", "")
                vcard = self.contact_service.get_by_uid(uid)
                if vcard:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/vcard')
                    self.send_header('Content-Length', str(len(vcard.encode('utf-8'))))
                    self.send_header('ETag', self.contact_service.get_etag(uid) or '')
                    self.end_headers()
                else:
                    self._send_error(404, "Contact not found")
            elif self.path.startswith("/events/") and self.path.endswith(".ics"):
                uid = os.path.basename(self.path).replace(".ics", "")
                event = self.event_service.get_by_uid(uid)
                if event:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/calendar')
                    self.send_header('Content-Length', str(len(event.encode('utf-8'))))
                    self.send_header('ETag', self.event_service.get_etag(uid) or '')
                    self.end_headers()
                else:
                    self._send_error(404, "Event not found")
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_DELETE(self):
        """处理 DELETE 请求 - 1:1 还原 main_old.py 缺失方法"""
        try:
            self.log_message(f"处理DELETE请求: {self.path}")
            if not self._check_auth():
                return
            
            if self.path.startswith("/contacts/"):
                uid = os.path.basename(self.path).replace(".vcf", "")
                if self.contact_service.delete(uid):
                    self.send_response(204)
                    self.end_headers()
                else:
                    self._send_error(404, "Contact not found")
            elif self.path.startswith("/events/"):
                uid = os.path.basename(self.path).replace(".ics", "")
                if self.event_service.delete(uid):
                    self.send_response(204)
                    self.end_headers()
                else:
                    self._send_error(404, "Event not found")
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_POST(self):
        """处理 POST 请求 - 用于表单提交"""
        try:
            self.log_message(f"处理POST请求: {self.path}")
            if not self._check_auth():
                return
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
            
            # 处理联系人创建
            if self.path.startswith("/contacts/"):
                uid = os.path.basename(self.path).replace(".vcf", "")
                self.contact_service.add_contact(data)
                self.send_response(201)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Contact {uid} created".encode())
            # 处理事件创建
            elif self.path.startswith("/events/"):
                uid = os.path.basename(self.path).replace(".ics", "")
                self.event_service.add_event(data)
                self.send_response(201)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Event {uid} created".encode())
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

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
        import time
        self.start_time = time.time()
        self.server = HTTPServer(('', self.port), DAVHandler)
        scheme = "HTTPS" if (self.ssl_enabled and self.ssl_certfile) else "HTTP"
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
