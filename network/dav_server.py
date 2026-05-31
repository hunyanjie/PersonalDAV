import os
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

    def do_GET(self):
        try:
            self.log_message(f"处理GET请求: {self.path}")

            # 处理联系人请求
            if self.path.startswith("/contacts/"):
                if self.path.endswith(".vcf"):
                    uid = os.path.basename(self.path).replace(".vcf", "")
                    vcard = self.contact_service.get_by_uid(uid)
                    if vcard:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/vcard')
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
            content_length = int(self.headers['Content-Length'])
            data = self.rfile.read(content_length).decode('utf-8')

            if self.path.startswith("/contacts/"):
                uid = os.path.basename(self.path).replace(".vcf", "")
                self.contact_service.add_contact(data)
                self.send_response(201)
                self.end_headers()
                self.wfile.write(f"Contact {uid} created/updated".encode())
            elif self.path.startswith("/events/"):
                uid = os.path.basename(self.path).replace(".ics", "")
                self.event_service.add_event(data)
                self.send_response(201)
                self.end_headers()
                self.wfile.write(f"Event {uid} created/updated".encode())
            else:
                self._send_error(404)
        except Exception as e:
            self._send_error(500, str(e))

    def do_PROPFIND(self):
        try:
            self.log_message(f"处理PROPFIND请求: {self.path}")
            self.send_response(207)
            self.send_header('Content-Type', 'text/xml; charset="utf-8"')
            self.end_headers()
            response = f"""<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
    <D:response>
        <D:href>{self.path}</D:href>
        <D:propstat>
            <D:prop><D:resourcetype/></D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>
</D:multistatus>"""
            self.wfile.write(response.encode('utf-8'))
        except Exception as e:
            self._send_error(500, str(e))

    def do_OPTIONS(self):
        try:
            self.log_message(f"处理OPTIONS请求: {self.path}")
            self.send_response(200)
            self.send_header('Allow', 'OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND')
            self.send_header('DAV', '1, 2')
            self.end_headers()
        except Exception as e:
            self._send_error(500, str(e))

    def do_HEAD(self):
        """处理 HEAD 请求 - 1:1 还原 main_old.py 缺失方法"""
        try:
            self.log_message(f"处理HEAD请求: {self.path}")
            
            if self.path.startswith("/contacts/") and self.path.endswith(".vcf"):
                uid = os.path.basename(self.path).replace(".vcf", "")
                vcard = self.contact_service.get_contact(uid)
                if vcard:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/vcard')
                    self.send_header('Content-Length', str(len(vcard.encode('utf-8'))))
                    self.end_headers()
                else:
                    self._send_error(404, "Contact not found")
            elif self.path.startswith("/events/") and self.path.endswith(".ics"):
                uid = os.path.basename(self.path).replace(".ics", "")
                event = self.event_service.get_event(uid)
                if event:
                    self.send_response(200)
                    self.send_header('Content-type', 'text/calendar')
                    self.send_header('Content-Length', str(len(event.encode('utf-8'))))
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
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
            
            # 处理联系人创建
            if self.path.startswith("/contacts/"):
                uid = os.path.basename(self.path).replace(".vcf", "")
                self.contact_service.add_contact(data)
                self.send_response(201)
                self.end_headers()
                self.wfile.write(f"Contact {uid} created".encode())
            # 处理事件创建
            elif self.path.startswith("/events/"):
                uid = os.path.basename(self.path).replace(".ics", "")
                self.event_service.add_event(data)
                self.send_response(201)
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
    """WebDAV 服务器封装"""
    def __init__(self, port):
        self.port = port
        self.server = None

    def start(self):
        self.server = HTTPServer(('', self.port), DAVHandler)
        self.server.serve_forever()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
