import os
import ssl
import base64
import hashlib
import shutil
import time
import email.utils
from http.server import HTTPServer, BaseHTTPRequestHandler
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from utils.logger import logger
from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_DESCRIPTION
from network.webdav_helper import propfind_response, error_xml

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

        if svc.ip_bypasses_auth(client_ip):
            svc.log_auth(True, client_ip, "WebDAV", f"免密 IP UA={ua}")
            return True

        if not svc.is_password_required():
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

    # ── WebDAV 文件服务（/dav/ 路径） ───────────────────────────

    @staticmethod
    def _get_dav_root() -> str:
        return SettingsService().get_setting("dav_root", "./dav_root")

    def _resolve_dav_path(self, path: str) -> str | None:
        root = os.path.abspath(self._get_dav_root())
        clean = os.path.normpath(path.lstrip("/dav").lstrip("/").replace("\\", "/"))
        abs_path = os.path.normpath(os.path.join(root, clean))
        if not abs_path.startswith(root):
            return None
        return abs_path

    def _list_dav_entries(self, fs_path: str) -> list[dict[str, any]]:
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

    def _handle_dav_PROPFIND(self) -> None:
        fs_path = self._resolve_dav_path(self.path)
        if fs_path is None or not os.path.exists(fs_path):
            self._send_error(404, "Not found")
            return
        if not os.path.isdir(fs_path):
            self._send_error(400, "PROPFIND on non-collection")
            return

        entries = self._list_dav_entries(fs_path)
        body = propfind_response(self.path, entries)
        self.send_response(207)
        self.send_header('Content-Type', 'text/xml; charset="utf-8"')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_dav_GET(self) -> None:
        fs_path = self._resolve_dav_path(self.path)
        if fs_path is None:
            self._send_error(404, "Not found")
            return
        if os.path.isdir(fs_path):
            self._send_error(400, "Is a directory, use PROPFIND")
            return
        if not os.path.isfile(fs_path):
            self._send_error(404, "File not found")
            return

        st = os.stat(fs_path)
        mime = "application/octet-stream"
        _, ext = os.path.splitext(fs_path)
        ext_map = {".txt": "text/plain", ".html": "text/html", ".json": "application/json",
                   ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                   ".gif": "image/gif", ".pdf": "application/pdf", ".xml": "text/xml",
                   ".zip": "application/zip", ".mp3": "audio/mpeg", ".mp4": "video/mp4",
                   ".vcf": "text/vcard", ".ics": "text/calendar"}
        mime = ext_map.get(ext.lower(), "application/octet-stream")

        self.send_response(200)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(st.st_size))
        self.send_header('Last-Modified', email.utils.formatdate(timeval=st.st_mtime, localtime=False, usegmt=True))
        self.end_headers()
        with open(fs_path, "rb") as f:
            shutil.copyfileobj(f, self.wfile)

    def _handle_dav_PUT(self) -> None:
        fs_path = self._resolve_dav_path(self.path)
        if fs_path is None:
            self._send_error(400, "Invalid path")
            return
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            os.makedirs(os.path.dirname(fs_path), exist_ok=True)
            with open(fs_path, "wb") as f:
                if content_length > 0:
                    chunk_size = 65536
                    remaining = content_length
                    while remaining > 0:
                        chunk = self.rfile.read(min(chunk_size, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
            self.send_response(201)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Created")
        except Exception as e:
            self._send_error(500, str(e))

    def _handle_dav_DELETE(self) -> None:
        fs_path = self._resolve_dav_path(self.path)
        if fs_path is None or not os.path.exists(fs_path):
            self._send_error(404, "Not found")
            return
        try:
            if os.path.isdir(fs_path):
                shutil.rmtree(fs_path)
            else:
                os.remove(fs_path)
            self.send_response(204)
            self.end_headers()
        except Exception as e:
            self._send_error(500, str(e))

    def _handle_dav_MKCOL(self) -> None:
        fs_path = self._resolve_dav_path(self.path)
        if fs_path is None:
            self._send_error(400, "Invalid path")
            return
        if os.path.exists(fs_path):
            self._send_error(405, "Already exists")
            return
        try:
            os.makedirs(fs_path)
            self.send_response(201)
            self.end_headers()
        except Exception as e:
            self._send_error(500, str(e))

    def _handle_dav_HEAD(self) -> None:
        fs_path = self._resolve_dav_path(self.path)
        if fs_path is None or not os.path.exists(fs_path):
            self._send_error(404)
            return
        if os.path.isdir(fs_path):
            self.send_response(200)
            self.send_header('Content-Type', 'httpd/unix-directory')
            self.end_headers()
            return
        st = os.stat(fs_path)
        self.send_response(200)
        self.send_header('Content-Length', str(st.st_size))
        self.send_header('Last-Modified', email.utils.formatdate(timeval=st.st_mtime, localtime=False, usegmt=True))
        self.end_headers()

    def _collection_ctag(self, service) -> str:
        """计算集合的 CTag（所有子资源的 ETag 哈希）"""
        tags = []
        if service:
            for uid, _ in service.get_all_items():
                etag = service.get_etag(uid) or ""
                tags.append(etag)
        return f'"ctag-{hashlib.md5("|".join(sorted(tags)).encode("utf-8")).hexdigest()[:16]}"'

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
                elif self.path == "/events/":
                    self.send_response(200)
                    self.send_header('Content-type', 'text/calendar')
                    self.end_headers()
                    all_events = self.event_service.get_all_raw()
                    calendar_data = self.event_service.combine_raw_events(all_events)
                    self.wfile.write(calendar_data.encode('utf-8'))
                else:
                    self._send_error(404, "Event not found")

            # 根路径
            elif self.path == "/":
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                content = f"<h1>{SOFTWARE_NAME} v{SOFTWARE_VERSION}</h1><p>{SOFTWARE_DESCRIPTION}</p>"
                content += "<p>CardDAV endpoint: <a href='/contacts/'>/contacts/</a></p>"
                content += "<p>CalDAV endpoint: <a href='/events/'>/events/</a></p>"
                content += "<p>WebDAV endpoint: <a href='/dav/'>/dav/</a></p>"
                self.wfile.write(content.encode('utf-8'))

            # WebDAV 文件服务
            elif self.path.startswith("/dav"):
                self._handle_dav_GET()
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
                self._handle_dav_PUT()
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
            elif self.path.startswith("/dav"):
                self._handle_dav_PROPFIND()
                return
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
                ctag = self._collection_ctag(svc)
                # 替换标准 resource_xml 以包含 CTag
                responses.append(f"""    <D:response>
        <D:href>{self.path}</D:href>
        <D:propstat>
            <D:prop>
                <D:resourcetype>{rtype}</D:resourcetype>
                <D:getetag>{etag}</D:getetag>
                <D:getcontenttype>{ctype}</D:getcontenttype>
                <D:getcontentlength>0</D:getcontentlength>
                <getctag xmlns="http://calendarserver.org/ns/">{ctag}</getctag>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>""")
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
            elif self.path.startswith("/dav"):
                self._handle_dav_DELETE()
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
                self._handle_dav_MKCOL()
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

            # 读取所有 <D:href> 中的路径
            hrefs = [h.text for h in root.findall(".//D:href", ns) if h.text]

            if self.path.startswith("/contacts/"):
                svc = self.contact_service
                ext = ".vcf"
                ctype = "text/vcard"
            elif self.path.startswith("/events/"):
                svc = self.event_service
                ext = ".ics"
                ctype = "text/calendar"
            else:
                self._send_error(400, "Unsupported REPORT target")
                return

            responses = []
            for href in hrefs:
                uid = os.path.basename(href).replace(ext, "")
                raw = svc.get_by_uid(uid)
                if raw:
                    etag = svc.get_etag(uid) or f'"{hashlib.md5(raw.encode("utf-8")).hexdigest()}"'
                    responses.append(f"""    <D:response>
        <D:href>{href}</D:href>
        <D:propstat>
            <D:prop>
                <D:getetag>{etag}</D:getetag>
                <D:getcontenttype>{ctype}</D:getcontenttype>
                <D:getcontentlength>{len(raw.encode("utf-8"))}</D:getcontentlength>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>""")
                else:
                    responses.append(f"""    <D:response>
        <D:href>{href}</D:href>
        <D:status>HTTP/1.1 404 Not Found</D:status>
    </D:response>""")

            response_xml = f"""<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
{chr(10).join(responses)}
</D:multistatus>"""
            self.send_response(207)
            self.send_header('Content-Type', 'text/xml; charset="utf-8"')
            self.send_header('Content-Length', str(len(response_xml.encode('utf-8'))))
            self.end_headers()
            self.wfile.write(response_xml.encode('utf-8'))
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
            src_fs = self._resolve_dav_path(src_path)
            dst_fs = self._resolve_dav_path(dst_path)
            if src_fs is None or dst_fs is None:
                self._send_error(400, "Invalid path")
                return
            if not os.path.exists(src_fs):
                self._send_error(404, "Source not found")
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
                self.send_response(201)
                self.end_headers()
            except Exception as e:
                self._send_error(500, str(e))
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
