import base64
import locale
import logging
import os
import queue
import quopri
import sqlite3
import tempfile  # 用于从WebDAV导入时生成临时文件
import threading
import tkinter as tk
import traceback
import uuid
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from tkinter import ttk, messagebox, simpledialog, filedialog
from urllib.parse import urlparse

import pytz
import requests
import vobject
from babel.dates import get_timezone_name
from dateutil import parser
from tkcalendar import DateEntry
from tkinterdnd2 import TkinterDnD, DND_FILES
from tzlocal import get_localzone
from webdav3.client import Client


# ======================
# 配置日志和基础信息
# ======================
class GUIHandler(logging.Handler):
    """自定义日志处理器，将日志发送到GUI"""

    def __init__(self, app):
        super().__init__()
        self.app = app
        # 设置格式化器 - 添加时间戳
        self.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S'))

    def emit(self, record):
        try:
            # 使用格式化器格式化日志消息
            formatted_message = self.format(record)

            # 将格式化后的日志添加到队列
            self.app.log_queue.put(formatted_message)
        except Exception:
            self.handleError(record)


# 创建日志记录器
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# 清除可能已有的处理器
if logger.hasHandlers(): logger.handlers.clear()

# 创建文件处理器
file_handler = logging.FileHandler("dav_server.log", encoding='utf-8')
file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# 创建控制台处理器
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)

# 添加到记录器
logger.addHandler(file_handler)
logger.addHandler(console_handler)

software_name = "PrivateDAV"
software_description = "私人 CardDAV/CalDAV 服务"
software_version = "1.2"
software_author = "hunyanjie"


# ======================
# 数据库管理
# ======================
class Database:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path='dav_data.db'):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(Database, cls).__new__(cls)
                    cls._instance._initialize(db_path)
        return cls._instance

    def _initialize(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA busy_timeout = 5000;")
        self.create_tables()

    def create_tables(self):
        c = self.conn.cursor()
        # 联系人表
        c.execute(
            '''CREATE TABLE IF NOT EXISTS contacts (id INTEGER PRIMARY KEY, uid TEXT UNIQUE, full_name TEXT, email TEXT, phone TEXT, vcard TEXT)''')
        # 日历事件表
        c.execute(
            '''CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, uid TEXT UNIQUE, summary TEXT, dtstart TEXT, dtend TEXT, ical TEXT)''')
        self.conn.commit()

    def add_contact(self, vcard_data):
        with self._lock:
            try:
                try:
                    vcard = vobject.readOne(vcard_data)
                except Exception as e:
                    logger.warning(f"使用 vobject 解析失败，尝试手动解析: {str(e)}")
                    return self._manual_add_contact(vcard_data)

                uid = getattr(vcard, 'uid', None)
                if uid is None:
                    uid = str(uuid.uuid4())
                    logger.info(f"生成新 UID: {uid}")
                else:
                    uid = uid.value

                full_name = ""
                if hasattr(vcard, 'fn'):
                    full_name = vcard.fn.value
                elif hasattr(vcard, 'n'):
                    n = vcard.n.value
                    name_parts = []
                    if hasattr(n, 'prefix') and n.prefix:
                        name_parts.append(n.prefix)
                    if hasattr(n, 'given') and n.given:
                        name_parts.append(n.given)
                    if hasattr(n, 'additional') and n.additional:
                        name_parts.append(n.additional)
                    if hasattr(n, 'family') and n.family:
                        name_parts.append(n.family)
                    if hasattr(n, 'suffix') and n.suffix:
                        name_parts.append(n.suffix)
                    full_name = " ".join(name_parts)

                emails = []
                if hasattr(vcard, 'email_list'):
                    for email in vcard.email_list:
                        emails.append(email.value)
                elif hasattr(vcard, 'email'):
                    emails.append(vcard.email.value)

                phones = []
                if hasattr(vcard, 'tel_list'):
                    for tel in vcard.tel_list:
                        phones.append(tel.value)
                elif hasattr(vcard, 'tel'):
                    phones.append(vcard.tel.value)

                # 检查联系人是否已存在
                c = self.conn.cursor()
                c.execute("SELECT vcard FROM contacts WHERE uid=?", (uid,))
                existing = c.fetchone()

                # 确定操作类型
                operation = "inserted"
                if existing:
                    if existing[0] == vcard_data:
                        operation = "unchanged"
                    else:
                        operation = "updated"

                # 执行数据库操作
                if operation != "unchanged":
                    c.execute(
                        '''INSERT OR REPLACE INTO contacts (uid, full_name, email, phone, vcard) VALUES (?, ?, ?, ?, ?)''',
                              (uid, full_name, ";".join(emails), ";".join(phones), vcard_data))
                    self.conn.commit()

                return uid, operation
            except Exception as e:
                self.conn.rollback()
                logger.error(f"添加联系人失败: {str(e)}")
                return None, f"Error: {str(e)}"

    def _manual_add_contact(self, vcard_data):
        """手动解析 vCard 数据"""
        try:
            properties = {}
            current_property = None

            for line in vcard_data.splitlines():
                line = line.strip()
                if not line: continue

                if line.startswith(" ") or line.startswith("\t"):
                    if current_property:
                        properties[current_property]["value"] += line.strip()
                    continue

                # 解析属性
                if ":" in line:
                    name_part, value_part = line.split(":", 1)
                    parts = name_part.split(";")
                    name = parts[0].strip()
                    params = {}

                    # 解析参数
                    for part in parts[1:]:
                        if "=" in part:
                            key, val = part.split("=", 1)
                            params[key.lower()] = val

                    # 处理编码
                    encoding = params.get("encoding", "").lower()
                    charset = params.get("charset", "utf-8").lower()

                    # 解码值
                    if encoding == "quoted-printable":
                        value = quopri.decodestring(value_part).decode(charset, errors="replace")
                    elif encoding == "base64" or encoding == "b":
                        value = base64.b64decode(value_part).decode(charset, errors="replace")
                    else:
                        value = value_part

                    # 处理 CHARSET
                    if charset != "utf-8":
                        try:
                            value = value.encode('latin1').decode(charset, errors="replace")
                        except BaseException:
                            pass

                    properties[name] = {"value": value, "params": params}
                    current_property = name
                else:
                    logger.warning(f"忽略无效行: {line}")

            uid = properties.get("UID", {}).get("value", str(uuid.uuid4()))
            full_name = properties.get("FN", {}).get("value", "")

            if not full_name and "N" in properties:
                n_value = properties["N"]["value"]
                n_parts = n_value.split(";")
                if len(n_parts) >= 5:
                    # 格式: 姓;名;中间名;前缀;后缀
                    family, given, additional, prefix, suffix = n_parts[:5]
                    name_parts = []
                    if prefix: name_parts.append(prefix)
                    if given: name_parts.append(given)
                    if additional: name_parts.append(additional)
                    if family: name_parts.append(family)
                    if suffix: name_parts.append(suffix)
                    full_name = " ".join(name_parts)

            emails = []
            for key in properties:
                if key.startswith("EMAIL") or key == "EMAIL":
                    emails.append(properties[key]["value"])

            phones = []
            for key in properties:
                if key.startswith("TEL") or key == "TEL":
                    phones.append(properties[key]["value"])

            # 检查联系人是否已存在
            c = self.conn.cursor()
            c.execute("SELECT vcard FROM contacts WHERE uid=?", (uid,))
            existing = c.fetchone()

            # 确定操作类型
            operation = "inserted"
            if existing:
                if existing[0] == vcard_data:
                    operation = "unchanged"
                else:
                    operation = "updated"

            # 执行数据库操作
            if operation != "unchanged":
                c.execute(
                    '''INSERT OR REPLACE INTO contacts (uid, full_name, email, phone, vcard) VALUES (?, ?, ?, ?, ?)''',
                          (uid, full_name, ";".join(emails), ";".join(phones), vcard_data))
                self.conn.commit()

            return uid, operation
        except Exception as e:
            self.conn.rollback()
            logger.error(f"手动解析联系人失败: {str(e)}")
            return None, f"Error: {str(e)}"

    def get_contact(self, uid):
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT vcard FROM contacts WHERE uid=?", (uid,))
            result = c.fetchone()
            return result[0] if result else None

    def get_contacts(self):
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT uid, full_name, email, phone FROM contacts")
            return c.fetchall()

    def get_all_contacts(self):
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT vcard FROM contacts")
            return [row[0] for row in c.fetchall()]

    def get_selected_contacts(self, uids):
        """获取选中的联系人数据"""
        if not uids: return []

        with self._lock:
            c = self.conn.cursor()
            placeholders = ','.join(['?'] * len(uids))
            c.execute(f"SELECT vcard FROM contacts WHERE uid IN ({placeholders})", uids)
            return [row[0] for row in c.fetchall()]

    def delete_contact(self, uid):
        with self._lock:
            c = self.conn.cursor()
            c.execute("DELETE FROM contacts WHERE uid=?", (uid,))
            self.conn.commit()
            return True

    def add_event(self, ical_data):
        with self._lock:
            try:
                ical = vobject.readOne(ical_data)
                uid = ical.vevent.uid.value
                summary = ical.vevent.summary.value if hasattr(ical.vevent, 'summary') else ""
                dtstart = ical.vevent.dtstart.value if hasattr(ical.vevent, 'dtstart') else ""
                dtend = ical.vevent.dtend.value if hasattr(ical.vevent, 'dtend') else ""

                # 检查事件是否已存在
                c = self.conn.cursor()
                c.execute("SELECT ical FROM events WHERE uid=?", (uid,))
                existing = c.fetchone()

                # 确定操作类型
                operation = "inserted"
                if existing:
                    if existing[0] == ical_data:
                        operation = "unchanged"
                    else:
                        operation = "updated"

                # 执行数据库操作 - 保存原始数据
                if operation != "unchanged":
                    c.execute(
                        '''INSERT OR REPLACE INTO events (uid, summary, dtstart, dtend, ical) VALUES (?, ?, ?, ?, ?)''',
                              (uid, summary, dtstart, dtend, ical_data))
                    self.conn.commit()

                return uid, operation
            except Exception as e:
                self.conn.rollback()
                logger.error(f"添加事件失败: {str(e)}")
                traceback.print_exc()
                return None, f"Error: {str(e)}"

    def get_event(self, uid):
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT ical FROM events WHERE uid=?", (uid,))
            result = c.fetchone()
            return result[0] if result else None

    def get_events(self):
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT uid, summary, dtstart, dtend FROM events")
            return c.fetchall()

    def get_all_events(self):
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT ical FROM events")
            events = []
            for row in c.fetchall():
                try:
                    cal = vobject.readOne(row[0])
                    for component in cal.components():
                        if component.name == 'VEVENT':
                            events.append(component.serialize())
                except Exception as e:
                    logger.error(f"解析事件失败: {str(e)}")
                    continue
            return events

    def get_selected_events(self, uids):
        if not uids: return []
        with self._lock:
            c = self.conn.cursor()
            placeholders = ','.join(['?'] * len(uids))
            c.execute(f"SELECT ical FROM events WHERE uid IN ({placeholders})", uids)
            events = []
            for row in c.fetchall():
                try:
                    cal = vobject.readOne(row[0])
                    for component in cal.components():
                        if component.name == 'VEVENT':
                            events.append(component.serialize())
                except Exception as e:
                    logger.error(f"解析事件失败: {str(e)}")
                    continue
            return events

    def delete_event(self, uid):
        with self._lock:
            c = self.conn.cursor()
            c.execute("DELETE FROM events WHERE uid=?", (uid,))
            self.conn.commit()
            return True

    def count_contacts(self):
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT COUNT(*) FROM contacts")
            return c.fetchone()[0]

    def count_events(self):
        with self._lock:
            c = self.conn.cursor()
            c.execute("SELECT COUNT(*) FROM events")
            return c.fetchone()[0]

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None


# ======================
# WebDAV 服务器
# ======================
class SimpleDAVHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        db = Database()
        try:
            self.log_message(f"处理GET请求: {self.path}")

            # 处理联系人请求
            if self.path.startswith("/contacts/"):
                # 请求单个联系人
                if self.path.endswith(".vcf"):
                    uid = os.path.basename(self.path).replace(".vcf", "")
                    vcard = db.get_contact(uid)
                    if vcard:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/vcard')
                        self.end_headers()
                        self.wfile.write(vcard.encode('utf-8'))
                    else:
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write(b"Contact not found")
                # 请求所有联系人
                elif self.path == "/contacts/":
                    self.send_response(200)
                    self.send_header('Content-type', 'text/directory')
                    self.end_headers()

                    # 生成包含所有联系人的vCard集合
                    all_contacts = db.get_all_contacts()
                    for vcard in all_contacts:
                        self.wfile.write(vcard.encode('utf-8'))
                        self.wfile.write(b"\n")
                else:
                    self.send_response(404)
                    self.end_headers()

            # 处理日历请求
            elif self.path.startswith("/events/"):
                # 请求单个事件
                if self.path.endswith(".ics"):
                    uid = os.path.basename(self.path).replace(".ics", "")
                    event = db.get_event(uid)
                    if event:
                        self.send_response(200)
                        self.send_header('Content-type', 'text/calendar')
                        self.end_headers()
                        self.wfile.write(event.encode('utf-8'))
                    else:
                        self.send_response(404)
                        self.end_headers()
                        self.wfile.write(b"Event not found")
                # 请求所有事件
                elif self.path == "/events/":
                    self.send_response(200)
                    self.send_header('Content-type', 'text/calendar')
                    self.end_headers()

                    # 生成包含所有事件的iCalendar集合
                    all_events = db.get_all_events()
                    self.wfile.write((
                                                 "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//" + software_name + "//" + software_version + "ZH-CN\n").encode(
                        'utf-8'))
                    for event in all_events:
                        self.wfile.write(event.encode('utf-8'))
                    self.wfile.write("END:VCALENDAR\n".encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()

            # 根路径显示服务信息
            elif self.path == "/":
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(bytes(software_name + " v" + software_version + " - " + software_description, "utf-8"))
                self.wfile.write(b"<p>CardDAV endpoint: <a href='/contacts/'>/contacts/</a></p>")
                self.wfile.write(b"<p>CalDAV endpoint: <a href='/events/'>/events/</a></p>")

            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            error_msg = f"Server error: {str(e)}"
            self.wfile.write(error_msg.encode('utf-8'))
            self.log_message(f"PUT请求处理失败: {str(e)}")

    def do_PUT(self):
        db = Database()
        try:
            self.log_message(f"处理PUT请求: {self.path}")

            content_length = int(self.headers['Content-Length'])
            data = self.rfile.read(content_length).decode('utf-8')

            if self.path.startswith("/contacts/"):
                uid = os.path.basename(self.path).replace(".vcf", "")
                db.add_contact(data)
                self.send_response(201)
                self.end_headers()
                self.wfile.write(f"Contact {uid} created/updated".encode())

            elif self.path.startswith("/events/"):
                uid = os.path.basename(self.path).replace(".ics", "")
                db.add_event(data)
                self.send_response(201)
                self.end_headers()
                self.wfile.write(f"Event {uid} created/updated".encode())

            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            error_msg = f"Server error: {str(e)}"
            self.wfile.write(error_msg.encode('utf-8'))
            self.log_message(f"PROPFIND请求处理失败: {str(e)}")

    def do_PROPFIND(self):
        try:
            self.log_message(f"处理PROPFIND请求: {self.path}")

            self.send_response(207)
            self.send_header('Content-Type', 'text/xml; charset="utf-8"')
            self.end_headers()

            # 返回一个基本的WebDAV多状态响应
            response = """<?xml version="1.0" encoding="utf-8" ?><D:multistatus xmlns:D="DAV:"><D:response><D:href>{}</D:href><D:propstat><D:prop><D:resourcetype/></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>""".format(
                self.path)

            self.wfile.write(response.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            error_msg = f"Server error: {str(e)}"
            self.wfile.write(error_msg.encode('utf-8'))
            self.log_message(f"PROPFIND请求处理失败: {str(e)}")

    def do_OPTIONS(self):
        try:
            self.log_message(f"处理OPTIONS请求: {self.path}")

            self.send_response(200)
            self.send_header('Allow', 'OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND')
            self.send_header('DAV', '1, 2')
            self.end_headers()
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            error_msg = f"Server error: {str(e)}"
            self.wfile.write(error_msg.encode('utf-8'))
            self.log_message(f"OPTIONS请求处理失败: {str(e)}")

    def log_message(self, format, *args):
        # 生成日志消息
        message = format % args
        client_ip = self.client_address[0]

        # 添加请求方法信息
        method = self.command
        path = self.path

        # 创建详细的日志行
        log_line = f"[{client_ip}] {method} {path} - {message}"

        # 根据HTTP状态码确定日志级别
        if len(args) >= 2:
            status_code = args[1] if isinstance(args[1], str) else str(args[1])
            if status_code.startswith("1"):
                logger.info(log_line)
            elif status_code.startswith("2"):
                logger.info(log_line)  # 调试信息也用INFO级别
            elif status_code.startswith("3"):
                logger.warning(log_line)
            elif status_code.startswith("4"):
                logger.error(log_line)
            elif status_code.startswith("5"):
                logger.critical(log_line)
            else:
                logger.info(log_line)  # 其他状态码默认使用info级别
        else:
            logger.info(log_line)  # 没有状态码时使用info级别


# ======================
# 从 WebDAV 中获取数据
# ======================
class WebDAVClient:
    def __init__(self):
        self.cancel_event = threading.Event()
        self.import_lock = threading.Lock()
        self.active_downloads = []

    def create_import_dialog(self, parent, title, on_complete=None):
        """创建通用的WebDAV导入对话框"""
        dialog = tk.Toplevel(parent)
        dialog.title(title)
        dialog.geometry('500x300')
        dialog.transient(parent)
        dialog.grab_set()

        ttk.Label(dialog, text='WebDAV服务器配置', font=('Arial', 12)).pack(pady=10)

        frame = ttk.Frame(dialog)
        frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)

        ttk.Label(frame, text='服务器地址:').grid(row=0, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(frame, width=40)
        self.url_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text='用户名:').grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_entry = ttk.Entry(frame, width=40)
        self.username_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text='密码:').grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(frame, width=40, show='*')
        self.password_entry.grid(row=2, column=1, sticky=tk.W, pady=5)

        ttk.Label(frame, text='路径(可选):').grid(row=3, column=0, sticky=tk.W, pady=5)
        self.path_entry = ttk.Entry(frame, width=40)
        self.path_entry.grid(row=3, column=1, sticky=tk.W, pady=5)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=10)

        ttk.Button(button_frame, text='导入', command=lambda: self.start_import(
            dialog, on_complete)).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text='取消', command=dialog.destroy).pack(side=tk.LEFT, padx=5)

        return dialog

    def start_import(self, dialog, on_complete):
        """开始导入流程"""
        url = self.url_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        path = self.path_entry.get().strip()

        if not url:
            messagebox.showerror('错误', '请输入服务器地址', parent=dialog)
            return

        progress_window = self.create_progress_window(dialog, "WebDAV导入进度")

        import_thread = threading.Thread(
            target=self._import_task,
            args=(url, username, password, path, progress_window, on_complete),
            daemon=True
        )
        import_thread.start()

        self.monitor_import_thread(import_thread, progress_window)

    def create_progress_window(self, parent, title):
        """创建进度显示窗口"""
        window = tk.Toplevel(parent)
        window.title(title)
        window.geometry('700x500')
        window.transient(parent)
        window.grab_set()

        self.cancel_event.clear()

        ttk.Label(window, text=title, font=('Arial', 12)).pack(pady=5)

        self.status_var = tk.StringVar(value='正在初始化...')
        status_label = ttk.Label(window, textvariable=self.status_var, font=('Arial', 10))
        status_label.pack(pady=5)

        self.progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(window, variable=self.progress_var, maximum=100)
        progress_bar.pack(fill=tk.X, padx=20, pady=5)

        error_frame = ttk.LabelFrame(window, text='详细日志')
        error_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = tk.Text(error_frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(error_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.cancel_button = ttk.Button(window, text='取消', command=lambda: self.cancel_import(window))
        self.cancel_button.pack(pady=10)

        window.protocol('WM_DELETE_WINDOW', lambda: self.cancel_import(window))
        return window

    def cancel_import(self, window):
        """取消导入操作"""
        self.cancel_event.set()
        with self.import_lock:
            for temp_file in self.active_downloads[:]:
                try:
                    if os.path.exists(temp_file): os.remove(temp_file)
                    self.active_downloads.remove(temp_file)
                except:
                    pass
        self.log("用户主动取消了导入操作", 'info')
        window.destroy()

    def log(self, message, level='info'):
        """记录日志"""
        timestamp = datetime.now().strftime('%H:%M:%S')

        if hasattr(self, 'log_text'):
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
        if level == 'error':
            logger.error(f"{message}")
        elif level == 'warning':
            logger.warning(f"{message}")
        else:
            logger.info(f"{message}")

    def update_status(self, text):
        """更新状态文本"""
        if hasattr(self, 'status_var'):
            self.status_var.set(text)

    def update_progress(self, value):
        """更新进度条"""
        if hasattr(self, 'progress_var'):
            self.progress_var.set(value)

    def monitor_import_thread(self, thread, window):
        """监控导入线程状态"""
        if thread.is_alive():
            window.after(100, lambda: self.monitor_import_thread(thread, window))
        elif window.winfo_exists():
            window.protocol('WM_DELETE_WINDOW', window.destroy)
            self.cancel_button.config(text='关闭', command=window.destroy)

    def _import_task(self, url, username, password, path, progress_window, on_complete):
        """执行实际的导入任务"""
        client = None
        temp_files = []

        try:
            if self.cancel_event.is_set(): return

            self.update_status('正在验证服务器连接...')
            self.log(f"正在测试连接: {url}")

            options = {
                'webdav_hostname': url,
                'webdav_timeout': 5,
                'webdav_verbose': False
            }
            if username: options['webdav_login'] = username
            if password: options['webdav_password'] = password

            client = Client(options)

            if self.cancel_event.is_set(): return

            self.update_status('正在获取文件列表...')
            self.log(f"正在列出路径: {path}")

            try:
                files = client.list(path)
                self.log(f"找到 {len(files)} 个文件/目录")
            except Exception as e:
                if not self.cancel_event.is_set():
                    error_msg = f"获取文件列表失败: {str(e)}"
                    self.log(error_msg, 'error')
                    self.update_status('导入失败')
                    messagebox.showerror('错误', error_msg, parent=progress_window)
                return

            if on_complete and hasattr(on_complete, 'filter_files'):
                target_files = on_complete.filter_files(files)
            else:
                target_files = files

            if not target_files:
                error_msg = f"在 {path} 中没有找到目标文件"
                self.log(error_msg, 'error')
                self.update_status('导入失败')
                messagebox.showerror('错误', error_msg, parent=progress_window)
                return

            total_files = len(target_files)
            success_count = 0
            failed_count = 0

            for i, filename in enumerate(target_files):
                if self.cancel_event.is_set():
                    self.log('导入被用户取消')
                    self.update_status('已取消')
                    return

                self.update_status(f"正在处理 {i + 1}/{total_files}: {filename}")
                self.update_progress(i / total_files * 100)
                self.log(f"正在处理文件: {filename}")

                temp_file = None
                try:
                    temp_file = os.path.join(tempfile.gettempdir(), f"dav_import_{uuid.uuid4().hex}")
                    with self.import_lock:
                        if self.cancel_event.is_set(): raise Exception('导入被用户取消')
                        self.active_downloads.append(temp_file)

                    self._download_file(client, f"{path}{filename}", temp_file)

                    if on_complete:
                        result = on_complete.process_file(temp_file, filename)
                        if result:
                            success_count += 1
                            temp_files.append(temp_file)  # 跟踪成功处理的文件
                            self.log(f"成功处理文件: {filename}")
                        else:
                            failed_count += 1

                except Exception as e:
                    failed_count += 1
                    if not self.cancel_event.is_set():
                        error_msg = f"处理文件 {filename} 失败: {str(e)}"
                        self.log(error_msg, 'error')
                    # 如果处理失败，删除临时文件
                    if temp_file and os.path.exists(temp_file):
                        try:
                            os.remove(temp_file)
                        except:
                            pass

            if not self.cancel_event.is_set():
                self.update_progress(100)
                result_msg = f"导入完成! 成功: {success_count}, 失败: {failed_count}"
                self.log(result_msg)
                self.update_status(result_msg)

                if on_complete and hasattr(on_complete, 'on_import_complete'):
                    on_complete.on_import_complete(temp_files)

        except Exception as e:
            if not self.cancel_event.is_set():
                error_msg = f"导入过程中发生错误: {str(e)}"
                self.log(error_msg, 'error')
                self.update_status('导入失败')
                messagebox.showerror('错误', error_msg, parent=progress_window)
        finally:
            if client:
                try:
                    client.session.close()
                except:
                    pass

    def _download_file(self, client, remote_path, local_path):
        """下载单个文件"""

        def progress_callback(current, total):
            if self.cancel_event.is_set(): raise Exception('下载被用户取消')
            return True

        client.download_sync(remote_path=remote_path, local_path=local_path, callback=progress_callback)

# ======================
# GUI 应用
# ======================
class DAVServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title(software_name + " v" + software_version + " - " + software_description)
        self.root.geometry("1000x700")

        # 创建数据库实例
        self.db = Database('dav_data.db')
        self.server = None
        self.server_thread = None
        self.import_queue = queue.Queue()
        self.import_in_progress = False
        self.import_cancel_requested = False

        # 创建日志队列
        self.log_queue = queue.Queue()

        # 添加GUI日志处理器 - 只添加一次
        gui_handler = GUIHandler(self)
        gui_handler.setLevel(logging.INFO)
        logger.addHandler(gui_handler)  # 添加到全局logger

        # 开始处理日志队列
        self.root.after(100, self.process_log_queue)

        # 创建标签页
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 绑定标签页切换事件
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # 服务器管理标签页
        self.server_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.server_tab, text="服务器管理")

        # 联系人管理标签页
        self.contacts_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.contacts_tab, text="联系人")

        # 日历管理标签页
        self.calendar_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.calendar_tab, text="日历事件")

        # 初始化各标签页
        self.setup_server_tab()
        self.setup_contacts_tab()
        self.setup_calendar_tab()

        # 添加状态栏
        self.status_bar = ttk.Label(root, text="就绪", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # 显示数据统计
        self.update_status_bar()

        # 注册 WebDAV 客户端
        self.webdav_client = WebDAVClient()

        # 开始处理导入队列
        self.root.after(100, self.process_import_queue)

        # 绑定快捷键
        self.root.bind("<Control-a>", self.select_all)
        self.root.bind("<Delete>", self.on_delete_key)

        # 注册文件拖拽事件
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.handle_drop)

    def process_log_queue(self):
        """处理日志队列"""
        try:
            while not self.log_queue.empty():
                log_message = self.log_queue.get_nowait()
                self.append_to_log_window(log_message)
        except queue.Empty:
            pass

        # 继续检查队列
        self.root.after(100, self.process_log_queue)

    def append_to_log_window(self, message):
        """将消息添加到日志窗口"""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def log_message(self, message):
        """记录日志消息"""
        # 只通过 logger 记录消息，由 GUIHandler 负责格式化并放入队列
        logger.info(message)

    def on_delete_key(self, event):
        """处理Delete键事件"""
        current_tab = self.notebook.select()
        tab_text = self.notebook.tab(current_tab, "text")

        if tab_text == "联系人":
            self.delete_contact()
        elif tab_text == "日历事件":
            self.delete_event()

    def handle_drop(self, event):
        """处理文件拖拽事件"""
        files = []

        # 尝试解析为文件列表
        if isinstance(event.data, (list, tuple)):
            files = [f for f in event.data if os.path.exists(f)]
        else:
            # 处理字符串格式的路径
            raw_paths = event.data

            # 尝试解析大括号格式的路径
            if raw_paths.startswith('{') and raw_paths.endswith('}'):
                raw_paths = raw_paths[1:-1]
                possible_paths = raw_paths.split('} {')
                for path in possible_paths:
                    if os.path.exists(path):
                        files.append(path)
            else:
                # 尝试直接作为单个路径
                if os.path.exists(raw_paths):
                    files.append(raw_paths)
                else:
                    # 尝试分割空格分隔的路径
                    possible_paths = raw_paths.split()
                    for path in possible_paths:
                        if os.path.exists(path):
                            files.append(path)

        if not files:
            self.log_message(f"未找到有效文件路径: {event.data}")
            return

        self.log_message(f"拖拽导入文件: {', '.join(files)}")

        current_tab = self.notebook.select()
        tab_text = self.notebook.tab(current_tab, "text")

        if tab_text == "联系人":
            self._start_import_contacts(files, "文件")
        elif tab_text == "日历事件":
            self._start_import_events(files, "文件")
        else:
            messagebox.showinfo("提示", "请切换到联系人或日历标签页进行导入")

    def on_tab_changed(self, event):
        """标签页切换时自动刷新列表"""
        current_tab = self.notebook.select()
        tab_text = self.notebook.tab(current_tab, "text")

        if tab_text == "联系人":
            self.refresh_contacts()
        elif tab_text == "日历事件":
            self.refresh_events()

    def setup_server_tab(self):
        frame = ttk.LabelFrame(self.server_tab, text="服务器控制")
        frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(frame, text="端口号:").grid(row=0, column=0, padx=5, pady=5)
        self.port_entry = ttk.Entry(frame, width=10)
        self.port_entry.insert(0, "8000")
        self.port_entry.grid(row=0, column=1, padx=5, pady=5)

        self.start_btn = ttk.Button(frame, text="启动服务器", command=self.start_server)
        self.start_btn.grid(row=0, column=2, padx=5, pady=5)

        self.stop_btn = ttk.Button(frame, text="停止服务器", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=3, padx=5, pady=5)

        # 服务器日志
        log_frame = ttk.LabelFrame(self.server_tab, text="服务器日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, height=10)
        self.log_scroll = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=self.log_scroll.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, "服务器未启动\n")
        self.log_text.config(state=tk.DISABLED)

        # 服务器信息
        info_frame = ttk.LabelFrame(self.server_tab, text="客户端配置信息")
        info_frame.pack(fill=tk.X, padx=10, pady=10)

        info_text = """CardDAV 配置:
  服务器地址: http://localhost:8000/contacts/
  用户名: (任意)
  密码: (任意)

CalDAV 配置:
  服务器地址: http://localhost:8000/events/
  用户名: (任意)
  密码: (任意)

在浏览器中测试:
  http://localhost:8000/ - 查看服务信息
  http://localhost:8000/contacts/ - 所有联系人
  http://localhost:8000/events/ - 所有日历事件"""
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT).pack(padx=5, pady=5)

    def setup_contacts_tab(self):
        # 联系人列表
        list_frame = ttk.LabelFrame(self.contacts_tab, text="联系人列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 添加操作提示
        hint_frame = ttk.Frame(list_frame)
        hint_frame.pack(fill=tk.X, padx=5, pady=5)

        hint_label = ttk.Label(
            hint_frame,
            text="操作提示: \n1) 点击复选框选择/取消选择单个事件 2) 点击表头复选框全选/取消全选 3) 按住鼠标拖动选择多行 4) 在其他列单击只选择当前行 5) 如果选择多列并编辑则只会编辑第一项",
            foreground="blue"
        )
        hint_label.pack(side=tk.LEFT)

        # 添加列 - 第一列为复选框
        columns = ("selected", "uid", "name", "email", "phone")
        self.contacts_tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")

        # 配置列标题
        self.contacts_tree.heading("selected", text="✓")
        self.contacts_tree.heading("uid", text="ID")
        self.contacts_tree.heading("name", text="姓名")
        self.contacts_tree.heading("email", text="邮箱")
        self.contacts_tree.heading("phone", text="电话")

        # 配置列宽
        self.contacts_tree.column("selected", width=30, anchor=tk.CENTER)
        self.contacts_tree.column("uid", width=100, anchor=tk.CENTER)
        self.contacts_tree.column("name", width=150)
        self.contacts_tree.column("email", width=200)
        self.contacts_tree.column("phone", width=150)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.contacts_tree.yview)
        self.contacts_tree.configure(yscroll=scrollbar.set)

        self.contacts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 添加全选复选框到表头
        self.contacts_tree.heading("selected", command=self.toggle_all_contacts_selection)

        # 添加事件绑定
        self.contacts_tree.bind('<ButtonPress-1>', self.on_contact_tree_click)
        self.contacts_tree.bind('<B1-Motion>', self.on_contact_tree_drag)
        self.contacts_tree.bind('<ButtonRelease-1>', self.on_contact_tree_release)
        self.contacts_tree.bind('<Double-1>', self.on_contact_double_click)
        self.contacts_tree.bind("<Control-a>", lambda e: self.select_all(e, self.contacts_tree))

        # 添加自动滚动绑定
        self.contacts_tree.bind("<Motion>", self.on_contact_tree_motion)

        # 初始化拖拽状态变量
        self.contact_drag_start = None
        self.contact_drag_item = None
        self.contact_dragging = False
        self.auto_scroll_active = False

        # 操作按钮
        btn_frame = ttk.Frame(self.contacts_tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="添加联系人", command=self.add_contact).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="编辑联系人", command=self.edit_contact).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="删除联系人", command=self.delete_contact).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="查看原始数据", command=self.show_contact_raw).pack(side=tk.LEFT, padx=5)

        # 导入导出按钮
        import_export_frame = ttk.Frame(btn_frame)
        import_export_frame.pack(side=tk.RIGHT)

        ttk.Button(import_export_frame, text="导入联系人", command=self.import_contacts).pack(side=tk.LEFT, padx=5)
        ttk.Button(import_export_frame, text="导出选中", command=self.export_selected_contacts).pack(side=tk.LEFT,
                                                                                                     padx=5)

        ttk.Button(btn_frame, text="刷新列表", command=self.refresh_contacts).pack(side=tk.LEFT, padx=5)

    def setup_calendar_tab(self):
        # 事件列表
        list_frame = ttk.LabelFrame(self.calendar_tab, text="日历事件")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 添加操作提示
        hint_frame = ttk.Frame(list_frame)
        hint_frame.pack(fill=tk.X, padx=5, pady=5)

        hint_label = ttk.Label(
            hint_frame,
            text="操作提示: \n1) 点击复选框选择/取消选择单个事件 2) 点击表头复选框全选/取消全选 3) 按住鼠标拖动选择多行 4) 在其他列单击只选择当前行 5) 如果选择多列并编辑则只会编辑第一项",
            foreground="blue"
        )
        hint_label.pack(side=tk.LEFT)

        # 添加列 - 第一列为复选框
        columns = ("selected", "uid", "summary", "start", "end")
        self.events_tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")

        # 配置列标题
        self.events_tree.heading("selected", text="✓")
        self.events_tree.heading("uid", text="ID")
        self.events_tree.heading("summary", text="事件")
        self.events_tree.heading("start", text="开始时间")
        self.events_tree.heading("end", text="结束时间")

        # 配置列宽
        self.events_tree.column("selected", width=10, anchor=tk.CENTER)
        self.events_tree.column("uid", width=100, anchor=tk.CENTER)
        self.events_tree.column("summary", width=200)
        self.events_tree.column("start", width=150)
        self.events_tree.column("end", width=150)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscroll=scrollbar.set)

        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 添加全选复选框到表头
        self.events_tree.heading("selected", command=self.toggle_all_events_selection)

        # 添加事件绑定
        self.events_tree.bind('<ButtonPress-1>', self.on_event_tree_click)
        self.events_tree.bind('<B1-Motion>', self.on_event_tree_drag)
        self.events_tree.bind('<ButtonRelease-1>', self.on_event_tree_release)
        self.events_tree.bind('<Double-1>', self.on_event_double_click)
        self.events_tree.bind("<Control-a>", lambda e: self.select_all(e, self.events_tree))

        # 添加自动滚动绑定
        self.events_tree.bind("<Motion>", self.on_event_tree_motion)

        # 初始化拖拽状态变量
        self.event_drag_start = None
        self.event_drag_item = None
        self.event_dragging = False
        self.auto_scroll_active = False

        # 操作按钮
        btn_frame = ttk.Frame(self.calendar_tab)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="添加事件", command=self.add_event).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="编辑事件", command=self.edit_event).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="删除事件", command=self.delete_event).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="查看原始数据", command=self.show_event_raw).pack(side=tk.LEFT, padx=5)

        # 导入导出按钮
        import_export_frame = ttk.Frame(btn_frame)
        import_export_frame.pack(side=tk.RIGHT)

        ttk.Button(import_export_frame, text="导入事件", command=self.import_events).pack(side=tk.LEFT, padx=5)
        ttk.Button(import_export_frame, text="导出选中", command=self.export_selected_events).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="刷新列表", command=self.refresh_events).pack(side=tk.LEFT, padx=5)

    def toggle_all_contacts_selection(self):
        """切换所有联系人的选择状态"""
        all_items = self.contacts_tree.get_children()
        if not all_items: return

        # 检查当前是否全部已选
        all_selected = all(item in self.contacts_tree.selection() for item in all_items)

        new_selection = [] if all_selected else all_items

        # 更新Treeview选择
        self.contacts_tree.selection_set(new_selection)

        # 更新复选框状态
        for item in all_items:
            values = list(self.contacts_tree.item(item, 'values'))
            values[0] = "✓" if not all_selected else " "
            self.contacts_tree.item(item, values=values)

    def toggle_all_events_selection(self):
        """切换所有事件的选择状态"""
        all_items = self.events_tree.get_children()
        if not all_items: return

        # 检查当前是否全部已选
        all_selected = all(item in self.events_tree.selection() for item in all_items)

        new_selection = [] if all_selected else all_items

        # 更新Treeview选择
        self.events_tree.selection_set(new_selection)

        # 更新复选框状态
        for item in all_items:
            values = list(self.events_tree.item(item, 'values'))
            values[0] = "✓" if not all_selected else " "
            self.events_tree.item(item, values=values)

    def on_contact_tree_click(self, event):
        """处理联系人列表点击事件"""
        region = self.contacts_tree.identify("region", event.x, event.y)
        item = self.contacts_tree.identify_row(event.y)
        column = self.contacts_tree.identify_column(event.x)

        # 记录拖拽起始位置
        self.contact_drag_start = (event.x, event.y)
        self.contact_drag_item = item  # 保存起始行
        self.contact_dragging = False

        if region == "heading" and column == "#1":
            # 点击了表头复选框
            self.toggle_all_contacts_selection()
            return "break"

        # 处理Shift键区间选择
        if event.state & 0x0001:  # Shift键按下
            if not item: return "break"

            if not hasattr(self, 'contact_last_selected'): self.contact_last_selected = item

            # 获取所有行
            all_items = list(self.contacts_tree.get_children())

            # 获取起始和结束索引
            start_idx = all_items.index(self.contact_last_selected)
            end_idx = all_items.index(item)

            start = min(start_idx, end_idx)
            end = max(start_idx, end_idx)

            # 获取范围内的所有行
            selected_items = all_items[start:end + 1]

            # 更新选择
            self.contacts_tree.selection_set(selected_items)

            # 更新复选框状态
            for itm in all_items:
                values = list(self.contacts_tree.item(itm, 'values'))
                if itm in selected_items:
                    values[0] = "✓"
                else:
                    if itm not in self.contacts_tree.selection(): values[0] = " "
                self.contacts_tree.item(itm, values=values)

            return "break"

        # 处理Ctrl键多选/反选
        if event.state & 0x0004:  # Ctrl键按下
            if not item: return "break"

            # 记录最后选择的项
            self.contact_last_selected = item

            # 获取当前选择状态
            current_selection = self.contacts_tree.selection()

            if item in current_selection:
                # 如果已选中，则取消选中
                self.contacts_tree.selection_remove(item)
                values = list(self.contacts_tree.item(item, 'values'))
                values[0] = " "
                self.contacts_tree.item(item, values=values)
            else:
                # 如果未选中，则选中
                self.contacts_tree.selection_add(item)
                values = list(self.contacts_tree.item(item, 'values'))
                values[0] = "✓"
                self.contacts_tree.item(item, values=values)

            return "break"

        if region == "cell" and column == "#1" and item:
            # 点击了复选框列
            values = list(self.contacts_tree.item(item, 'values'))
            current_selection = self.contacts_tree.selection()

            if item in current_selection:
                # 如果已选中，则取消选中
                self.contacts_tree.selection_remove(item)
                values[0] = " "
            else:
                # 如果未选中，则选中
                self.contacts_tree.selection_add(item)
                values[0] = "✓"

            self.contacts_tree.item(item, values=values)
            # 记录最后选择的项
            self.contact_last_selected = item
            return "break"

        if region == "cell" and column != "#1" and item:
            # 点击非复选框列 - 只选择当前行
            # 清除所有选择
            self.contacts_tree.selection_set([])

            # 选中当前行
            self.contacts_tree.selection_add(item)

            # 更新所有行的复选框状态
            all_items = self.contacts_tree.get_children()
            for itm in all_items:
                vals = list(self.contacts_tree.item(itm, 'values'))
                if itm == item:
                    vals[0] = "✓"
                else:
                    vals[0] = " "
                self.contacts_tree.item(itm, values=vals)

            # 记录最后选择的项
            self.contact_last_selected = item
            return "break"

    def on_contact_tree_drag(self, event):
        """处理联系人列表拖拽事件"""
        if not self.contact_drag_start or not self.contact_drag_item: return

        # 设置拖拽状态
        self.contact_dragging = True

        # 获取当前拖拽位置对应的行
        item = self.contacts_tree.identify_row(event.y)
        if not item:
            # 添加自动滚动逻辑
            height = self.contacts_tree.winfo_height()
            if height == 0: return

            # 计算鼠标在Treeview中的相对位置
            rel_y = event.y / height

            # 如果鼠标在顶部10%区域，向上滚动
            if rel_y < 0.1:
                self.contacts_tree.yview_scroll(-1, "units")
            # 如果鼠标在底部10%区域，向下滚动
            elif rel_y > 0.9:
                self.contacts_tree.yview_scroll(1, "units")
            return

        # 获取起始行和当前行的索引
        start_index = self.contacts_tree.index(self.contact_drag_item)
        current_index = self.contacts_tree.index(item)

        # 获取所有行
        all_items = list(self.contacts_tree.get_children())

        # 确定选择范围
        start = min(start_index, current_index)
        end = max(start_index, current_index)

        # 获取范围内的所有行
        selected_items = all_items[start:end + 1]

        # 更新选择
        self.contacts_tree.selection_set(selected_items)

        # 更新复选框状态
        for item in all_items:
            values = list(self.contacts_tree.item(item, 'values'))
            if item in selected_items:
                values[0] = "✓"
            else:
                values[0] = " "
            self.contacts_tree.item(item, values=values)

        # 添加自动滚动逻辑
        height = self.contacts_tree.winfo_height()
        if height == 0: return

        # 计算鼠标在Treeview中的相对位置
        rel_y = event.y / height

        # 如果鼠标在顶部10%区域，向上滚动
        if rel_y < 0.1:
            self.contacts_tree.yview_scroll(-1, "units")
        # 如果鼠标在底部10%区域，向下滚动
        elif rel_y > 0.9:
            self.contacts_tree.yview_scroll(1, "units")

    def on_contact_tree_release(self, event):
        """处理联系人列表鼠标释放事件"""
        self.contact_drag_start = None
        self.contact_drag_item = None
        self.contact_dragging = False
        return "break"

    def on_contact_tree_motion(self, event):
        """处理联系人列表鼠标移动事件 - 实现自动滚动"""
        if not self.contact_dragging: return

        # 获取Treeview的高度
        height = self.contacts_tree.winfo_height()
        if height == 0: return

        # 计算鼠标在Treeview中的相对位置
        rel_y = event.y / height

        # 如果鼠标在顶部10%区域，向上滚动
        if rel_y < 0.1:
            self.contacts_tree.yview_scroll(-1, "units")
        # 如果鼠标在底部10%区域，向下滚动
        elif rel_y > 0.9:
            self.contacts_tree.yview_scroll(1, "units")

    def on_event_tree_click(self, event):
        """处理事件列表点击事件"""
        region = self.events_tree.identify("region", event.x, event.y)
        item = self.events_tree.identify_row(event.y)
        column = self.events_tree.identify_column(event.x)

        # 记录拖拽起始位置
        self.event_drag_start = (event.x, event.y)
        self.event_drag_item = item  # 保存起始行
        self.event_dragging = False

        if region == "heading" and column == "#1":
            # 点击了表头复选框
            self.toggle_all_events_selection()
            return "break"

        # 处理Shift键区间选择
        if event.state & 0x0001:  # Shift键按下
            if not item: return "break"

            if not hasattr(self, 'event_last_selected'): self.event_last_selected = item

            # 获取所有行
            all_items = list(self.events_tree.get_children())

            # 获取起始和结束索引
            start_idx = all_items.index(self.event_last_selected)
            end_idx = all_items.index(item)

            start = min(start_idx, end_idx)
            end = max(start_idx, end_idx)

            # 获取范围内的所有行
            selected_items = all_items[start:end + 1]

            # 更新选择
            self.events_tree.selection_set(selected_items)

            # 更新复选框状态
            for itm in all_items:
                values = list(self.events_tree.item(itm, 'values'))
                if itm in selected_items:
                    values[0] = "✓"
                else:
                    if itm not in self.events_tree.selection(): values[0] = " "
                self.events_tree.item(itm, values=values)

            return "break"

        # 处理Ctrl键多选/反选
        if event.state & 0x0004:  # Ctrl键按下
            if not item: return "break"

            # 记录最后选择的项
            self.event_last_selected = item

            # 获取当前选择状态
            current_selection = self.events_tree.selection()

            if item in current_selection:
                # 如果已选中，则取消选中
                self.events_tree.selection_remove(item)
                values = list(self.events_tree.item(item, 'values'))
                values[0] = " "
                self.events_tree.item(item, values=values)
            else:
                # 如果未选中，则选中
                self.events_tree.selection_add(item)
                values = list(self.events_tree.item(item, 'values'))
                values[0] = "✓"
                self.events_tree.item(item, values=values)

            return "break"

        if region == "cell" and column == "#1" and item:
            # 点击了复选框列
            values = list(self.events_tree.item(item, 'values'))
            current_selection = self.events_tree.selection()

            if item in current_selection:
                # 如果已选中，则取消选中
                self.events_tree.selection_remove(item)
                values[0] = " "
            else:
                # 如果未选中，则选中
                self.events_tree.selection_add(item)
                values[0] = "✓"

            self.events_tree.item(item, values=values)
            # 记录最后选择的项
            self.event_last_selected = item
            return "break"

        if region == "cell" and column != "#1" and item:
            # 点击非复选框列 - 只选择当前行
            # 清除所有选择
            self.events_tree.selection_set([])

            # 选中当前行
            self.events_tree.selection_add(item)

            # 更新所有行的复选框状态
            all_items = self.events_tree.get_children()
            for itm in all_items:
                vals = list(self.events_tree.item(itm, 'values'))
                if itm == item:
                    vals[0] = "✓"
                else:
                    vals[0] = " "
                self.events_tree.item(itm, values=vals)

            # 记录最后选择的项
            self.event_last_selected = item
            return "break"

    def on_event_tree_drag(self, event):
        """处理事件列表拖拽事件"""
        if not self.event_drag_start or not self.event_drag_item: return

        # 设置拖拽状态
        self.event_dragging = True

        # 获取当前拖拽位置对应的行
        item = self.events_tree.identify_row(event.y)
        if not item:
            # 添加自动滚动逻辑
            height = self.events_tree.winfo_height()
            if height == 0: return

            # 计算鼠标在Treeview中的相对位置
            rel_y = event.y / height

            # 如果鼠标在顶部10%区域，向上滚动
            if rel_y < 0.1:
                self.events_tree.yview_scroll(-1, "units")
            # 如果鼠标在底部10%区域，向下滚动
            elif rel_y > 0.9:
                self.events_tree.yview_scroll(1, "units")
            return

        # 获取起始行和当前行的索引
        start_index = self.events_tree.index(self.event_drag_item)
        current_index = self.events_tree.index(item)

        # 获取所有行
        all_items = list(self.events_tree.get_children())

        # 确定选择范围
        start = min(start_index, current_index)
        end = max(start_index, current_index)

        selected_items = all_items[start:end + 1]

        # 更新选择
        self.events_tree.selection_set(selected_items)

        # 更新复选框状态
        for item in all_items:
            values = list(self.events_tree.item(item, 'values'))
            if item in selected_items:
                values[0] = "✓"
            else:
                values[0] = " "
            self.events_tree.item(item, values=values)

        # 添加自动滚动逻辑
        height = self.events_tree.winfo_height()
        if height == 0: return

        # 计算鼠标在Treeview中的相对位置
        rel_y = event.y / height

        # 如果鼠标在顶部10%区域，向上滚动
        if rel_y < 0.1:
            self.events_tree.yview_scroll(-1, "units")
        # 如果鼠标在底部10%区域，向下滚动
        elif rel_y > 0.9:
            self.events_tree.yview_scroll(1, "units")

    def on_event_tree_release(self, event):
        """处理事件列表鼠标释放事件"""
        self.event_drag_start = None
        self.event_drag_item = None
        self.event_dragging = False
        return "break"

    def on_event_tree_motion(self, event):
        """处理事件列表鼠标移动事件 - 实现自动滚动"""
        if not self.event_dragging: return

        # 获取Treeview的高度
        height = self.events_tree.winfo_height()
        if height == 0: return

        # 计算鼠标在Treeview中的相对位置
        rel_y = event.y / height

        # 如果鼠标在顶部10%区域，向上滚动
        if rel_y < 0.1:
            self.events_tree.yview_scroll(-1, "units")
        # 如果鼠标在底部10%区域，向下滚动
        elif rel_y > 0.9:
            self.events_tree.yview_scroll(1, "units")

    def refresh_contacts(self):
        # 清除现有项
        for item in self.contacts_tree.get_children(): self.contacts_tree.delete(item)

        # 获取联系人数据
        contacts = self.db.get_contacts()

        # 获取当前选中的UID
        selected_uids = set()
        for item_id in self.contacts_tree.selection():
            item = self.contacts_tree.item(item_id)
            values = item['values']
            if len(values) > 1: selected_uids.add(values[1])

        # 添加联系人到列表
        for contact in contacts:
            # 确保所有值都是字符串
            contact = [str(item) if item is not None else "" for item in contact]
            uid = contact[1]

            # 确定是否选中
            selected = "✓" if uid in selected_uids else " "

            # 插入新行（复选框、UID、姓名、邮箱、电话）
            item_id = self.contacts_tree.insert("", tk.END, values=[selected] + contact)

            # 如果之前是选中的，添加到当前选择
            if selected == "✓": self.contacts_tree.selection_add(item_id)

        self.update_status_bar()

    def refresh_events(self):
        # 清除现有项
        for item in self.events_tree.get_children(): self.events_tree.delete(item)

        # 获取事件数据
        events = self.db.get_events()

        # 获取当前选中的UID
        selected_uids = set()
        for item_id in self.events_tree.selection():
            item = self.events_tree.item(item_id)
            values = item['values']
            if len(values) > 1: selected_uids.add(values[1])

        # 添加事件到列表
        for event in events:
            # 确保所有值都是字符串
            event = [str(item) if item is not None else "" for item in event]
            uid = event[1]

            # 确定是否选中
            selected = "✓" if uid in selected_uids else " "

            # 插入新行（复选框、UID、摘要、开始时间、结束时间）
            item_id = self.events_tree.insert("", tk.END, values=[selected] + event)

            # 如果之前是选中的，添加到当前选择
            if selected == "✓":
                self.events_tree.selection_add(item_id)

        self.update_status_bar()

    def select_all(self, event, tree=None):
        if tree is None:
            current_tab = self.notebook.select()
            tab_text = self.notebook.tab(current_tab, "text")
            if tab_text == "联系人":
                tree = self.contacts_tree
            elif tab_text == "日历事件":
                tree = self.events_tree
            else:
                return

        # 获取所有项目
        items = tree.get_children()

        # 设置选中状态
        tree.selection_set(items)

        # 更新第一列的勾选框状态
        for item in items:
            values = list(tree.item(item, 'values'))
            values[0] = "✓"
            tree.item(item, values=values)

        return "break"

    def on_contact_double_click(self, event):
        """双击联系人列表项时触发编辑"""
        self.edit_contact()

    def on_event_double_click(self, event):
        """双击事件列表项时触发编辑"""
        self.edit_event()

    def update_status_bar(self):
        contact_count = self.db.count_contacts()
        event_count = self.db.count_events()
        status = f"联系人: {contact_count} | 日历事件: {event_count} | 就绪"
        self.status_bar.config(text=status)

    def add_contact(self):
        dialog = ContactDialog(self.root)
        if dialog.result:
            try:
                # 直接使用对话框返回的vCard字符串
                vcard_str = dialog.result['vcard']
                uid, operation = self.db.add_contact(vcard_str)
                if uid:
                    self.refresh_contacts()
                    self.log_message(f"添加联系人 ({operation}): {dialog.result['name']} ({uid})")
                else:
                    messagebox.showerror("错误", f"添加联系人失败: {operation}")
            except Exception as e:
                messagebox.showerror("错误", f"添加联系人失败: {str(e)}")

    def edit_contact(self):
        selected = self.contacts_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个联系人")
            return

        # 只编辑第一个选中的联系人（双击或单个选择）
        item = self.contacts_tree.item(selected[0])
        values = [str(v) if v is not None else "" for v in item['values']]
        _, uid, name, email, phone = values

        # 获取完整的 vCard 数据
        vcard_data = self.db.get_contact(uid)
        if not vcard_data:
            messagebox.showerror("错误", "无法获取联系人详情")
            return

        # 解析 vCard
        try:
            vcard = vobject.readOne(vcard_data)
        except Exception as e:
            logger.warning(f"使用 vobject 解析失败: {str(e)}")
            vcard = None

        # 准备初始数据
        initial_data = {
            'uid': uid,
            'name': name,
            'email': email.split(';')[0] if email else '',
            'phone': phone.split(';')[0] if phone else ''
        }

        # 创建对话框
        dialog = ContactDialog(self.root, initial=initial_data, vcard=vcard)

        if dialog.result:
            try:
                # 构建 vCard
                vcard_str = f"""BEGIN:VCARD
        VERSION:3.0
        FN:{dialog.result['name']}
        EMAIL:{dialog.result['email']}
        TEL:{dialog.result['phone']}
        UID:{dialog.result['uid']}
        END:VCARD"""

                # 保存到数据库
                uid, operation = self.db.add_contact(vcard_str)
                if uid:
                    self.refresh_contacts()
                    self.log_message(f"更新联系人 ({operation}): {dialog.result['name']} ({uid})")
                else:
                    messagebox.showerror("错误", f"更新联系人失败: {operation}")
            except Exception as e:
                messagebox.showerror("错误", f"更新联系人失败: {str(e)}")

    def delete_contact(self):
        selected = self.contacts_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的联系人")
            return

        contacts_to_delete = []
        for item_id in selected:
            item = self.contacts_tree.item(item_id)
            values = [str(v) if v is not None else "" for v in item['values']]
            uid, name, email, phone = values
            contacts_to_delete.append((uid, name))

        names = ", ".join([name for _, name in contacts_to_delete])
        if messagebox.askyesno("确认删除", f"确定要删除以下联系人吗?\n{names}"):
            success_count = 0
            fail_count = 0

            for uid, name in contacts_to_delete:
                try:
                    if self.db.delete_contact(uid):
                        success_count += 1
                    else:
                        fail_count += 1
                except Exception as e:
                    fail_count += 1

            self.refresh_contacts()
            if fail_count > 0:
                messagebox.showinfo("删除完成", f"成功删除 {success_count} 个联系人\n失败 {fail_count} 个")
            else:
                messagebox.showinfo("删除完成", f"成功删除 {success_count} 个联系人")

            self.log_message(f"删除联系人: {success_count} 个成功, {fail_count} 个失败")

    def show_contact_raw(self):
        selected = self.contacts_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个联系人")
            return

        item = self.contacts_tree.item(selected[0])
        uid = item['values'][1]
        vcard_data = self.db.get_contact(uid)

        self.show_raw_data(vcard_data, "联系人原始数据")

    def export_selected_contacts(self):
        """导出选中的联系人"""
        selected = self.contacts_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要导出的联系人")
            return

        uids = []
        for item_id in selected:
            item = self.contacts_tree.item(item_id)
            uid = item['values'][1]
            uids.append(uid)

        # 获取选中的联系人数据
        contacts = self.db.get_selected_contacts(uids)
        if not contacts:
            messagebox.showerror("错误", "没有找到选中的联系人数据")
            return

        file_path = filedialog.asksaveasfilename(
            title="保存联系人文件",
            filetypes=[("vCard 文件", "*.vcf"), ("所有文件", "*.*")],
            defaultextension=".vcf"
        )
        if not file_path: return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                for i, vcard in enumerate(contacts):
                    if i > 0:
                        f.write("\n")  # 只在vCard之间添加空行
                    f.write(vcard.strip())  # 移除原有换行符
            messagebox.showinfo("导出成功", f"已成功导出 {len(contacts)} 个联系人")
            self.log_message(f"导出联系人: {len(contacts)} 个到 {file_path}")
        except Exception as e:
            messagebox.showerror("导出失败", f"导出联系人时出错: {str(e)}")
            logger.error(f"导出联系人失败: {str(e)}")

    def export_selected_events(self):
        """导出选中的日历事件"""
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要导出的事件")
            return

        uids = []
        for item_id in selected:
            item = self.events_tree.item(item_id)
            uid = item['values'][1]
            uids.append(uid)

        # 获取选中的事件数据
        events = self.db.get_selected_events(uids)
        if not events:
            messagebox.showerror("错误", "没有找到选中的事件数据")
            return

        file_path = filedialog.asksaveasfilename(
            title="保存日历文件",
            filetypes=[("iCalendar 文件", "*.ics"), ("所有文件", "*.*")],
            defaultextension=".ics"
        )
        if not file_path: return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(
                    "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//" + software_name + "//" + software_version + "//ZH-CN\n")
                for event in events:
                    # 去除每个事件的外部VCALENDAR标签
                    event_lines = event.splitlines()
                    if event_lines[0].startswith("BEGIN:VCALENDAR"):
                        event_lines = event_lines[1:-1]
                    f.write("\n".join(event_lines))
                    f.write("\n")
                f.write("END:VCALENDAR\n")
            messagebox.showinfo("导出成功", f"已成功导出 {len(events)} 个日历事件")
            self.log_message(f"导出事件: {len(events)} 个到 {file_path}")
        except Exception as e:
            messagebox.showerror("导出失败", f"导出日历时出错: {str(e)}")
            logger.error(f"导出日历失败: {str(e)}")

    def import_contacts(self):
        import_dialog = tk.Toplevel(self.root)
        import_dialog.title("导入联系人")
        import_dialog.geometry("400x300")
        import_dialog.transient(self.root)
        import_dialog.grab_set()

        ttk.Label(import_dialog, text="请选择导入方式:", font=("Arial", 12)).pack(pady=10)

        button_frame = ttk.Frame(import_dialog)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="从文件导入", width=20,
                   command=lambda: self._import_contacts_from_file(import_dialog)).pack(pady=5)
        ttk.Button(button_frame, text="从URL导入", width=20,
                   command=lambda: self._import_contacts_from_url(import_dialog)).pack(pady=5)
        ttk.Button(button_frame, text="从剪切板导入", width=20,
                   command=lambda: self._import_contacts_from_clipboard(import_dialog)).pack(pady=5)
        ttk.Button(button_frame, text="从WebDAV服务器导入", width=20,
                   command=lambda: self._import_contacts_from_webdav(import_dialog)).pack(pady=5)
        ttk.Button(button_frame, text="从文本框粘贴导入", width=20,
                   command=lambda: self._import_contacts_from_text(import_dialog)).pack(pady=5)

    def _import_contacts_from_file(self, dialog=None):
        if dialog: dialog.destroy()

        file_paths = filedialog.askopenfilenames(
            title="选择联系人文件",
            filetypes=[("vCard 文件", "*.vcf *.vcard"), ("所有文件", "*.*")]
        )
        if not file_paths: return

        logger.info(f"联系人导入：从文件导入: {file_paths}")
        self._start_import_contacts(file_paths, "文件")

    def _import_contacts_from_url(self, dialog=None, initialvalue=""):
        if dialog: dialog.destroy()

        url = simpledialog.askstring("从URL导入", "请输入联系人文件的URL:", parent=self.root, initialvalue=initialvalue)
        if not url: return

        # 验证URL格式
        parsed_url = urlparse(url)
        logger.info(f"联系人导入：从URL导入: {url}")
        if not parsed_url.scheme or not parsed_url.netloc:
            messagebox.showerror("错误", "无效的URL格式")
            logger.error(f"联系人导入：从URL导入：无效的URL: {url}")
            self._import_contacts_from_url(dialog, url)
            return

        self._start_import_contacts([url], "URL")

    def _import_contacts_from_clipboard(self, dialog=None):
        if dialog: dialog.destroy()
        try:
            import pyperclip
            data = pyperclip.paste()
            if not data:
                messagebox.showwarning("警告", "剪切板中没有内容")
                logger.warning("联系人导入：剪切板中没有内容")
                return
            logger.info(f"联系人导入：从剪切板导入: {base64.b64encode(bytes(data, 'utf-8'))}")
            self._start_import_contacts([data], "剪切板")
        except ImportError:
            logger.error("联系人导入：从剪切板导入：pyperclip库未安装")
            messagebox.showerror("错误", "需要安装pyperclip库才能使用剪切板功能\n请运行: pip install pyperclip")

    def _import_contacts_from_webdav(self, dialog=None):
        """从WebDAV导入联系人"""
        if dialog: dialog.destroy()

        class ContactsImportHandler:
            def filter_files(self, files):
                return [f for f in files if f.lower().endswith(('.vcf', '.vcard'))]

            def process_file(self, file_path, filename):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    if 'BEGIN:VCARD' not in content:
                        raise Exception('文件内容不是有效的vCard格式')

                    uid, operation = self.app.db.add_contact(content)
                    self.app.log_message(f"成功 {operation} 联系人: {filename} ({uid})")
                    return True
                except Exception as e:
                    self.app.log_message(f"导入联系人失败: {str(e)}", 'error')
                    return False

            def on_import_complete(self, temp_files):
                # 不需要在这里处理，因为process_file已经直接添加到数据库了
                # 只需删除临时文件
                for temp_file in temp_files:
                    try:
                        if os.path.exists(temp_file): os.remove(temp_file)
                    except:
                        pass

        handler = ContactsImportHandler()
        handler.app = self  # 传递app引用

        self.webdav_client.create_import_dialog(
            self.root,
            '从WebDAV导入联系人',
            on_complete=handler
        )

    def _import_contacts_from_text(self, dialog=None):
        if dialog: dialog.destroy()

        text_dialog = tk.Toplevel(self.root)
        text_dialog.title("从文本导入联系人")
        text_dialog.geometry("600x500")
        text_dialog.transient(self.root)
        text_dialog.grab_set()

        ttk.Label(text_dialog, text="请粘贴vCard格式的联系人数据:", font=("Arial", 12)).pack(pady=10)

        text_frame = ttk.Frame(text_dialog)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.contact_text_editor = tk.Text(text_frame, height=20, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(text_frame, command=self.contact_text_editor.yview)
        self.contact_text_editor.config(yscrollcommand=scrollbar.set)

        self.contact_text_editor.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        button_frame = ttk.Frame(text_dialog)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="导入",
                   command=lambda: self._import_from_text_editor(text_dialog, "contacts")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=text_dialog.destroy).pack(side=tk.LEFT, padx=5)

        try:
            import pyperclip
            clipboard_content = pyperclip.paste()
            if "BEGIN:VCARD" in clipboard_content: self.contact_text_editor.insert(tk.END, clipboard_content)
        except ImportError:
            pass

    def _start_import_contacts(self, sources, source_type):
        # 创建进度窗口
        progress_window = tk.Toplevel(self.root)
        progress_window.title(f"从{source_type}导入联系人")
        progress_window.geometry("600x250")
        progress_window.transient(self.root)
        progress_window.grab_set()
        progress_window.resizable(False, False)

        # 防止多次打开导入窗口
        self.import_in_progress = True
        self.import_cancel_requested = False

        # 进度条
        ttk.Label(progress_window, text=f"正在从{source_type}导入联系人，请稍候...", font=("Arial", 10)).pack(pady=10)

        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress_window, variable=progress_var, maximum=100)
        progress_bar.pack(fill=tk.X, padx=20, pady=5)

        status_var = tk.StringVar()
        status_var.set("准备开始导入...")
        status_label = ttk.Label(progress_window, textvariable=status_var)
        status_label.pack(pady=5)

        # 添加统计信息标签
        stats_frame = ttk.Frame(progress_window)
        stats_frame.pack(fill=tk.X, padx=20, pady=5)

        ttk.Label(stats_frame, text="新增:").grid(row=0, column=0, sticky=tk.W)
        self.inserted_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.inserted_var).grid(row=0, column=1, padx=5)

        ttk.Label(stats_frame, text="更新:").grid(row=0, column=2, padx=(10, 0), sticky=tk.W)
        self.updated_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.updated_var).grid(row=0, column=3, padx=5)

        ttk.Label(stats_frame, text="相同:").grid(row=0, column=4, padx=(10, 0), sticky=tk.W)
        self.unchanged_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.unchanged_var).grid(row=0, column=5, padx=5)

        ttk.Label(stats_frame, text="失败:").grid(row=0, column=6, padx=(10, 0), sticky=tk.W)
        self.error_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.error_var).grid(row=0, column=7, padx=5)

        # 错误信息
        error_var = tk.StringVar()
        error_label = ttk.Label(progress_window, textvariable=error_var, foreground="red", wraplength=550)
        error_label.pack(pady=5)

        cancel_btn = ttk.Button(progress_window, text="取消", command=lambda: self.cancel_import(progress_window))
        cancel_btn.pack(pady=10)

        # 启动后台导入线程
        import_thread = threading.Thread(
            target=self.import_contacts_thread,
            args=(sources, progress_var, status_var, error_var, progress_window),
            daemon=True
        )
        import_thread.start()

        # 开始监控进度
        self.monitor_import_progress(progress_var, status_var, error_var, progress_window)

    def import_contacts_thread(self, sources, progress_var, status_var, error_var, progress_window):
        total_sources = len(sources)
        inserted_count = 0
        updated_count = 0
        unchanged_count = 0
        error_count = 0
        errors = []

        try:
            for i, source in enumerate(sources):
                if self.import_cancel_requested:
                    status_var.set("导入已取消")
                    return

                source_name = os.path.basename(source) if os.path.exists(source) else source
                status_var.set(f"正在处理: {source_name} ({i + 1}/{total_sources})")
                progress_var.set((i / total_sources) * 100)

                try:
                    if os.path.exists(source):
                        with open(source, 'r', encoding='utf-8') as f:
                            data = f.read()
                    else:
                        try:
                            response = requests.get(source, timeout=30)
                            response.raise_for_status()
                            data = response.text
                        except Exception as e:
                            raise Exception(f"下载文件失败: {str(e)}")

                    if "BEGIN:VCARD" not in data:
                        error_details = f"源: {source_name} - 错误: 文件内容不是有效的vCard格式"
                        errors.append(error_details)
                        error_var.set(error_details)
                        error_count += 1
                        continue

                    try:
                        components = list(vobject.readComponents(data))
                    except Exception as e:
                        error_details = f"源: {source_name} - 错误: 解析vCard失败 - {str(e)}"
                        errors.append(error_details)
                        error_var.set(error_details)
                        error_count += 1
                        continue

                    if not components:
                        error_details = f"源: {source_name} - 错误: 没有找到有效的联系人数据"
                        errors.append(error_details)
                        error_var.set(error_details)
                        error_count += 1
                        continue

                    total_contacts = len(components)
                    for j, comp in enumerate(components):
                        if self.import_cancel_requested:
                            status_var.set("导入已取消")
                            return

                        status_var.set(f"导入: {source_name} - 联系人 {j + 1}/{total_contacts}")
                        progress_var.set((i + (j / total_contacts)) / total_sources * 100)

                        try:
                            vcard_str = comp.serialize()
                            uid, operation = self.db.add_contact(vcard_str)
                            if operation == "inserted":
                                inserted_count += 1
                            elif operation == "updated":
                                updated_count += 1
                            elif operation == "unchanged":
                                unchanged_count += 1
                            else:
                                error_count += 1
                                error_details = f"源: {source_name} - 联系人 {j + 1} ({uid}) - 未知操作: {operation}"
                                errors.append(error_details)
                            self.root.after(0, lambda: self.update_import_stats(inserted_count, updated_count,
                                                                                unchanged_count, error_count))
                        except Exception as e:
                            error_count += 1
                            try:
                                name = comp.fn.value if hasattr(comp, 'fn') else "未知联系人"
                                error_details = f"源: {source_name} - 联系人 {j + 1} ({name}) - 错误: {str(e)}"
                            except BaseException:
                                error_details = f"源: {source_name} - 联系人 {j + 1} - 错误: {str(e)}"
                            errors.append(error_details)
                            error_var.set(error_details)
                except Exception as e:
                    error_count += 1
                    error_details = f"源: {source_name} - 错误: {str(e)}"
                    errors.append(error_details)
                    error_var.set(error_details)

            progress_var.set(100)
            if error_count == total_sources:
                status_var.set("导入失败! 所有源都处理失败")
            else:
                status_var.set(
                    f"导入完成! 新增: {inserted_count}, 更新: {updated_count}, 相同: {unchanged_count}, 失败: {error_count}")

            result = {
                "type": "contacts",
                "inserted": inserted_count,
                "updated": updated_count,
                "unchanged": unchanged_count,
                "errors": error_count,
                "error_list": errors
            }
            self.import_queue.put(result)
        except Exception as e:
            error_var.set(f"严重错误: {str(e)}")
            logger.error(f"联系人导入线程异常: {str(e)}")
            traceback.print_exc()
        finally:
            if not self.import_cancel_requested: self.root.after(0, progress_window.destroy)
            self.import_in_progress = False

    def update_import_stats(self, inserted, updated, unchanged, errors):
        """更新导入统计信息"""
        self.inserted_var.set(str(inserted))
        self.updated_var.set(str(updated))
        self.unchanged_var.set(str(unchanged))
        self.error_var.set(str(errors))

    def import_events(self):
        import_dialog = tk.Toplevel(self.root)
        import_dialog.title("导入日历事件")
        import_dialog.geometry("400x300")
        import_dialog.transient(self.root)
        import_dialog.grab_set()

        ttk.Label(import_dialog, text="请选择导入方式:", font=("Arial", 12)).pack(pady=10)

        button_frame = ttk.Frame(import_dialog)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="从文件导入", width=20,
                   command=lambda: self._import_events_from_file(import_dialog)).pack(pady=5)
        ttk.Button(button_frame, text="从URL导入", width=20,
                   command=lambda: self._import_events_from_url(import_dialog)).pack(pady=5)
        ttk.Button(button_frame, text="从剪切板导入", width=20,
                   command=lambda: self._import_events_from_clipboard(import_dialog)).pack(pady=5)
        ttk.Button(button_frame, text="从WebDAV服务器导入", width=20,
                   command=lambda: self._import_events_from_webdav(import_dialog)).pack(pady=5)
        ttk.Button(button_frame, text="从文本框粘贴导入", width=20,
                   command=lambda: self._import_events_from_text(import_dialog)).pack(pady=5)

    def _import_events_from_file(self, dialog=None):
        if dialog: dialog.destroy()

        file_paths = filedialog.askopenfilenames(
            title="选择日历事件文件",
            filetypes=[("iCalendar 文件", "*.ics"), ("所有文件", "*.*")]
        )
        if not file_paths: return

        self._start_import_events(file_paths, "文件")

    def _import_events_from_url(self, dialog=None, initialvalue=""):
        if dialog: dialog.destroy()

        url = simpledialog.askstring("从URL导入", "请输入日历文件的URL:", parent=self.root, initialvalue=initialvalue)
        if not url: return

        # 验证URL格式
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            messagebox.showerror("错误", "无效的URL格式")
            logger.error(f"无效的导入URL: {url}")
            self._import_events_from_url(dialog, url)
            return

        self._start_import_events([url], "URL")

    def _import_events_from_clipboard(self, dialog=None):
        if dialog: dialog.destroy()
        try:
            import pyperclip
            data = pyperclip.paste()
            if not data:
                messagebox.showwarning("警告", "剪切板中没有内容")
                return
            self._start_import_events([data], "剪切板")
        except ImportError:
            messagebox.showerror("错误", "需要安装pyperclip库才能使用剪切板功能\n请运行: pip install pyperclip")

    def _import_events_from_webdav(self, dialog=None):
        """从WebDAV导入日历事件"""
        if dialog: dialog.destroy()

        class EventsImportHandler:
            def filter_files(self, files):
                return [f for f in files if f.lower().endswith('.ics')]

            def process_file(self, file_path, filename):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    if 'BEGIN:VCALENDAR' not in content and 'BEGIN:VEVENT' not in content:
                        raise Exception('文件内容不是有效的iCalendar格式')

                    cal = vobject.readOne(content)
                    events = [comp for comp in cal.components() if comp.name == 'VEVENT']
                    if not events:
                        self.app.log_message("文件中没有找到日历事件", 'warning')
                        return False

                    success = 0
                    for event in events:
                        try:
                            new_cal = vobject.iCalendar()
                            new_cal.add(event)
                            uid, operation = self.app.db.add_event(new_cal.serialize())
                            summary = getattr(event, 'summary', None)
                            event_name = summary.value if summary else '未命名事件'
                            self.app.log_message(f"成功{operation}事件: {event_name} ({uid})")
                            success += 1
                        except Exception as e:
                            self.app.log_message(f"导入事件失败: {str(e)}", 'error')

                    return success > 0
                except Exception as e:
                    self.app.log_message(f"处理日历文件失败: {str(e)}", 'error')
                    return False

            def on_import_complete(self, temp_files):
                # 刷新事件列表
                self.app.refresh_events()
                # 删除临时文件
                for temp_file in temp_files:
                    try:
                        if os.path.exists(temp_file): os.remove(temp_file)
                    except:
                        pass

        handler = EventsImportHandler()
        handler.app = self  # 传递app引用

        self.webdav_client.create_import_dialog(
            self.root,
            '从WebDAV导入日历事件',
            on_complete=handler
        )

    def _import_events_from_text(self, dialog=None):
        if dialog:
            dialog.destroy()

        text_dialog = tk.Toplevel(self.root)
        text_dialog.title("从文本导入日历事件")
        text_dialog.geometry("600x500")
        text_dialog.transient(self.root)
        text_dialog.grab_set()

        ttk.Label(text_dialog, text="请粘贴iCalendar格式的事件数据:", font=("Arial", 12)).pack(pady=10)

        text_frame = ttk.Frame(text_dialog)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.event_text_editor = tk.Text(text_frame, height=20, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(text_frame, command=self.event_text_editor.yview)
        self.event_text_editor.config(yscrollcommand=scrollbar.set)

        self.event_text_editor.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        button_frame = ttk.Frame(text_dialog)
        button_frame.pack(pady=10)

        ttk.Button(button_frame, text="导入",
                   command=lambda: self._import_from_text_editor(text_dialog, "events")).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=text_dialog.destroy).pack(side=tk.LEFT, padx=5)

        try:
            import pyperclip
            clipboard_content = pyperclip.paste()
            if "BEGIN:VCALENDAR" in clipboard_content or "BEGIN:VEVENT" in clipboard_content:
                self.event_text_editor.insert(tk.END, clipboard_content)
        except ImportError:
            pass

    def _start_import_events(self, sources, source_type):
        # 创建进度窗口
        progress_window = tk.Toplevel(self.root)
        progress_window.title(f"从{source_type}导入日历事件")
        progress_window.geometry("600x250")
        progress_window.transient(self.root)
        progress_window.grab_set()
        progress_window.resizable(False, False)

        # 防止多次打开导入窗口
        self.import_in_progress = True
        self.import_cancel_requested = False

        # 进度条
        ttk.Label(progress_window, text=f"正在从{source_type}导入日历事件，请稍候...", font=("Arial", 10)).pack(pady=10)

        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress_window, variable=progress_var, maximum=100)
        progress_bar.pack(fill=tk.X, padx=20, pady=5)

        status_var = tk.StringVar()
        status_var.set("准备开始导入...")
        status_label = ttk.Label(progress_window, textvariable=status_var)
        status_label.pack(pady=5)

        # 添加统计信息标签
        stats_frame = ttk.Frame(progress_window)
        stats_frame.pack(fill=tk.X, padx=20, pady=5)

        ttk.Label(stats_frame, text="新增:").grid(row=0, column=0, sticky=tk.W)
        self.inserted_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.inserted_var).grid(row=0, column=1, padx=5)

        ttk.Label(stats_frame, text="更新:").grid(row=0, column=2, padx=(10, 0), sticky=tk.W)
        self.updated_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.updated_var).grid(row=0, column=3, padx=5)

        ttk.Label(stats_frame, text="相同:").grid(row=0, column=4, padx=(10, 0), sticky=tk.W)
        self.unchanged_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.unchanged_var).grid(row=0, column=5, padx=5)

        ttk.Label(stats_frame, text="失败:").grid(row=0, column=6, padx=(10, 0), sticky=tk.W)
        self.error_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.error_var).grid(row=0, column=7, padx=5)

        # 错误信息
        error_var = tk.StringVar()
        error_label = ttk.Label(progress_window, textvariable=error_var, foreground="red", wraplength=550)
        error_label.pack(pady=5)

        cancel_btn = ttk.Button(progress_window, text="取消",
                                command=lambda: self.cancel_import(progress_window))
        cancel_btn.pack(pady=10)

        # 启动后台导入线程
        import_thread = threading.Thread(
            target=self.import_events_thread,
            args=(sources, progress_var, status_var, error_var, progress_window),
            daemon=True
        )
        import_thread.start()

        # 开始监控进度
        self.monitor_import_progress(progress_var, status_var, error_var, progress_window)

    def import_events_thread(self, sources, progress_var, status_var, error_var, progress_window):
        total_sources = len(sources)
        inserted_count = 0
        updated_count = 0
        unchanged_count = 0
        error_count = 0
        errors = []

        try:
            for i, source in enumerate(sources):
                if self.import_cancel_requested:
                    status_var.set("导入已取消")
                    return

                source_name = os.path.basename(source) if os.path.exists(source) else source
                status_var.set(f"正在处理: {source_name} ({i + 1}/{total_sources})")
                progress_var.set((i / total_sources) * 100)

                try:
                    if os.path.exists(source):
                        with open(source, 'r', encoding='utf-8') as f:
                            data = f.read()
                    else:
                        try:
                            response = requests.get(source, timeout=30)
                            response.raise_for_status()
                            data = response.text
                        except Exception as e:
                            raise Exception(f"下载文件失败: {str(e)}")

                    if "BEGIN:VCALENDAR" not in data and "BEGIN:VEVENT" not in data:
                        error_details = f"源: {source_name} - 错误: 文件内容不是有效的iCalendar格式"
                        errors.append(error_details)
                        error_var.set(error_details)
                        error_count += 1
                        continue

                    try:
                        cal = vobject.readOne(data)
                        events = [comp for comp in cal.components() if comp.name == 'VEVENT']
                    except Exception as e:
                        error_details = f"源: {source_name} - 错误: 解析日历失败 - {str(e)}"
                        errors.append(error_details)
                        error_var.set(error_details)
                        error_count += 1
                        continue

                    if not events:
                        error_details = f"源: {source_name} - 错误: 没有找到有效的事件数据"
                        errors.append(error_details)
                        error_var.set(error_details)
                        error_count += 1
                        continue

                    total_events = len(events)
                    for j, event in enumerate(events):
                        if self.import_cancel_requested:
                            status_var.set("导入已取消")
                            return

                        status_var.set(f"导入: {source_name} - 事件 {j + 1}/{total_events}")
                        progress_var.set((i + (j / total_events)) / total_sources * 100)

                        try:
                            summary = event.summary.value if hasattr(event, 'summary') else "无标题事件"
                            new_cal = vobject.iCalendar()
                            new_cal.add(event)
                            ical_str = new_cal.serialize()
                            uid, operation = self.db.add_event(ical_str)
                            if operation == "inserted":
                                inserted_count += 1
                            elif operation == "updated":
                                updated_count += 1
                            elif operation == "unchanged":
                                unchanged_count += 1
                            else:
                                error_count += 1
                                error_details = f"源: {source_name} - 事件 {j + 1} ({summary} ({uid})) - 未知操作: {operation}"
                                errors.append(error_details)
                            self.root.after(0, lambda: self.update_import_stats(inserted_count, updated_count,
                                                                                unchanged_count, error_count))
                        except Exception as e:
                            error_count += 1
                            error_details = f"源: {source_name} - 事件 {j + 1} ({summary} ({uid})) - 错误: {str(e)}"
                            errors.append(error_details)
                            error_var.set(error_details)
                except Exception as e:
                    error_count += 1
                    error_details = f"源: {source_name} - 错误: {str(e)}"
                    errors.append(error_details)
                    error_var.set(error_details)

            progress_var.set(100)
            if error_count == total_sources:
                status_var.set("导入失败! 所有源都处理失败")
            else:
                status_var.set(
                    f"导入完成! 新增: {inserted_count}, 更新: {updated_count}, 相同: {unchanged_count}, 失败: {error_count}")

            result = {
                "type": "events",
                "inserted": inserted_count,
                "updated": updated_count,
                "unchanged": unchanged_count,
                "errors": error_count,
                "error_list": errors
            }
            self.import_queue.put(result)
        except Exception as e:
            error_var.set(f"严重错误: {str(e)}")
            logger.error(f"事件导入线程异常: {str(e)}")
            traceback.print_exc()
        finally:
            if not self.import_cancel_requested:
                self.root.after(0, progress_window.destroy)
            self.import_in_progress = False

    def _import_from_text_editor(self, dialog, data_type):
        text_content = self.contact_text_editor.get("1.0",
                                                    tk.END) if data_type == "contacts" else self.event_text_editor.get(
            "1.0", tk.END)
        if not text_content.strip():
            messagebox.showwarning("警告", "没有输入任何内容")
            return

        if data_type == "contacts" and "BEGIN:VCARD" not in text_content:
            messagebox.showwarning("格式错误", "粘贴的内容不是有效的vCard格式")
            return

        if data_type == "events" and "BEGIN:VCALENDAR" not in text_content and "BEGIN:VEVENT" not in text_content:
            messagebox.showwarning("格式错误", "粘贴的内容不是有效的iCalendar格式")
            return

        progress_window = tk.Toplevel(dialog)
        progress_window.title("正在导入")
        progress_window.geometry("400x150")
        progress_window.transient(dialog)
        progress_window.grab_set()

        ttk.Label(progress_window, text="正在导入数据，请稍候...", font=("Arial", 10)).pack(pady=10)

        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(progress_window, variable=progress_var, maximum=100)
        progress_bar.pack(fill=tk.X, padx=20, pady=5)

        status_var = tk.StringVar()
        status_var.set("准备导入...")
        status_label = ttk.Label(progress_window, textvariable=status_var)
        status_label.pack(pady=5)

        def import_thread():
            try:
                if data_type == "contacts":
                    status_var.set("正在解析联系人数据...")
                    self._start_import_contacts([text_content], "文本")
                else:
                    status_var.set("正在解析日历事件数据...")
                    self._start_import_events([text_content], "文本")

                progress_var.set(100)
                status_var.set("导入完成!")
                progress_window.after(2000, progress_window.destroy)
                dialog.destroy()
            except Exception as e:
                status_var.set(f"导入失败: {str(e)}")
                logger.error(f"从文本导入失败: {str(e)}")
                progress_window.after(3000, progress_window.destroy)

        threading.Thread(target=import_thread, daemon=True).start()
        progress_window.after(100,
                              lambda: self.monitor_import_progress(progress_var, status_var, None, progress_window))

    def monitor_import_progress(self, progress_var, status_var, error_var, progress_window):
        """监控导入进度并更新UI"""
        if self.import_in_progress:
            # 更新进度条
            progress_window.update()
            # 继续监控
            self.root.after(100,
                            lambda: self.monitor_import_progress(progress_var, status_var, error_var, progress_window))
        else:
            progress_window.destroy()

    def cancel_import(self, progress_window):
        """取消导入操作"""
        self.import_cancel_requested = True
        progress_window.destroy()
        self.import_in_progress = False
        self.log_message("导入操作已取消")

    def process_import_queue(self):
        """处理导入结果队列"""
        try:
            while not self.import_queue.empty():
                result = self.import_queue.get_nowait()

                # 刷新对应的列表
                if result["type"] == "contacts":
                    self.refresh_contacts()
                else:
                    self.refresh_events()

                self.update_status_bar()

                if result["errors"] == 0:
                    message = f"导入完成!\n新增: {result['inserted']}, 更新: {result['updated']}, 相同: {result['unchanged']}"
                    messagebox.showinfo("导入完成", message)

                    self.log_message(
                        f"导入{result['type']}: 新增 {result['inserted']}, 更新 {result['updated']}, 相同 {result['unchanged']}")
                else:
                    error_msg = f"导入完成!\n新增: {result['inserted']}, 更新: {result['updated']}, 相同: {result['unchanged']}, 失败: {result['errors']}\n\n错误详情:\n"
                    for i, err in enumerate(result["error_list"][:10]): error_msg += f"{i + 1}. {err}\n"
                    if len(result[
                               "error_list"]) > 10: error_msg += f"\n...以及另外 {len(result['error_list']) - 10} 条错误"

                    messagebox.showinfo("导入完成", error_msg)

                    self.log_message(
                        f"导入{result['type']}: 新增 {result['inserted']}, 更新 {result['updated']}, 相同 {result['unchanged']}, 失败 {result['errors']}" + (
                            (" - 错误详情: " + str(result["error_list"])) if result["errors"] != 0 else ""))
        except queue.Empty:
            pass

        # 继续检查队列
        self.root.after(500, self.process_import_queue)

    def add_event(self):
        dialog = EventDialog(self.root)
        if dialog.result:
            # 直接获取对话框生成的原始iCalendar数据
            ical = dialog.get_raw_ical()

            # 保存到数据库
            uid, operation = self.db.add_event(ical)
            if uid:
                self.refresh_events()
                self.log_message(f"添加事件 ({operation}): {dialog.result['summary']} ({uid})")

    def edit_event(self):
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个事件")
            return

        # 只编辑第一个选中的事件
        item = self.events_tree.item(selected[0])
        values = [str(v) if v is not None else "" for v in item['values']]
        _, uid, _, _, _ = values  # 只使用UID，其他字段从原始数据获取

        # 从数据库获取完整事件数据
        event_data = self.db.get_event(uid)
        if not event_data:
            messagebox.showerror("错误", "无法获取事件详情")
            return

        # 解析iCalendar数据
        try:
            ical = vobject.readOne(event_data)
            vevent = ical.vevent

            # 准备初始数据
            initial = {
                'uid': uid,
                'summary': self.decode_text(vevent.summary.value) if hasattr(vevent, 'summary') else "",
                'location': self.decode_text(vevent.location.value) if hasattr(vevent, 'location') else "",
                'description': self.decode_text(vevent.description.value) if hasattr(vevent, 'description') else "",
                'status': vevent.status.value if hasattr(vevent, 'status') else "CONFIRMED",
                'version': ical.version.value if hasattr(ical, 'version') else "2.0",
                'allday': False,
                'force_reminder': False,
                'categories': "",
                'priority': "5",
                'transparency': "OPAQUE",
                'sequence': "0",
                'url': "",
                'organizer': "",
                'attendees': [],
                'alarms': [],
                'rrule': ""
            }

            # 处理日期时间
            if hasattr(vevent, 'dtstart'):
                dtstart = vevent.dtstart.value
                if isinstance(dtstart, datetime):
                    initial['start'] = dtstart.isoformat()
                    initial['allday'] = False
                else:  # 全天事件
                    initial['start'] = dtstart.strftime("%Y-%m-%d")
                    initial['allday'] = True

            if hasattr(vevent, 'dtend'):
                dtend = vevent.dtend.value
                if isinstance(dtend, datetime):
                    initial['end'] = dtend.isoformat()
                else:
                    initial['end'] = dtend.strftime("%Y-%m-%d")

            # 处理重复规则
            if hasattr(vevent, 'rrule'):
                rrule = vevent.rrule.value
                initial['rrule'] = rrule

                # 解析重复规则
                if 'FREQ=DAILY' in rrule:
                    initial['repeat'] = '每天'
                elif 'FREQ=WEEKLY' in rrule:
                    if 'INTERVAL=2' in rrule:
                        initial['repeat'] = '每两周'
                    else:
                        initial['repeat'] = '每周'
                elif 'FREQ=MONTHLY' in rrule:
                    initial['repeat'] = '每月'
                elif 'FREQ=YEARLY' in rrule:
                    initial['repeat'] = '每年'
                else:
                    initial['repeat'] = '自定义'

                # 解析结束条件
                if 'UNTIL=' in rrule:
                    initial['end_cond'] = '按日期结束'
                    try:
                        until_str = rrule.split('UNTIL=')[1].split(';')[0]
                        until_date = parser.parse(until_str).strftime("%Y-%m-%d")
                        initial['end_date'] = until_date
                    except BaseException:
                        pass
                elif 'COUNT=' in rrule:
                    initial['end_cond'] = '按次数结束'
                    try:
                        count = rrule.split('COUNT=')[1].split(';')[0]
                        initial['end_count'] = count
                    except BaseException:
                        pass

            # 处理提醒 - 解析所有VALARM组件
            initial['alarms'] = []
            for component in vevent.getChildren():
                if component.name == 'VALARM':
                    alarm = {
                        'action': component.action.value if hasattr(component, 'action') else "DISPLAY",
                        'trigger': component.trigger.value if hasattr(component, 'trigger') else timedelta(
                            minutes=-15)
                    }

                    if hasattr(component, 'repeat') and hasattr(component, 'duration'):
                        alarm['repeat'] = component.repeat.value
                        alarm['duration'] = component.duration.value

                    if hasattr(component, 'description'): alarm['description'] = self.decode_text(
                        component.description.value)
                    if hasattr(component, 'attach'): alarm['attach'] = component.attach.value
                    if hasattr(component, 'attendee'): alarm['attendee'] = component.attendee.value
                    if hasattr(component, 'summary'): alarm['summary'] = self.decode_text(component.summary.value)

                    initial['alarms'].append(alarm)

            if hasattr(vevent, 'categories'): initial['categories'] = self.decode_text(vevent.categories.value)
            if hasattr(vevent, 'priority'): initial['priority'] = vevent.priority.value
            if hasattr(vevent, 'transp'): initial['transparency'] = vevent.transp.value
            if hasattr(vevent, 'sequence'): initial['sequence'] = vevent.sequence.value
            if hasattr(vevent, 'url'): initial['url'] = vevent.url.value
            if hasattr(vevent, 'organizer'): initial['organizer'] = vevent.organizer.value
            if hasattr(vevent, 'attendee'): initial['attendees'] = [self.decode_text(att.value) for att in
                                                                    vevent.attendee_list]

        except Exception as e:
            logger.error(f"解析事件错误: {str(e)}")
            traceback.print_exc()
            messagebox.showerror("错误", f"解析事件失败: {str(e)}")
            return

        dialog = EventDialog(self.root, initial=initial)

        if dialog.result:
            # 直接获取对话框生成的原始iCalendar数据
            ical = dialog.get_raw_ical()

            # 保存到数据库
            uid, operation = self.db.add_event(ical)
            if uid:
                self.refresh_events()
                self.log_message(f"更新事件 ({operation}): {dialog.result['summary']} ({uid})")

    def decode_text(self, text):
        """解码QUOTED-PRINTABLE编码的文本"""
        if not text: return ""

        # 检查是否包含QUOTED-PRINTABLE编码
        if "ENCODING=QUOTED-PRINTABLE" in text:
            try:
                # 提取编码部分
                encoded_part = text.split(":", 1)[1]
                # 解码QUOTED-PRINTABLE
                decoded_bytes = quopri.decodestring(encoded_part)
                # 尝试UTF-8解码
                return decoded_bytes.decode('utf-8')
            except BaseException:
                return text

        return text

    def delete_event(self):
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的事件")
            return

        # 获取所有选中的事件
        events_to_delete = []
        for item_id in selected:
            item = self.events_tree.item(item_id)
            # 确保所有值都是字符串
            values = [str(v) if v is not None else "" for v in item['values']]
            _, uid, summary, start, end = values
            events_to_delete.append((uid, summary))

        # 确认删除
        summaries = ", ".join([summary for _, summary in events_to_delete])
        if messagebox.askyesno("确认删除", f"确定要删除以下事件吗?\n{summaries}"):
            success_count = 0
            fail_count = 0

            for uid, summary in events_to_delete:
                try:
                    if self.db.delete_event(uid):
                        success_count += 1
                    else:
                        fail_count += 1
                except Exception as e:
                    fail_count += 1

            self.refresh_events()
            if fail_count > 0:
                messagebox.showinfo("删除完成", f"成功删除 {success_count} 个事件\n失败 {fail_count} 个")
            else:
                messagebox.showinfo("删除完成", f"成功删除 {success_count} 个事件")

            self.log_message(f"删除事件: {success_count} 个成功, {fail_count} 个失败")

    def show_event_raw(self):
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个事件")
            return

        item = self.events_tree.item(selected[0])
        uid = item['values'][1]
        event_data = self.db.get_event(uid)

        self.show_raw_data(event_data, "事件原始数据")

    def show_raw_data(self, data, title):
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("600x400")

        text_frame = ttk.Frame(window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_area = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_area.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_area.yview)

        text_area.insert(tk.END, data)
        text_area.config(state=tk.DISABLED)

        ttk.Button(window, text="关闭", command=window.destroy).pack(pady=10)

    def start_server(self):
        port = int(self.port_entry.get())

        # 创建自定义处理程序
        class CustomHandler(SimpleDAVHandler): pass

        # 创建服务器
        self.server = HTTPServer(('', port), CustomHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        # 更新日志
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.insert(tk.END, f"服务器已启动在端口 {port}\n")
        self.log_text.insert(tk.END, f"CardDAV URL: http://localhost:{port}/contacts/\n")
        self.log_text.insert(tk.END, f"CalDAV URL: http://localhost:{port}/events/\n")
        self.log_text.config(state=tk.DISABLED)

        logger.info(f"服务器启动: 端口 {port}")

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            if self.server_thread: self.server_thread.join()
            self.server = None
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

            # 只记录一次日志
            logger.info("服务器已停止")

    def on_closing(self):
        if self.server: self.stop_server()
        self.db.close()
        self.root.destroy()


# ======================
# 自定义对话框
# ======================
class ContactDialog(tk.Toplevel):
    def __init__(self, parent, initial=None, vcard=None):
        super().__init__(parent)
        self.title("添加/编辑联系人")
        self.geometry("500x450")
        self.transient(parent)
        self.grab_set()

        self.result = None
        self.initial = initial or {}
        self.vcard = vcard

        self.create_widgets()

        # 设置初始值
        if self.initial:
            self.uid_entry.insert(0, self.initial.get('uid', ''))
            self.name_entry.insert(0, self.initial.get('name', ''))
            self.email_entry.insert(0, self.initial.get('email', ''))
            self.phone_entry.insert(0, self.initial.get('phone', ''))
        else:
            uid = f"contact-{int(datetime.now().timestamp())}"
            self.uid_entry.insert(0, uid)

        # 添加更多字段按钮
        if self.vcard: ttk.Button(self, text="显示完整 vCard", command=self.show_full_vcard).pack(pady=5)

        button_frame = ttk.Frame(self)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

        ttk.Button(button_frame, text="确定", command=self.ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="取消", command=self.cancel).pack(side=tk.RIGHT, padx=5)

        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.wait_window(self)

    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # UID
        ttk.Label(main_frame, text="UID:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.uid_entry = ttk.Entry(main_frame, width=40)
        self.uid_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        # 姓名
        ttk.Label(main_frame, text="姓名*:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.name_entry = ttk.Entry(main_frame, width=40)
        self.name_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        # 邮箱输入 (支持多个)
        ttk.Label(main_frame, text="邮箱:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.email_entry = ttk.Entry(main_frame, width=40)
        self.email_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="(多个邮箱用逗号或分号分隔)", foreground="gray").grid(row=3, column=1, sticky=tk.W)

        # 电话输入 (支持多个)
        ttk.Label(main_frame, text="电话:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.phone_entry = ttk.Entry(main_frame, width=40)
        self.phone_entry.grid(row=4, column=1, sticky=tk.W, pady=5)
        ttk.Label(main_frame, text="(多个电话用逗号或分号分隔)", foreground="gray").grid(row=5, column=1, sticky=tk.W)

        # 生日输入
        ttk.Label(main_frame, text="生日:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.birthday_entry = DateEntry(main_frame, date_pattern='yyyy-mm-dd')
        self.birthday_entry.delete(0, tk.END)  # 确保默认为空
        self.birthday_entry.grid(row=6, column=1, sticky=tk.W, pady=5)

        # 备注
        ttk.Label(main_frame, text="备注:").grid(row=7, column=0, sticky=tk.W, pady=5)
        self.note_entry = ttk.Entry(main_frame, width=40)
        self.note_entry.grid(row=7, column=1, sticky=tk.W, pady=5)

        # 其他字段 (带滚动条)
        ttk.Label(main_frame, text="其他字段:").grid(row=8, column=0, sticky=tk.W, pady=5)
        frame = ttk.Frame(main_frame)
        frame.grid(row=8, column=1, sticky=tk.W + tk.E, pady=5)

        self.other_text = tk.Text(frame, width=40, height=5)
        scrollbar = ttk.Scrollbar(frame, command=self.other_text.yview)
        self.other_text.configure(yscrollcommand=scrollbar.set)

        self.other_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 如果有vCard数据，显示其他字段
        if self.vcard:
            other_fields = []
            for child in self.vcard.getChildren():
                if child.name not in ["UID", "FN", "N", "EMAIL", "TEL", "BDAY", "NOTE"]:
                    other_fields.append(f"{child.name}: {child.value}")
            self.other_text.insert(tk.END, "\n".join(other_fields))

    def show_full_vcard(self):
        """显示完整的 vCard 内容"""
        if not self.vcard: return

        vcard_window = tk.Toplevel(self)
        vcard_window.title("完整 vCard")
        vcard_window.geometry("600x400")

        text_frame = ttk.Frame(vcard_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_area = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_area.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_area.yview)

        text_area.insert(tk.END, self.vcard.serialize())
        text_area.config(state=tk.DISABLED)

        ttk.Button(vcard_window, text="关闭", command=vcard_window.destroy).pack(pady=10)

    def ok(self):
        uid = self.uid_entry.get()
        name = self.name_entry.get()
        email = self.email_entry.get()
        phone = self.phone_entry.get()

        # 检查必填项
        missing_fields = []
        if not uid: missing_fields.append("UID")
        if not name: missing_fields.append("姓名")

        if missing_fields:
            messagebox.showerror("缺少必填项", f"以下字段是必填的: {', '.join(missing_fields)}")
            return

        self.result = {
            'uid': uid,
            'name': name,
            'email': email,
            'phone': phone
        }
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()


class EventDialog:
    # 状态和透明度的映射关系
    STATUS_MAPPING = {
        "待定": "TENTATIVE",
        "已确认": "CONFIRMED",
        "已取消": "CANCELLED"
    }

    TRANSPARENCY_MAPPING = {
        "忙碌": "OPAQUE",
        "空闲": "TRANSPARENT"
    }

    # 重复频率选项
    REPEAT_OPTIONS = ["不重复", "每天", "每周", "每两周", "每月", "每年", "自定义"]

    # 星期选项
    WEEKDAYS = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
    WEEKDAYS_RRULE = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"]

    # 结束条件选项
    END_CONDITIONS = ["永不结束", "按日期结束", "按次数结束"]

    def __init__(self, parent, initial=None, software_name=software_name, software_version=software_version):
        self.root = tk.Toplevel(parent)
        self.root.title("添加/编辑日历事件")
        self.root.geometry("900x750")
        self.root.transient(parent)
        self.root.grab_set()

        self.software_name = software_name
        self.software_version = software_version
        self.initial = initial or {}
        self.result = None
        self.alarms = []
        self.repeat_days = []
        self.end_count_var = tk.StringVar(value="5")
        self.raw_ical = None

        # 配置根窗口的网格权重
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # 主框架
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # 配置主框架的网格权重
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)

        # 创建选项卡
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # 配置选项卡的网格权重
        self.notebook.grid_rowconfigure(0, weight=1)
        self.notebook.grid_columnconfigure(0, weight=1)

        # 基本信息标签页
        self.basic_frame = ttk.Frame(self.notebook)
        self.basic_frame.grid_rowconfigure(0, weight=1)
        self.basic_frame.grid_columnconfigure(0, weight=1)
        self.notebook.add(self.basic_frame, text="基本信息")
        self.create_basic_tab()

        # 时间设置标签页
        self.time_frame = ttk.Frame(self.notebook)
        self.time_frame.grid_rowconfigure(0, weight=1)
        self.time_frame.grid_columnconfigure(0, weight=1)
        self.notebook.add(self.time_frame, text="时间设置")
        self.create_time_tab()

        # 提醒设置标签页
        self.reminder_frame = ttk.Frame(self.notebook)
        self.reminder_frame.grid_rowconfigure(0, weight=1)
        self.reminder_frame.grid_columnconfigure(0, weight=1)
        self.notebook.add(self.reminder_frame, text="提醒设置")
        self.create_reminder_tab()

        # 高级设置标签页
        self.advanced_frame = ttk.Frame(self.notebook)
        self.advanced_frame.grid_rowconfigure(0, weight=1)
        self.advanced_frame.grid_columnconfigure(0, weight=1)
        self.notebook.add(self.advanced_frame, text="高级设置")
        self.create_advanced_tab()

        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)

        ttk.Button(button_frame, text="保存", command=self.save).pack(side="left", padx=5)
        ttk.Button(button_frame, text="确定", command=self.ok).pack(side="right", padx=5)
        ttk.Button(button_frame, text="取消", command=self.cancel).pack(side="right", padx=5)

        #  添加查看原始数据按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=9, column=0, columnspan=2, sticky="e", padx=10, pady=10)

        # 添加查看原始数据按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=9, column=0, columnspan=2, sticky="e", padx=10, pady=10)

        ttk.Button(button_frame, text="查看原始数据", command=self.show_raw_data).pack(side="right", padx=5)

        # 初始化表单
        self.set_initial_values()

        self.root.protocol("WM_DELETE_WINDOW", self.cancel)
        self.root.wait_window(self.root)

    def create_basic_tab(self):
        frame = ttk.LabelFrame(self.basic_frame, text="事件基本信息")
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        ttk.Label(frame, text="事件ID:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.uid_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.uid_var, width=40).grid(row=0, column=1, columnspan=3, sticky="we", padx=5,
                                                                   pady=5)

        ttk.Label(frame, text="事件标题*:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.summary_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.summary_var, width=40).grid(row=1, column=1, columnspan=3, sticky="we",
                                                                       padx=5, pady=5)

        ttk.Label(frame, text="地点:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.location_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.location_var, width=40).grid(row=2, column=1, columnspan=3, sticky="we",
                                                                        padx=5, pady=5)

        ttk.Label(frame, text="描述:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.description_text = tk.Text(frame, height=5, width=50)
        self.description_text.grid(row=3, column=1, columnspan=3, sticky="nsew", padx=5, pady=5)
        scrollbar = ttk.Scrollbar(frame, command=self.description_text.yview)
        scrollbar.grid(row=3, column=4, sticky="ns")
        self.description_text.config(yscrollcommand=scrollbar.set)

        ttk.Label(frame, text="事件状态:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.status_var = tk.StringVar()
        status_options = ["待定", "已确认", "已取消"]
        ttk.Combobox(frame, textvariable=self.status_var, values=status_options, width=15, state="readonly").grid(row=4,
                                                                                                                  column=1,
                                                                                                                  sticky="w",
                                                                                                                  padx=5,
                                                                                                                  pady=5)
        self.status_var.trace("w", self.on_status_changed)  # 添加状态变更监听

        ttk.Label(frame, text="日历版本:").grid(row=4, column=2, sticky="e", padx=5, pady=5)
        self.version_var = tk.StringVar(value="2.0")
        version_options = ["1.0", "2.0", "2.1", "3.0"]
        ttk.Combobox(frame, textvariable=self.version_var, values=version_options,
                     width=8, state="readonly").grid(row=4, column=3, sticky="w", padx=5, pady=5)

    def create_time_tab(self):
        frame = ttk.LabelFrame(self.time_frame, text="时间设置")
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # 配置网格权重
        frame.columnconfigure(1, weight=1)

        # 全天事件
        self.allday_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="全天事件", variable=self.allday_var, command=self.toggle_allday_event).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=5, pady=5)

        # 开始时间 - 使用框架组织
        start_frame = ttk.Frame(frame)
        start_frame.grid(row=1, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        ttk.Label(start_frame, text="开始日期*:").grid(row=0, column=0, sticky="w")
        self.start_date = DateEntry(start_frame, date_pattern='yyyy-mm-dd', width=12)
        self.start_date.grid(row=0, column=1, padx=(5, 0))

        ttk.Label(start_frame, text="时间:").grid(row=0, column=2, padx=(10, 0))
        self.start_hour = ttk.Combobox(start_frame, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly")
        self.start_hour.grid(row=0, column=3, padx=5)
        self.start_hour.set("00")

        ttk.Label(start_frame, text=":").grid(row=0, column=4)
        self.start_minute = ttk.Combobox(start_frame, width=3, values=[f"{m:02d}" for m in range(0, 60, 5)],
                                         state="readonly")
        self.start_minute.grid(row=0, column=5, padx=(0, 10))
        self.start_minute.set("00")

        # 添加"当前时间"按钮
        ttk.Button(start_frame, text="当前时间", command=self.set_start_current_time, width=10).grid(row=0, column=6,
                                                                                                     padx=(10, 0))

        # 结束时间
        end_frame = ttk.Frame(frame)
        end_frame.grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        ttk.Label(end_frame, text="结束日期*:").grid(row=0, column=0, sticky="w")
        self.end_date = DateEntry(end_frame, date_pattern='yyyy-mm-dd', width=12)
        self.end_date.grid(row=0, column=1, padx=(5, 0))

        ttk.Label(end_frame, text="时间:").grid(row=0, column=2, padx=(10, 0))
        self.end_hour = ttk.Combobox(end_frame, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly")
        self.end_hour.grid(row=0, column=3, padx=5)
        self.end_hour.set("00")

        ttk.Label(end_frame, text=":").grid(row=0, column=4)
        self.end_minute = ttk.Combobox(end_frame, width=3, values=[f"{m:02d}" for m in range(0, 60, 5)],
                                       state="readonly")
        self.end_minute.grid(row=0, column=5, padx=(0, 10))
        self.end_minute.set("00")

        # 添加"当前时间"按钮
        ttk.Button(end_frame, text="当前时间", command=self.set_end_current_time, width=10).grid(row=0, column=6,
                                                                                                 padx=(10, 0))

        # 开始时间时区
        ttk.Label(frame, text="开始时间时区:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.start_timezone_var = tk.StringVar()
        self.start_timezone_combo = ttk.Combobox(frame, textvariable=self.start_timezone_var,
                                                 values=self.get_timezone_list(), width=40)
        self.start_timezone_combo.grid(row=3, column=1, columnspan=2, sticky="we", padx=5, pady=5)

        # 结束时间时区
        ttk.Label(frame, text="结束时间时区:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.end_timezone_var = tk.StringVar()
        self.end_timezone_combo = ttk.Combobox(frame, textvariable=self.end_timezone_var,
                                               values=self.get_timezone_list(), width=40)
        self.end_timezone_combo.grid(row=4, column=1, columnspan=2, sticky="we", padx=5, pady=5)

        # 同步时区复选框
        self.sync_timezone_var = tk.BooleanVar(value=True)
        self.sync_timezone_check = ttk.Checkbutton(frame, text="结束时间使用相同时区", variable=self.sync_timezone_var,
                                                   command=self.toggle_timezone_sync)
        self.sync_timezone_check.grid(row=5, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        # 绑定开始时间时区改变事件
        self.start_timezone_var.trace("w", self.sync_timezones)

        # 设置默认时区
        local_tz_str = self.get_local_timezone_str()
        self.start_timezone_var.set(local_tz_str)
        self.end_timezone_var.set(local_tz_str)

        # 初始同步状态
        self.toggle_timezone_sync()

        # 重复规则
        ttk.Label(frame, text="重复规则:").grid(row=6, column=0, sticky="w", padx=5, pady=5)

        # 重复频率选择
        repeat_frame = ttk.Frame(frame)
        repeat_frame.grid(row=6, column=1, columnspan=2, sticky="w", padx=5, pady=5)

        self.repeat_var = tk.StringVar(value="不重复")
        repeat_combo = ttk.Combobox(repeat_frame, textvariable=self.repeat_var, values=self.REPEAT_OPTIONS, width=10,
                                    state="readonly")
        repeat_combo.grid(row=0, column=0, sticky="w")

        # 当选择"自定义"时，显示详细设置按钮
        self.custom_repeat_btn = ttk.Button(repeat_frame, text="详细设置...", command=self.custom_repeat_settings,
                                            state="disabled")
        self.custom_repeat_btn.grid(row=0, column=1, padx=(10, 0))

        # 绑定事件
        self.repeat_var.trace("w", self.on_repeat_changed)

        # 结束条件
        ttk.Label(frame, text="结束条件:").grid(row=7, column=0, sticky="w", padx=5, pady=5)

        # 创建结束条件框架并保存为实例变量
        self.end_cond_frame = ttk.Frame(frame)
        self.end_cond_frame.grid(row=7, column=1, columnspan=2, sticky="w", padx=5, pady=5)

        self.end_cond_var = tk.StringVar(value="永不结束")
        self.end_cond_var.trace("w", self.on_end_cond_changed)
        for i, option in enumerate(self.END_CONDITIONS):
            ttk.Radiobutton(self.end_cond_frame, text=option, variable=self.end_cond_var, value=option).grid(row=0,
                                                                                                             column=i,
                                                                                                             padx=(
                                                                                                             0, 10),
                                                                                                             sticky="w")

        # 结束日期/次数输入
        self.end_input_frame = ttk.Frame(frame)
        self.end_input_frame.grid(row=8, column=1, columnspan=2, sticky="w", padx=5, pady=5)

        # 初始隐藏
        self.end_input_frame.grid_remove()

        # 根据重复规则更新结束条件状态
        self.on_repeat_changed()

    def create_reminder_tab(self):
        """创建提醒设置标签页"""
        # 主框架
        frame = ttk.LabelFrame(self.reminder_frame, text="提醒设置")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 配置网格权重
        frame.columnconfigure(1, weight=1)

        # 提醒列表框架 - 显示所有已设置的提醒
        reminder_list_frame = ttk.LabelFrame(frame, text="提醒列表")
        reminder_list_frame.grid(row=0, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)
        reminder_list_frame.columnconfigure(0, weight=1)

        # 提醒列表
        self.reminder_listbox = tk.Listbox(reminder_list_frame, height=5)
        self.reminder_listbox.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(reminder_list_frame, command=self.reminder_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.reminder_listbox.config(yscrollcommand=scrollbar.set)

        # 提醒操作按钮
        button_frame = ttk.Frame(reminder_list_frame)
        button_frame.grid(row=1, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        ttk.Button(button_frame, text="添加提醒", command=self.add_reminder).pack(side="left", padx=2)
        ttk.Button(button_frame, text="编辑提醒", command=self.edit_reminder).pack(side="left", padx=2)
        ttk.Button(button_frame, text="删除提醒", command=self.delete_reminder).pack(side="left", padx=2)
        ttk.Label(button_frame, text="双击列表项编辑", foreground="gray").pack(side="right", padx=10)

        # 绑定双击事件
        self.reminder_listbox.bind("<Double-1>", lambda e: self.edit_reminder())

        # 提醒类型选择
        ttk.Label(frame, text="提醒类型:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.reminder_type_var = tk.StringVar(value="显示")
        reminder_types = ["显示", "声音", "邮件"]
        self.reminder_type_combo = ttk.Combobox(frame, textvariable=self.reminder_type_var, values=reminder_types,
                                                width=10, state="readonly")
        self.reminder_type_combo.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.reminder_type_combo.bind("<<ComboboxSelected>>", self.on_reminder_type_change)

        # 提醒触发类型选择
        ttk.Label(frame, text="提醒触发方式:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.reminder_trigger_type = tk.StringVar(value="relative")  # relative or absolute
        trigger_frame = ttk.Frame(frame)
        trigger_frame.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        ttk.Radiobutton(trigger_frame, text="提前时间提醒",
                        variable=self.reminder_trigger_type, value="relative",
                        command=self.toggle_reminder_trigger_type).pack(side="left", padx=5)
        ttk.Radiobutton(trigger_frame, text="指定时间提醒",
                        variable=self.reminder_trigger_type, value="absolute",
                        command=self.toggle_reminder_trigger_type).pack(side="left", padx=5)

        # 提前时间提醒设置
        ttk.Label(frame, text="提前多少时间提醒:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.reminder_time_frame = ttk.Frame(frame)
        self.reminder_time_frame.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        self.reminder_days_var = tk.StringVar(value="0")
        ttk.Label(self.reminder_time_frame, text="天:").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=365, textvariable=self.reminder_days_var, width=3).grid(row=0,
                                                                                                                  column=1,
                                                                                                                  padx=5)

        self.reminder_hours_var = tk.StringVar(value="0")
        ttk.Label(self.reminder_time_frame, text="小时:").grid(row=0, column=2, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=23, textvariable=self.reminder_hours_var, width=3).grid(row=0,
                                                                                                                  column=3,
                                                                                                                  padx=5)

        self.reminder_minutes_var = tk.StringVar(value="15")
        ttk.Label(self.reminder_time_frame, text="分钟:").grid(row=0, column=4, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=59, textvariable=self.reminder_minutes_var, width=3).grid(
            row=0, column=5, padx=5)

        # 指定时间提醒设置框架
        self.absolute_trigger_frame = ttk.Frame(frame)
        self.absolute_trigger_frame.grid(row=4, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        self.absolute_trigger_frame.grid_remove()  # 初始隐藏

        # 指定日期
        ttk.Label(self.absolute_trigger_frame, text="提醒日期:").grid(row=0, column=0, sticky="w")
        self.absolute_trigger_date = DateEntry(self.absolute_trigger_frame, date_pattern='yyyy-mm-dd', width=12)
        self.absolute_trigger_date.grid(row=0, column=1, padx=5)

        # 指定时间
        ttk.Label(self.absolute_trigger_frame, text="时间:").grid(row=0, column=2, padx=(10, 0))
        self.absolute_trigger_hour = ttk.Combobox(self.absolute_trigger_frame, width=3,
                                                  values=[f"{h:02d}" for h in range(24)], state="readonly")
        self.absolute_trigger_hour.grid(row=0, column=3, padx=5)
        self.absolute_trigger_hour.set("09")

        ttk.Label(self.absolute_trigger_frame, text=":").grid(row=0, column=4)
        self.absolute_trigger_minute = ttk.Combobox(self.absolute_trigger_frame, width=3,
                                                    values=[f"{m:02d}" for m in range(0, 60, 5)], state="readonly")
        self.absolute_trigger_minute.grid(row=0, column=5, padx=5)
        self.absolute_trigger_minute.set("00")

        # 时区选择
        ttk.Label(self.absolute_trigger_frame, text="时区:").grid(row=0, column=6, padx=(10, 0))
        self.absolute_trigger_timezone = ttk.Combobox(self.absolute_trigger_frame, values=self.get_timezone_list(),
                                                      width=30)
        self.absolute_trigger_timezone.grid(row=0, column=7, padx=5)
        self.absolute_trigger_timezone.set(self.get_local_timezone_str())

        # 提醒重复设置
        reminder_repeat_frame = ttk.Frame(frame)
        reminder_repeat_frame.grid(row=5, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        # 重复次数
        ttk.Label(reminder_repeat_frame, text="重复次数:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.reminder_repeat_var = tk.StringVar(value="0")
        ttk.Spinbox(reminder_repeat_frame, from_=0, to=999, textvariable=self.reminder_repeat_var, width=3).grid(row=0,
                                                                                                                 column=1,
                                                                                                                 sticky="w",
                                                                                                                 padx=5,
                                                                                                                 pady=5)

        # 间隔时间
        ttk.Label(reminder_repeat_frame, text="间隔时间:").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        self.reminder_duration_frame = ttk.Frame(reminder_repeat_frame)
        self.reminder_duration_frame.grid(row=0, column=3, sticky="w", padx=5, pady=5)

        # 间隔时间子控件
        self.reminder_duration_days_var = tk.StringVar(value="0")
        ttk.Label(self.reminder_duration_frame, text="天:").grid(row=0, column=0, sticky="w", padx=2)
        ttk.Spinbox(self.reminder_duration_frame, from_=0, to=365, textvariable=self.reminder_duration_days_var,
                    width=3).grid(row=0, column=1, padx=2)

        self.reminder_duration_hours_var = tk.StringVar(value="0")
        ttk.Label(self.reminder_duration_frame, text="小时:").grid(row=0, column=2, sticky="w", padx=2)
        ttk.Spinbox(self.reminder_duration_frame, from_=0, to=23, textvariable=self.reminder_duration_hours_var,
                    width=3).grid(row=0, column=3, padx=2)

        self.reminder_duration_minutes_var = tk.StringVar(value="15")
        ttk.Label(self.reminder_duration_frame, text="分钟:").grid(row=0, column=4, sticky="w", padx=2)
        ttk.Spinbox(self.reminder_duration_frame, from_=0, to=59, textvariable=self.reminder_duration_minutes_var,
                    width=3).grid(row=0, column=5, padx=2)

        # 强制提醒选项
        self.force_reminder_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="强制提醒", variable=self.force_reminder_var).grid(row=6, column=0, columnspan=2,
                                                                                       sticky="w", padx=5, pady=10)

        # 根据不同提醒类型显示特定控件
        self.display_frame = ttk.Frame(frame)
        self.display_frame.grid(row=7, column=0, columnspan=4, sticky="ew", padx=5, pady=5)
        self.display_frame.grid_remove()

        self.audio_attach_frame = ttk.Frame(frame)
        self.audio_attach_frame.grid(row=7, column=0, columnspan=4, sticky="ew", padx=5, pady=5)
        self.audio_attach_frame.grid_remove()

        self.email_frame = ttk.Frame(frame)
        self.email_frame.grid(row=7, column=0, columnspan=4, sticky="ew", padx=5, pady=5)
        self.email_frame.grid_remove()

        # 显示提醒的描述框
        ttk.Label(self.display_frame, text="提醒描述:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.display_description = tk.Text(self.display_frame, height=3, width=40)
        self.display_description.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        display_scrollbar = ttk.Scrollbar(self.display_frame, command=self.display_description.yview)
        display_scrollbar.grid(row=0, column=2, sticky="ns")
        self.display_description.config(yscrollcommand=display_scrollbar.set)

        # 声音提醒的附件框
        ttk.Label(self.audio_attach_frame, text="音频文件地址:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.audio_attach_var = tk.StringVar()
        ttk.Entry(self.audio_attach_frame, textvariable=self.audio_attach_var, width=40).grid(row=0, column=1,
                                                                                              sticky="ew", padx=5,
                                                                                              pady=5)

        # 邮件提醒的多个字段
        ttk.Label(self.email_frame, text="收件人邮箱:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.email_attendee_var = tk.StringVar()
        ttk.Entry(self.email_frame, textvariable=self.email_attendee_var, width=40).grid(row=0, column=1, sticky="ew",
                                                                                         padx=5, pady=5)

        ttk.Label(self.email_frame, text="邮件主题:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.email_summary_var = tk.StringVar()
        ttk.Entry(self.email_frame, textvariable=self.email_summary_var, width=40).grid(row=1, column=1, sticky="ew",
                                                                                        padx=5, pady=5)

        ttk.Label(self.email_frame, text="邮件正文:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.email_description = tk.Text(self.email_frame, height=3, width=40)
        self.email_description.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)
        email_scrollbar = ttk.Scrollbar(self.email_frame, command=self.email_description.yview)
        email_scrollbar.grid(row=2, column=2, sticky="ns")
        self.email_description.config(yscrollcommand=email_scrollbar.set)

        ttk.Label(self.email_frame, text="邮件附件:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.email_attach_var = tk.StringVar()
        ttk.Entry(self.email_frame, textvariable=self.email_attach_var, width=40).grid(row=3, column=1, sticky="ew",
                                                                                       padx=5, pady=5)

        # 初始化提醒类型相关控件的状态
        self.on_reminder_type_change()

        # 初始化触发类型显示
        self.toggle_reminder_trigger_type()

    def create_advanced_tab(self):
        frame = ttk.LabelFrame(self.advanced_frame, text="高级设置")
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # 配置网格权重
        frame.columnconfigure(1, weight=1)

        # 分类
        ttk.Label(frame, text="日程分类:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.categories_var = tk.StringVar()
        self.categories_entry = ttk.Entry(frame, textvariable=self.categories_var, width=30)
        self.categories_entry.grid(row=0, column=1, sticky="we", padx=5, pady=5)

        # 优先级 - 使用Scale
        ttk.Label(frame, text="优先级:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.priority_var = tk.IntVar(value=5)  # 默认值为5（中等优先级）
        priority_frame = ttk.Frame(frame)
        priority_frame.grid(row=1, column=1, sticky="we", padx=5, pady=5)

        # 确保只能是整数，步长为1
        ttk.Scale(priority_frame, from_=0, to=9, variable=self.priority_var,
                  orient="horizontal", length=200, command=lambda v: self.priority_var.set(round(float(v)))).pack(
            side="left", anchor="center")
        ttk.Label(priority_frame, textvariable=self.priority_var).pack(side="left", padx=5)

        # 透明度 - 使用中文选项
        ttk.Label(frame, text="透明度:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.transparency_var = tk.StringVar(value="忙碌")
        transparencies = ["忙碌", "空闲"]
        ttk.Combobox(frame, textvariable=self.transparency_var, values=transparencies, width=15, state="readonly").grid(
            row=2, column=1, sticky="w", padx=5, pady=5)

        # 序列号
        ttk.Label(frame, text="序列号:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.sequence_var = tk.StringVar(value="0")
        ttk.Entry(frame, textvariable=self.sequence_var, width=10).grid(row=3, column=1, sticky="w", padx=5, pady=5)

        # URL
        ttk.Label(frame, text="URL:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.url_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.url_var, width=30).grid(row=4, column=1, sticky="we", padx=5, pady=5)

        # 组织者
        ttk.Label(frame, text="组织者:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
        self.organizer_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.organizer_var, width=30).grid(row=5, column=1, sticky="we", padx=5, pady=5)

        # 参与者
        ttk.Label(frame, text="参与者:").grid(row=6, column=0, sticky="nw", padx=5, pady=5)
        self.attendee_text = tk.Text(frame, height=3, width=40)
        self.attendee_text.grid(row=6, column=1, sticky="nsew", padx=5, pady=5)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(frame, command=self.attendee_text.yview)
        scrollbar.grid(row=6, column=2, sticky="ns")
        self.attendee_text.config(yscrollcommand=scrollbar.set)

    def on_end_cond_changed(self, *args):
        """当结束条件改变时更新UI"""
        self.update_end_condition_input(self.end_cond_var.get())

    def on_reminder_type_change(self, event=None):
        reminder_type = self.reminder_type_var.get()
        self.display_frame.grid_remove()
        self.audio_attach_frame.grid_remove()
        self.email_frame.grid_remove()

        if reminder_type == "显示":
            self.display_frame.grid(row=5, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        elif reminder_type == "声音":
            self.audio_attach_frame.grid(row=5, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        elif reminder_type == "邮件":
            self.email_frame.grid(row=5, column=0, columnspan=3, sticky="ew", padx=5, pady=5)

    def on_status_changed(self, *args):
        """当事件状态变更时的处理"""
        status = self.status_var.get()
        is_cancelled = (status == "已取消")
        is_tentative = (status == "待定")

        # 保存原有设置以便恢复
        if not hasattr(self, 'original_settings'):
            self.original_settings = {
                'time': {
                    'start_date': self.start_date.get_date(),
                    'start_hour': self.start_hour.get(),
                    'start_minute': self.start_minute.get(),
                    'end_date': self.end_date.get_date(),
                    'end_hour': self.end_hour.get(),
                    'end_minute': self.end_minute.get()
                },
                'alarms': self.alarms.copy()
            }

        # 根据状态设置页面可用性
        if is_cancelled:
            # 已取消状态：禁用时间和提醒设置
            self.notebook.tab(1, state="disabled")  # 时间设置
            self.notebook.tab(2, state="disabled")  # 提醒设置
        elif is_tentative:
            # 待定状态：只禁用提醒设置
            self.notebook.tab(1, state="normal")  # 时间设置保持可用
            self.notebook.tab(2, state="disabled")  # 提醒设置禁用
        else:
            # 其他状态：全部可用
            self.notebook.tab(1, state="normal")
            self.notebook.tab(2, state="normal")

    def update_reminder_listbox(self):
        """更新提醒列表框的内容"""
        self.reminder_listbox.delete(0, tk.END)
        for alarm in self.alarms:
            trigger = alarm['trigger']
            action = alarm['action']

            # 创建显示文本
            if isinstance(trigger, timedelta):
                days = abs(trigger.days)
                seconds = abs(trigger.seconds)
                hours = seconds // 3600
                minutes = (seconds % 3600) // 60

                trigger_text = f"{days}天{hours}小时{minutes}分钟前"
            else:
                trigger_text = str(trigger)

            display_text = f"{action} - {trigger_text}"

            # 添加重复信息
            repeat = alarm.get('repeat', '0')
            if repeat != '0' and 'duration' in alarm:
                duration = alarm['duration']
                if isinstance(duration, timedelta):
                    days = duration.days
                    seconds = duration.seconds
                    hours = seconds // 3600
                    minutes = (seconds % 3600) // 60

                    interval_text = ""
                    if days > 0: interval_text += f"{days}天"
                    if hours > 0: interval_text += f"{hours}小时"
                    if minutes > 0: interval_text += f"{minutes}分钟"

                    display_text += f" (重复{repeat}次, 间隔{interval_text})"

            # 添加其他属性
            if 'description' in alarm:
                display_text += f" - {alarm['description'][:10] + '...' if alarm['description'] and len(alarm['description']) >= 10 else alarm['description'] if alarm['description'] else '[无描述/正文]'}"
            if 'attendee' in alarm:
                display_text += f" - {alarm['attendee'][:10] + '...' if alarm['attendee'] and len(alarm['attendee']) >= 10 else alarm['attendee'] if alarm['attendee'] else '[无收件人]'}"
            if 'summary' in alarm:
                display_text += f" - {alarm['summary'][:10] + '...' if alarm['summary'] and len(alarm['summary']) >= 10 else alarm['summary'] if alarm['summary'] else '[无主题]'}"
            if 'attach' in alarm:
                display_text += f" - {alarm['attach'][:10] + '...' if alarm['attach'] and len(alarm['attach']) >= 10 else alarm['attach'] if alarm['attach'] else '[无文件]'}"

            self.reminder_listbox.insert("end", display_text)

    def toggle_reminder_trigger_type(self):
        """切换提醒触发类型显示"""
        if self.reminder_trigger_type.get() == "relative":
            self.reminder_time_frame.grid()
            self.absolute_trigger_frame.grid_remove()
        else:
            self.reminder_time_frame.grid_remove()
            self.absolute_trigger_frame.grid()

    def toggle_allday_event(self):
        """切换全天事件状态"""
        is_allday = self.allday_var.get()

        # 启用/禁用时间选择控件
        state = "disabled" if is_allday else "readonly"
        self.start_hour.config(state=state)
        self.start_minute.config(state=state)
        self.end_hour.config(state=state)
        self.end_minute.config(state=state)

        # 启用/禁用时区选择
        self.start_timezone_combo.config(state=state)
        self.end_timezone_combo.config(state=state)

        # 禁用时区同步选项
        self.sync_timezone_check.config(state="disabled" if is_allday else "normal")

        # 如果是全天事件，强制使用绝对时间提醒
        if is_allday:
            self.reminder_trigger_type.set("absolute")
            self.toggle_reminder_trigger_type()

            # 设置默认提醒时间为当天上午9点
            start_date = self.start_date.get_date()
            self.absolute_trigger_date.set_date(start_date)
            self.absolute_trigger_hour.set("09")
            self.absolute_trigger_minute.set("00")
            self.absolute_trigger_timezone.set(self.start_timezone_var.get())

            # 禁用相对时间提醒控件
            self.reminder_time_frame.grid_remove()

            # 显示提示信息
            if not hasattr(self, 'allday_reminder_hint'):
                self.allday_reminder_hint = ttk.Label(
                    self.reminder_frame,
                    text="全天事件只能使用指定时间提醒，默认设置为事件当天上午9点",
                    foreground="blue"
                )
                self.allday_reminder_hint.grid(row=10, column=0, columnspan=3, sticky="w", padx=5, pady=5)
            self.allday_reminder_hint.grid()
        else:
            # 启用相对时间提醒
            self.reminder_time_frame.grid()

            # 隐藏提示信息
            if hasattr(self, 'allday_reminder_hint'): self.allday_reminder_hint.grid_remove()

    def parse_duration_for_display(self, duration_str):
        """解析持续时间用于显示"""
        days = 0
        hours = 0
        minutes = 0

        if 'D' in duration_str:
            days_part = duration_str.split('D')[0]
            if days_part.startswith('P'): days_part = days_part[1:]
            days = int(days_part) if days_part else 0

        if 'H' in duration_str:
            hours_part = duration_str.split('H')[0]
            if 'T' in hours_part: hours_part = hours_part.split('T')[1]
            hours = int(hours_part) if hours_part else 0

        if 'M' in duration_str and 'T' in duration_str:
            minutes_part = duration_str.split('M')[0]
            if 'H' in minutes_part: minutes_part = minutes_part.split('H')[1]
            minutes = int(minutes_part) if minutes_part else 0

        return days, hours, minutes

    def set_initial_values(self):
        # 设置默认时区
        local_tz_str = self.get_local_timezone_str()
        self.start_timezone_var.set(local_tz_str)
        self.end_timezone_var.set(local_tz_str)

        # 如果有初始数据，填充表单
        if self.initial:
            self.uid_var.set(self.initial.get('uid', f"event-{uuid.uuid4().hex}"))
            self.summary_var.set(self.decode_text(self.initial.get('summary', '')))
            self.location_var.set(self.decode_text(self.initial.get('location', '')))

            if 'description' in self.initial: self.description_text.insert("1.0", self.decode_text(
                self.initial.get('description', '')))

            # 状态转换（英文->中文）
            status_en = self.initial.get('status', 'CONFIRMED')
            status_zh = next((k for k, v in self.STATUS_MAPPING.items() if v == status_en), "已确认")
            self.status_var.set(status_zh)

            self.version_var.set(self.initial.get('version', '2.0'))

            self.allday_var.set(self.initial.get('allday', False))

            # 如果是全天事件，应用相关设置
            if self.allday_var.get(): self.toggle_allday_event()

            # 设置时间
            if 'start' in self.initial:
                try:
                    if self.initial['start']:
                        # 解析日期时间字符串
                        if isinstance(self.initial['start'], str):
                            start_dt = parser.parse(self.initial['start'])
                        else:
                            start_dt = self.initial['start']

                        # 设置日期和时间组件
                        self.start_date.set_date(start_dt.strftime("%Y-%m-%d"))

                        if not self.initial.get('allday', False):
                            self.start_hour.set(start_dt.strftime("%H"))
                            self.start_minute.set(start_dt.strftime("%M"))

                        # 获取时区信息
                        if hasattr(start_dt, 'tzinfo') and start_dt.tzinfo:
                            tz_name = start_dt.tzinfo.tzname(start_dt)
                            if tz_name:
                                # 在列表中找到匹配项
                                for option in self.start_timezone_combo['values']:
                                    if tz_name in option:
                                        self.start_timezone_var.set(option)
                                        break
                except Exception as e:
                    logger.error(f"解析开始时间错误: {str(e)}")
                    # 设置默认时间
                    start_time = datetime.now()
                    self.start_date.set_date(start_time.strftime("%Y-%m-%d"))
                    self.start_hour.set(start_time.strftime("%H"))
                    self.start_minute.set(start_time.strftime("%M"))

            if 'end' in self.initial:
                try:
                    if self.initial['end']:
                        # 解析日期时间字符串
                        if isinstance(self.initial['end'], str):
                            end_dt = parser.parse(self.initial['end'])
                        else:
                            end_dt = self.initial['end']

                        # 设置日期和时间组件
                        self.end_date.set_date(end_dt.strftime("%Y-%m-%d"))

                        if not self.initial.get('allday', False):
                            self.end_hour.set(end_dt.strftime("%H"))
                            self.end_minute.set(end_dt.strftime("%M"))

                        # 获取时区信息
                        if hasattr(end_dt, 'tzinfo') and end_dt.tzinfo:
                            tz_name = end_dt.tzinfo.tzname(end_dt)
                            if tz_name:
                                # 在列表中找到匹配项
                                for option in self.end_timezone_combo['values']:
                                    if tz_name in option:
                                        self.end_timezone_var.set(option)
                                        break
                except Exception as e:
                    logger.error(f"解析结束时间错误: {str(e)}")
                    # 设置默认时间
                    end_time = datetime.now() + timedelta(hours=1)
                    self.end_date.set_date(end_time.strftime("%Y-%m-%d"))
                    self.end_hour.set(end_time.strftime("%H"))
                    self.end_minute.set(end_time.strftime("%M"))

            # 设置重复规则和结束条件
            self.repeat_var.set(self.initial.get('repeat', '不重复'))
            self.end_cond_var.set(self.initial.get('end_cond', '永不结束'))

            # 更新结束条件输入框
            self.update_end_condition_input(self.end_cond_var.get())

            # 如果有结束日期或次数，设置它们
            if 'end_date' in self.initial: self.end_date_entry.set_date(self.initial['end_date'])
            if 'end_count' in self.initial: self.end_count_var.set(str(self.initial['end_count']))

            # 提醒设置
            self.force_reminder_var.set(self.initial.get('force_reminder', False))

            # 设置提醒列表
            self.alarms = []
            for alarm in self.initial.get('alarms', []):
                # 解码提醒中的文本字段
                decoded_alarm = alarm.copy()
                if 'description' in decoded_alarm: decoded_alarm['description'] = self.decode_text(
                    decoded_alarm['description'])
                if 'summary' in decoded_alarm: decoded_alarm['summary'] = self.decode_text(decoded_alarm['summary'])
                self.alarms.append(decoded_alarm)

            self.update_reminder_listbox()

            # 高级设置
            if 'categories' in self.initial:
                categories = self.initial['categories']
                # 如果是列表，转换为逗号分隔的字符串
                if isinstance(categories, (list, tuple)): categories = ''.join([str(c) for c in categories if c])
                self.categories_var.set(str(categories))

            # 优先级
            priority = self.initial.get('priority', '5')
            try:
                self.priority_var.set(int(priority))
            except:
                self.priority_var.set(5)

            # 透明度转换（英文->中文）
            transparency_en = self.initial.get('transparency', 'OPAQUE')
            transparency_zh = next((k for k, v in self.TRANSPARENCY_MAPPING.items() if v == transparency_en), "忙碌")
            self.transparency_var.set(transparency_zh)

            self.sequence_var.set(self.initial.get('sequence', '0'))
            self.url_var.set(self.initial.get('url', ''))
            self.organizer_var.set(self.initial.get('organizer', ''))

            if 'attendees' in self.initial: self.attendee_text.insert("1.0", "\n".join(self.initial['attendees']))
        else:
            # 设置默认值
            self.uid_var.set(f"event-{uuid.uuid4().hex}")
            now = datetime.now()
            self.start_date.set_date(now.strftime("%Y-%m-%d"))
            self.start_hour.set(now.strftime("%H"))
            self.start_minute.set(now.strftime("%M"))

            end_time = now + timedelta(hours=1)
            self.end_date.set_date(end_time.strftime("%Y-%m-%d"))
            self.end_hour.set(end_time.strftime("%H"))
            self.end_minute.set(end_time.strftime("%M"))

            self.status_var.set("已确认")
            self.transparency_var.set("忙碌")

    def set_start_current_time(self):
        """设置开始时间为当前时间"""
        now = datetime.now()
        self.start_date.set_date(now.strftime("%Y-%m-%d"))
        self.start_hour.set(now.strftime("%H"))
        self.start_minute.set(now.strftime("%M"))

    def set_end_current_time(self):
        """设置结束时间为当前时间+1小时"""
        end_time = datetime.now() + timedelta(hours=1)
        self.end_date.set_date(end_time.strftime("%Y-%m-%d"))
        self.end_hour.set(end_time.strftime("%H"))
        self.end_minute.set(end_time.strftime("%M"))

    def on_repeat_changed(self, *args):
        """当重复选项改变时更新UI"""
        repeat_option = self.repeat_var.get()

        # 更新自定义按钮状态
        if repeat_option == "自定义":
            self.custom_repeat_btn.config(state="normal")
        else:
            self.custom_repeat_btn.config(state="disabled")

        # 更新结束条件状态
        if repeat_option == "不重复":
            # 禁用结束条件选项
            for widget in self.end_cond_frame.winfo_children(): widget.config(state="disabled")
            self.end_input_frame.grid_remove()
        else:
            # 启用结束条件选项
            for widget in self.end_cond_frame.winfo_children(): widget.config(state="normal")
            self.update_end_condition_input(self.end_cond_var.get())

        # 更新结束条件输入框
        self.update_end_condition_input(self.end_cond_var.get())

    def update_end_condition_input(self, end_cond):
        """根据结束条件显示相应的输入控件"""
        # 清除现有控件
        for widget in self.end_input_frame.winfo_children(): widget.destroy()

        if end_cond == "按日期结束":
            self.end_input_frame.grid()
            ttk.Label(self.end_input_frame, text="结束日期:").grid(row=0, column=0, padx=(0, 5))
            self.end_date_entry = DateEntry(self.end_input_frame, date_pattern='yyyy-mm-dd', width=12)
            self.end_date_entry.grid(row=0, column=1)
        elif end_cond == "按次数结束":
            self.end_input_frame.grid()
            ttk.Label(self.end_input_frame, text="重复次数:").grid(row=0, column=0, padx=(0, 5))
            ttk.Entry(self.end_input_frame, textvariable=self.end_count_var, width=5).grid(row=0, column=1)
            ttk.Label(self.end_input_frame, text="次").grid(row=0, column=2, padx=(5, 0))
        else:
            self.end_input_frame.grid_remove()

    def custom_repeat_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("自定义重复设置")
        dialog.geometry("500x450")
        dialog.transient(self.root)
        dialog.grab_set()

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 获取当前开始日期
        try:
            current_start_date = self.start_date.get_date()
            current_weekday = current_start_date.weekday()  # 0=周一, 6=周日
            current_day = current_start_date.day
        except:
            current_weekday = 0
            current_day = 1

        # 检查是否需要更新默认设置
        if not hasattr(self, 'custom_repeat_data'):
            # 第一次打开，使用开始日期作为默认
            self.custom_repeat_data = {
                'freq': 'WEEKLY',
                'interval': '1',
                'byday': [self.WEEKDAYS_RRULE[current_weekday]],
                'bymonthday': [str(current_day)],
                'last_start_date': current_start_date  # 记录上次的开始日期
            }
        elif not hasattr(self.custom_repeat_data, 'last_start_date'):
            # 已有设置但没有记录开始日期，添加记录
            self.custom_repeat_data['last_start_date'] = current_start_date
        elif self.custom_repeat_data['last_start_date'] != current_start_date:
            # 开始日期已更改，且用户没有自定义设置过，则更新默认值
            if not self.custom_repeat_data.get('user_modified', False):
                self.custom_repeat_data['byday'] = [self.WEEKDAYS_RRULE[current_weekday]]
                self.custom_repeat_data['bymonthday'] = [str(current_day)]
            self.custom_repeat_data['last_start_date'] = current_start_date

        freq_frame = ttk.LabelFrame(main_frame, text="重复频率")
        freq_frame.pack(fill="x", padx=5, pady=5)

        self.repeat_freq_var = tk.StringVar(value="每周")
        freqs = ["每天", "每周", "每月", "每年"]
        freq_map = {"每天": "DAILY", "每周": "WEEKLY", "每月": "MONTHLY", "每年": "YEARLY"}
        saved_freq = next((k for k, v in freq_map.items() if v == self.custom_repeat_data.get('freq', 'WEEKLY')),
                          "每周")
        self.repeat_freq_var.set(saved_freq)

        for freq in freqs: ttk.Radiobutton(freq_frame, text=freq, variable=self.repeat_freq_var, value=freq).pack(
            anchor="w", padx=5, pady=2)

        interval_frame = ttk.Frame(freq_frame)
        interval_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(interval_frame, text="每").pack(side="left")
        self.interval_var = tk.StringVar(value=self.custom_repeat_data.get('interval', '1'))
        ttk.Spinbox(interval_frame, from_=1, to=365, textvariable=self.interval_var, width=3).pack(side="left", padx=5)
        self.unit_label_var = tk.StringVar(value="周")
        ttk.Label(interval_frame, textvariable=self.unit_label_var).pack(side="left")

        def update_unit(*args):
            freq = self.repeat_freq_var.get()
            if freq == "每天":
                self.unit_label_var.set("天")
            elif freq == "每周":
                self.unit_label_var.set("周")
            elif freq == "每月":
                self.unit_label_var.set("月")
            elif freq == "每年":
                self.unit_label_var.set("年")

        self.repeat_freq_var.trace("w", update_unit)
        update_unit()

        # 每周重复选项
        week_frame = ttk.LabelFrame(main_frame, text="每周几重复 (选择星期)")
        week_frame.pack(fill="x", padx=5, pady=5)

        self.weekday_vars = []
        weekday_frame = ttk.Frame(week_frame)
        weekday_frame.pack(padx=5, pady=5)

        saved_days = self.custom_repeat_data.get('byday', [])
        for i, day in enumerate(self.WEEKDAYS):
            var = tk.BooleanVar()
            if self.WEEKDAYS_RRULE[i] in saved_days: var.set(True)
            self.weekday_vars.append(var)
            cb = ttk.Checkbutton(weekday_frame, text=day, variable=var,
                                 command=lambda: self.custom_repeat_data.update({'user_modified': True}))
            cb.grid(row=i // 4, column=i % 4, sticky="w", padx=10, pady=2)

        # 每月重复选项
        month_frame = ttk.LabelFrame(main_frame, text="每月重复 (选择日期)")
        month_frame.pack(fill="x", padx=5, pady=5)

        self.day_vars = []
        days_frame = ttk.Frame(month_frame)
        days_frame.pack(padx=5, pady=5)

        saved_days = self.custom_repeat_data.get('bymonthday', [])
        for i in range(31):
            var = tk.BooleanVar()
            if str(i + 1) in saved_days: var.set(True)
            self.day_vars.append(var)
            row = i // 7
            col = i % 7
            cb = ttk.Checkbutton(days_frame, text=str(i + 1), variable=var, width=3,
                                 command=lambda: self.custom_repeat_data.update({'user_modified': True}))
            cb.grid(row=row, column=col, padx=2, pady=2)

        def toggle_frames(*args):
            freq = self.repeat_freq_var.get()
            if freq == "每周":
                week_frame.pack(fill="x", padx=5, pady=5)
                month_frame.pack_forget()
            elif freq == "每月":
                week_frame.pack_forget()
                month_frame.pack(fill="x", padx=5, pady=5)
            else:
                week_frame.pack_forget()
                month_frame.pack_forget()

        self.repeat_freq_var.trace("w", toggle_frames)
        toggle_frames()

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(side="bottom", fill="x", pady=10)
        ttk.Button(btn_frame, text="确定", command=lambda: self.save_custom_settings(dialog)).pack(side="right", padx=5)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side="right", padx=5)

    def save_custom_settings(self, dialog):
        freq_map = {"每天": "DAILY", "每周": "WEEKLY", "每月": "MONTHLY", "每年": "YEARLY"}
        self.custom_repeat_data['freq'] = freq_map.get(self.repeat_freq_var.get(), "WEEKLY")
        self.custom_repeat_data['interval'] = self.interval_var.get()

        if self.repeat_freq_var.get() == "每周":
            byday = []
            for i, var in enumerate(self.weekday_vars):
                if var.get(): byday.append(self.WEEKDAYS_RRULE[i])
            self.custom_repeat_data['byday'] = byday
        else:
            self.custom_repeat_data['byday'] = []

        if self.repeat_freq_var.get() == "每月":
            bymonthday = []
            for i, var in enumerate(self.day_vars):
                if var.get(): bymonthday.append(str(i + 1))
            self.custom_repeat_data['bymonthday'] = bymonthday
        else:
            self.custom_repeat_data['bymonthday'] = []

        # 标记为用户已修改过设置
        self.custom_repeat_data['user_modified'] = True

        dialog.destroy()

    def get_local_timezone_id(self):
        """获取本地时区对应的 pytz 时区 ID"""
        try:
            # 获取本地时区对象
            local_tz = get_localzone()
            local_tz_name = str(local_tz)

            # 如果本地时区名称已经是 pytz 支持的时区 ID，直接返回
            if local_tz_name in pytz.all_timezones: return local_tz_name

            # 如果不是标准时区 ID，尝试匹配
            for tz_id in pytz.all_timezones:
                if tz_id.endswith(local_tz_name): return tz_id

            # 如果都匹配不到，使用 UTC 作为备选
            return "UTC"
        except Exception as e:
            print(f"错误: {e}")
            return "UTC"

    def get_timezone_list(self):
        """获取带偏移量的时区列表（使用本地化名称）"""
        timezones = []
        now = datetime.utcnow()

        local_tz_id = self.get_local_timezone_id()

        for tz_id in pytz.all_timezones:
            try:
                tz = pytz.timezone(tz_id)
                offset = tz.utcoffset(now)
                total_seconds = offset.total_seconds()
                hours = int(total_seconds // 3600)
                minutes = int((total_seconds % 3600) // 60)
                sign = '+' if hours >= 0 else '-'
                offset_str = f"UTC{sign}{abs(hours):02d}:{minutes:02d}"

                if '/' in tz_id:
                    city_name = tz_id.split('/')[-1].replace('_', ' ')
                else:
                    city_name = tz_id

                # 获取本地化时区名称
                try:
                    localized_name = get_timezone_name(tz_id,
                                                       locale=locale.getdefaultlocale()[0] if locale.getdefaultlocale()[
                                                           0] else 'en_US')
                except Exception as e:
                    print(f"Error occurred for {tz_id}: {e}")
                    localized_name = tz_id  # 如果获取失败，使用时区 ID 作为默认值

                display = f"{offset_str} - {city_name} ({tz_id}) {localized_name}"

                # 标记本地时区
                if tz_id == local_tz_id: display = f"{display} [本地]"

                timezones.append(display)
            except Exception as e:
                print(f"Error occurred for {tz_id}: {e}")
                continue

        # 按偏移量排序
        timezones.sort()
        return timezones

    def get_local_timezone_str(self):
        """获取本地时区的字符串表示（带偏移量）"""
        try:
            local_tz_id = self.get_local_timezone_id()
            local_tz = pytz.timezone(local_tz_id)

            # 获取当前时间并计算偏移量
            now = datetime.now(local_tz)
            offset = now.utcoffset()
            total_seconds = offset.total_seconds()
            hours = int(total_seconds // 3600)
            minutes = int((total_seconds % 3600) // 60)
            sign = '+' if hours >= 0 else '-'
            offset_str = f"UTC{sign}{abs(hours):02d}:{minutes:02d}"

            # 获取城市名
            if '/' in local_tz_id:
                parts = local_tz_id.split('/')
                city_name = parts[-1].replace('_', ' ')
            else:
                city_name = local_tz_id

            # 获取本地化的时区名称
            try:
                localized_name = get_timezone_name(local_tz_id, locale='zh_CN')
            except:
                localized_name = local_tz_id

            display = f"{offset_str} - {city_name} ({local_tz_id}) {localized_name}"

            # 标记本地时区
            display += " [本地]"

            return display
        except Exception as e:
            logger.error(f"获取本地时区显示字符串失败: {str(e)}")
            return "UTC+00:00 - UTC (UTC) 协调世界时 [本地]"

    def toggle_timezone_sync(self):
        """切换时区同步状态"""
        if self.sync_timezone_var.get() and not self.allday_var.get():
            # 同步时区
            self.end_timezone_var.set(self.start_timezone_var.get())
            self.end_timezone_combo.config(state="disabled")
        else:
            # 不同步时区
            self.end_timezone_combo.config(state="readonly")

    def sync_timezones(self, *args):
        """同步时区"""
        if self.sync_timezone_var.get(): self.end_timezone_var.set(self.start_timezone_var.get())

    def show_raw_data(self):
        """显示事件的原始数据"""
        ical = self.generate_ical()
        if not ical: return

        raw_window = tk.Toplevel(self.root)
        raw_window.title("事件原始数据")
        raw_window.geometry("600x400")

        text_frame = ttk.Frame(raw_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_area = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_area.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_area.yview)

        text_area.insert(tk.END, ical)
        text_area.config(state=tk.DISABLED)

        ttk.Button(raw_window, text="关闭", command=raw_window.destroy).pack(pady=10)

    def add_reminder(self):
        """添加新的提醒"""
        # 获取提醒类型
        reminder_type = self.reminder_type_var.get()

        # 根据触发类型设置提醒
        trigger_type = self.reminder_trigger_type.get()

        if trigger_type == "relative":
            # 相对时间提醒
            days = int(self.reminder_days_var.get())
            hours = int(self.reminder_hours_var.get())
            minutes = int(self.reminder_minutes_var.get())
            trigger = timedelta(days=days, hours=hours, minutes=minutes)
        else:
            # 绝对时间提醒
            date_str = self.absolute_trigger_date.get_date()
            hour = self.absolute_trigger_hour.get()
            minute = self.absolute_trigger_minute.get()

            # 获取时区
            tz_str = self.absolute_trigger_timezone.get().split('(')[-1].split(')')[0]
            tz = pytz.timezone(tz_str) if tz_str else pytz.utc

            # 创建带时区的datetime对象
            trigger = datetime.strptime(f"{date_str} {hour}:{minute}", "%Y-%m-%d %H:%M")
            trigger = tz.localize(trigger)

        # 将中文类型转换为英文
        action_mapping = {"显示": "DISPLAY", "声音": "AUDIO", "邮件": "EMAIL"}
        action = action_mapping.get(reminder_type, "DISPLAY")

        # 获取REPEAT和DURATION值
        repeat = self.reminder_repeat_var.get()
        duration_days = int(self.reminder_duration_days_var.get())
        duration_hours = int(self.reminder_duration_hours_var.get())
        duration_minutes = int(self.reminder_duration_minutes_var.get())

        # 创建持续时间（timedelta）
        duration = timedelta(days=duration_days, hours=duration_hours, minutes=duration_minutes)

        # 添加到提醒列表
        alarm = {
            'action': action,
            'trigger': trigger,
            'repeat': repeat,
            'duration': duration
        }

        # 获取特定类型的额外信息
        if reminder_type == "显示":
            alarm['description'] = self.display_description.get("1.0", "end").strip()
        elif reminder_type == "声音":
            alarm['attach'] = self.audio_attach_var.get()
        elif reminder_type == "邮件":
            alarm['attendee'] = self.email_attendee_var.get()
            alarm['summary'] = self.email_summary_var.get()
            alarm['description'] = self.email_description.get("1.0", "end").strip()
            alarm['attach'] = self.email_attach_var.get()

        self.alarms.append(alarm)

        # 更新提醒列表框
        self.update_reminder_listbox()

    def edit_reminder(self):
        """编辑选中的提醒"""
        selected = self.reminder_listbox.curselection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个提醒")
            return

        index = selected[0]
        alarm = self.alarms[index]

        # 设置触发时间
        if isinstance(alarm['trigger'], timedelta):
            total_seconds = abs(alarm['trigger'].total_seconds())
            days = int(total_seconds // 86400)
            remaining_seconds = total_seconds % 86400
            hours = int(remaining_seconds // 3600)
            minutes = int((remaining_seconds % 3600) // 60)

            self.reminder_days_var.set(str(days))
            self.reminder_hours_var.set(str(hours))
            self.reminder_minutes_var.set(str(minutes))
        else:
            # 处理其他格式
            trigger_str = alarm['trigger']
            if trigger_str.startswith('-P'):
                duration_str = trigger_str[1:]  # 去掉负号
                days = 0
                hours = 0
                minutes = 0

                if 'T' in duration_str:
                    date_part, time_part = duration_str.split('T')
                else:
                    date_part = duration_str
                    time_part = ""

                if 'D' in date_part: days = int(date_part.split('D')[0][1:])

                if time_part:
                    if 'H' in time_part:
                        hours = int(time_part.split('H')[0])
                        time_part = time_part.split('H')[1]
                    if 'M' in time_part:
                        minutes = int(time_part.split('M')[0])

                self.reminder_days_var.set(str(days))
                self.reminder_hours_var.set(str(hours))
                self.reminder_minutes_var.set(str(minutes))

        self.reminder_repeat_var.set(str(alarm.get('repeat', '0')))

        if 'duration' in alarm and isinstance(alarm['duration'], timedelta):
            duration = alarm['duration']
            days = duration.days
            seconds = duration.seconds
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60

            self.reminder_duration_days_var.set(str(days))
            self.reminder_duration_hours_var.set(str(hours))
            self.reminder_duration_minutes_var.set(str(minutes))
        else:
            # 处理其他格式
            duration_str = alarm.get('duration', 'PT15M')
            if duration_str.startswith('P'):
                duration_str = duration_str[1:]
                days = 0
                hours = 0
                minutes = 0

                if 'T' in duration_str:
                    date_part, time_part = duration_str.split('T')
                else:
                    date_part = duration_str
                    time_part = ""

                if 'D' in date_part: days = int(date_part.split('D')[0])

                if time_part:
                    if 'H' in time_part:
                        hours = int(time_part.split('H')[0])
                        time_part = time_part.split('H')[1]
                    if 'M' in time_part:
                        minutes = int(time_part.split('M')[0])

                self.reminder_duration_days_var.set(str(days))
                self.reminder_duration_hours_var.set(str(hours))
                self.reminder_duration_minutes_var.set(str(minutes))

        # 将英文类型转换为中文
        action_mapping = {"DISPLAY": "显示", "AUDIO": "声音", "EMAIL": "邮件"}
        action_zh = action_mapping.get(alarm['action'], "显示")
        self.reminder_type_var.set(action_zh)

        # 设置特定类型的额外信息
        if alarm['action'] == "DISPLAY":
            self.display_description.delete("1.0", "end")
            self.display_description.insert("1.0", alarm.get('description', ''))
        elif alarm['action'] == "AUDIO":
            self.audio_attach_var.set(alarm.get('attach', ''))
        elif alarm['action'] == "EMAIL":
            self.email_attendee_var.set(alarm.get('attendee', ''))
            self.email_summary_var.set(alarm.get('summary', ''))
            self.email_description.delete("1.0", "end")
            self.email_description.insert("1.0", alarm.get('description', ''))
            self.email_attach_var.set(alarm.get('attach', ''))

        # 更新提醒类型相关控件的状态
        self.on_reminder_type_change()

    def delete_reminder(self):
        """删除选中的提醒"""
        selected = self.reminder_listbox.curselection()
        if not selected: return

        index = selected[0]
        self.reminder_listbox.delete(index)
        del self.alarms[index]

    def encode_text(self, text):
        """对文本进行编码处理，防止特殊字符问题"""
        if not text: return ""

        # 检查是否包含非ASCII字符
        if any(ord(char) > 127 for char in text):
            encoded = quopri.encodestring(text.encode('utf-8')).decode('utf-8')
            return f"ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:{encoded}"
        return text

    def decode_text(self, text):
        """解码QUOTED-PRINTABLE编码的文本"""
        if not text: return ""

        # 检查是否包含QUOTED-PRINTABLE编码
        if "ENCODING=QUOTED-PRINTABLE" in text:
            try:
                # 提取编码部分
                encoded_part = text.split(":", 1)[1]
                # 解码QUOTED-PRINTABLE
                decoded_bytes = quopri.decodestring(encoded_part)
                # 尝试UTF-8解码
                return decoded_bytes.decode('utf-8')
            except:
                return text

        return text

    def generate_ical(self):
        """生成iCalendar格式的内容"""
        # 创建日历对象
        version = self.version_var.get()
        cal = vobject.iCalendar()
        cal.add('version').value = version
        cal.add('prodid').value = f"-//{self.software_name}//{self.software_version}//ZH-CN"

        event = cal.add('vevent')
        event.add('uid').value = self.uid_var.get()
        event.add('dtstamp').value = datetime.utcnow()

        summary = self.summary_var.get()
        if summary: event.add('summary').value = self.encode_text(summary)

        status_zh = self.status_var.get()
        status = self.STATUS_MAPPING.get(status_zh, "CONFIRMED")
        event.add('status').value = status

        location = self.location_var.get()
        if location: event.add('location').value = self.encode_text(location)

        description = self.description_text.get("1.0", "end").strip()
        if description: event.add('description').value = self.encode_text(description)

        # 只有状态不是"已取消"时才添加时间信息
        if status_zh != "已取消":
            start_date_obj = self.start_date.get_date()
            end_date_obj = self.end_date.get_date()

            if self.allday_var.get():
                event.add('dtstart').value = start_date_obj
                event.add('dtend').value = end_date_obj
                event.add('X-ALLDAY').value = "1"
                event.add('X-MICROSOFT-CDO-ALLDAYEVENT').value = "TRUE"
            else:
                start_hour = self.start_hour.get()
                start_minute = self.start_minute.get()
                end_hour = self.end_hour.get()
                end_minute = self.end_minute.get()

                try:
                    start_tz_str = self.start_timezone_var.get().split('(')[-1].split(')')[0]
                    if not start_tz_str: start_tz_str = "UTC"
                except:
                    start_tz_str = "UTC"

                try:
                    end_tz_str = self.end_timezone_var.get().split('(')[-1].split(')')[0]
                    if not end_tz_str: end_tz_str = "UTC"
                except:
                    end_tz_str = "UTC"

                start_time = datetime(start_date_obj.year, start_date_obj.month, start_date_obj.day,
                                      int(start_hour), int(start_minute), 0, tzinfo=pytz.timezone(start_tz_str))
                end_time = datetime(end_date_obj.year, end_date_obj.month, end_date_obj.day,
                                    int(end_hour), int(end_minute), 0, tzinfo=pytz.timezone(end_tz_str))

                event.add('dtstart').value = start_time
                event.add('dtend').value = end_time

                if start_tz_str != "UTC": event.dtstart.params['TZID'] = [start_tz_str]
                if end_tz_str != "UTC": event.dtend.params['TZID'] = [end_tz_str]

            repeat_option = self.repeat_var.get()
            if repeat_option != "不重复":
                rrule = self.generate_rrule()
                if rrule: event.add('rrule').value = rrule

            # 只有状态不是"待定"时才添加提醒
            if status_zh != "待定":
                for alarm in self.alarms:
                    valarm = event.add('valarm')
                    valarm.add('action').value = alarm['action']

                    if isinstance(alarm['trigger'], str):
                        if alarm['trigger'].startswith('-P'):
                            duration_str = alarm['trigger'][1:]
                            days = 0
                            hours = 0
                            minutes = 0
                            if 'T' in duration_str:
                                date_part, time_part = duration_str.split('T')
                            else:
                                date_part = duration_str
                                time_part = ""
                            if 'D' in date_part: days = int(date_part.split('D')[0][1:])
                            if time_part:
                                if 'H' in time_part:
                                    hours = int(time_part.split('H')[0])
                                    time_part = time_part.split('H')[1]
                                if 'M' in time_part:
                                    minutes = int(time_part.split('M')[0])
                            valarm.add('trigger').value = timedelta(days=days, hours=hours, minutes=minutes)
                        else:
                            valarm.add('trigger').value = timedelta(minutes=15)
                    elif isinstance(alarm['trigger'], datetime):
                        valarm.add('trigger').value = alarm['trigger']
                        valarm.trigger.params['VALUE'] = ['DATE-TIME']
                    else:
                        valarm.add('trigger').value = alarm['trigger']

                    if 'repeat' in alarm and 'duration' in alarm:
                        repeat = alarm['repeat']
                        duration = alarm['duration']
                        if repeat and int(repeat) > 0 and duration:
                            valarm.add('repeat').value = repeat
                            valarm.add('duration').value = duration

                    if alarm['action'] == "DISPLAY":
                        if 'description' in alarm: valarm.add('description').value = self.encode_text(
                            alarm['description'])
                    elif alarm['action'] == "AUDIO":
                        if 'attach' in alarm: valarm.add('attach').value = alarm['attach']
                    elif alarm['action'] == "EMAIL":
                        if 'attendee' in alarm: valarm.add('attendee').value = alarm['attendee']
                        if 'summary' in alarm: valarm.add('summary').value = self.encode_text(alarm['summary'])
                        if 'description' in alarm: valarm.add('description').value = self.encode_text(
                            alarm['description'])
                        if 'attach' in alarm: valarm.add('attach').value = alarm['attach']

        categories = self.categories_var.get().strip()
        if categories: event.add('categories').value = categories

        priority = str(self.priority_var.get())
        if priority != "0": event.add('priority').value = priority

        transparency_zh = self.transparency_var.get()
        transparency = self.TRANSPARENCY_MAPPING.get(transparency_zh, "OPAQUE")
        event.add('transp').value = transparency

        sequence = self.sequence_var.get()
        if sequence: event.add('sequence').value = sequence

        url = self.url_var.get()
        if url: event.add('url').value = url

        organizer = self.organizer_var.get()
        if organizer: event.add('organizer').value = organizer

        attendees = self.attendee_text.get("1.0", "end").strip().splitlines()
        for attendee in attendees:
            if attendee.strip(): event.add('attendee').value = attendee.strip()

        return cal.serialize()

    def generate_rrule(self):
        """生成重复规则字符串"""
        parts = []
        repeat_option = self.repeat_var.get()

        if repeat_option == "每天":
            parts.append("FREQ=DAILY")
        elif repeat_option == "每周":
            parts.append("FREQ=WEEKLY")
        elif repeat_option == "每两周":
            parts.append("FREQ=WEEKLY;INTERVAL=2")
        elif repeat_option == "每月":
            parts.append("FREQ=MONTHLY")
        elif repeat_option == "每年":
            parts.append("FREQ=YEARLY")
        elif repeat_option == "自定义":
            # 使用自定义设置生成规则
            # 添加频率
            freq = self.custom_repeat_data.get('freq', 'WEEKLY')
            parts.append(f"FREQ={freq}")

            # 添加间隔
            interval = self.custom_repeat_data.get('interval', '1')
            if interval != '1': parts.append(f"INTERVAL={interval}")

            # 添加每周设置
            if freq == 'WEEKLY':
                byday = self.custom_repeat_data.get('byday', [])
                if byday: parts.append(f"BYDAY={','.join(byday)}")

            # 添加每月设置
            if freq == 'MONTHLY':
                bymonthday = self.custom_repeat_data.get('bymonthday', [])
                if bymonthday: parts.append(f"BYMONTHDAY={','.join(bymonthday)}")
        else:
            return ""

        # 添加结束条件
        if self.END_CONDITIONS.index(self.end_cond_var.get()) == 0:
            pass
        elif self.END_CONDITIONS.index(self.end_cond_var.get()) == 1:
            parts.append(f"UNTIL={str(self.end_date_entry.get_date()).replace('-', '')}T000000Z")
        elif self.END_CONDITIONS.index(self.end_cond_var.get()) == 2:
            parts.append(f"COUNT={self.end_count_var.get()}")

        return ";".join(parts)

    def get_raw_ical(self):
        return self.raw_ical

    def save(self):
        ical = self.generate_ical()
        if ical:
            # 在实际应用中，这里可以调用回调函数保存事件
            messagebox.showinfo("保存成功", "事件已成功保存")
            return True
        return False

    def ok(self):
        """确定按钮点击事件"""
        status = self.status_var.get()
        if status == "已取消":
            # 检查是否有时间或提醒设置会被清除
            has_settings = (
                    self.start_date.get_date() != self.original_settings['time']['start_date'] or
                    self.start_hour.get() != self.original_settings['time']['start_hour'] or
                    self.start_minute.get() != self.original_settings['time']['start_minute'] or
                    len(self.alarms) > 0
            )

            if has_settings:
                response = messagebox.askyesno(
                    "警告",
                    "事件状态为'已取消'时，时间设置和提醒设置将被清除。\n确定要继续保存吗？",
                    parent=self.root
                )
                if not response: return

            # 清除设置
            self.alarms = []

        elif status == "待定":
            # 检查是否有提醒设置会被清除
            if len(self.alarms) > 0:
                response = messagebox.askyesno(
                    "警告",
                    "事件状态为'待定'时，提醒设置将被清除。\n确定要继续保存吗？",
                    parent=self.root
                )
                if not response: return

            self.alarms = []

        self.raw_ical = self.generate_ical()
        self.result = {
            'uid': self.uid_var.get(),
            'summary': self.summary_var.get(),
            'start': self.start_date.get_date(),
            'end': self.end_date.get_date()
        }
        self.root.destroy()

    def cancel(self):
        self.result = None
        self.root.destroy()


# ======================
# 主程序入口
# ======================
if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = DAVServerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()