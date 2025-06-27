import base64
import locale
import logging
import os
import queue
import quopri
import re
import sqlite3
import threading
import time
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

# ======================
# 配置日志
# ======================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dav_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


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
        c.execute('''CREATE TABLE IF NOT EXISTS contacts (
                     id INTEGER PRIMARY KEY,
                     uid TEXT UNIQUE,
                     full_name TEXT,
                     email TEXT,
                     phone TEXT,
                     vcard TEXT)''')
        # 日历事件表
        c.execute('''CREATE TABLE IF NOT EXISTS events (
                     id INTEGER PRIMARY KEY,
                     uid TEXT UNIQUE,
                     summary TEXT,
                     dtstart TEXT,
                     dtend TEXT,
                     ical TEXT)''')
        self.conn.commit()

    def add_contact(self, vcard_data):
        with self._lock:
            try:
                # 尝试解析 vCard
                try:
                    vcard = vobject.readOne(vcard_data)
                except Exception as e:
                    logger.warning(f"使用 vobject 解析失败，尝试手动解析: {str(e)}")
                    return self._manual_add_contact(vcard_data)

                # 获取 UID
                uid = getattr(vcard, 'uid', None)
                if uid is None:
                    uid = str(uuid.uuid4())
                    logger.info(f"生成新 UID: {uid}")
                else:
                    uid = uid.value

                # 获取全名
                full_name = ""
                if hasattr(vcard, 'fn'):
                    full_name = vcard.fn.value
                elif hasattr(vcard, 'n'):
                    n = vcard.n.value
                    # 组合 N 属性中的各个部分
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

                # 获取邮箱
                emails = []
                if hasattr(vcard, 'email_list'):
                    for email in vcard.email_list:
                        emails.append(email.value)
                elif hasattr(vcard, 'email'):
                    emails.append(vcard.email.value)

                # 获取电话
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
                    # 检查内容是否相同
                    if existing[0] == vcard_data:
                        operation = "unchanged"
                    else:
                        operation = "updated"

                # 执行数据库操作
                if operation != "unchanged":
                    c.execute('''INSERT OR REPLACE INTO contacts 
                                 (uid, full_name, email, phone, vcard) 
                                 VALUES (?, ?, ?, ?, ?)''',
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
            # 解析 vCard 属性
            properties = {}
            current_property = None

            for line in vcard_data.splitlines():
                line = line.strip()
                if not line:
                    continue

                # 处理多行值
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
                        except:
                            pass

                    properties[name] = {"value": value, "params": params}
                    current_property = name
                else:
                    logger.warning(f"忽略无效行: {line}")

            # 提取关键信息
            uid = properties.get("UID", {}).get("value", str(uuid.uuid4()))
            full_name = properties.get("FN", {}).get("value", "")

            # 处理 N 属性
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

            # 提取邮箱
            emails = []
            for key in properties:
                if key.startswith("EMAIL") or key == "EMAIL":
                    emails.append(properties[key]["value"])

            # 提取电话
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
                # 检查内容是否相同
                if existing[0] == vcard_data:
                    operation = "unchanged"
                else:
                    operation = "updated"

            # 执行数据库操作
            if operation != "unchanged":
                c.execute('''INSERT OR REPLACE INTO contacts 
                             (uid, full_name, email, phone, vcard) 
                             VALUES (?, ?, ?, ?, ?)''',
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
        if not uids:
            return []

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
            # try:
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
                # 检查内容是否相同
                if existing[0] == ical_data:
                    operation = "unchanged"
                else:
                    operation = "updated"

            # 执行数据库操作
            if operation != "unchanged":
                c.execute('''INSERT OR REPLACE INTO events 
                                 (uid, summary, dtstart, dtend, ical) 
                                 VALUES (?, ?, ?, ?, ?)''',
                          (uid, summary, str(dtstart), str(dtend), ical_data))
                self.conn.commit()

            return uid, operation
        # except Exception as e:
        #     self.conn.rollback()
        #     logger.error(f"添加事件失败: {str(e)}")
        #     return None, f"Error: {str(e)}"

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
            return [row[0] for row in c.fetchall()]

    def get_selected_events(self, uids):
        """获取选中的事件数据"""
        if not uids:
            return []

        with self._lock:
            c = self.conn.cursor()
            placeholders = ','.join(['?'] * len(uids))
            c.execute(f"SELECT ical FROM events WHERE uid IN ({placeholders})", uids)
            return [row[0] for row in c.fetchall()]

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
                    self.wfile.write("BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//MyDAVServer//EN\n".encode('utf-8'))
                    for event in all_events:
                        # 去除每个事件的外部VCALENDAR标签
                        event_lines = event.splitlines()
                        if event_lines[0].startswith("BEGIN:VCALENDAR"):
                            event_lines = event_lines[1:-1]  # 去掉第一行和最后一行
                        self.wfile.write("\n".join(event_lines).encode('utf-8'))
                        self.wfile.write(b"\n")
                    self.wfile.write("END:VCALENDAR\n".encode('utf-8'))
                else:
                    self.send_response(404)
                    self.end_headers()

            # 根路径显示服务信息
            elif self.path == "/":
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b"<h1>Private CardDAV/CalDAV Service</h1>")
                self.wfile.write(b"<p>CardDAV endpoint: <a href='/contacts/'>/contacts/</a></p>")
                self.wfile.write(b"<p>CalDAV endpoint: <a href='/events/'>/events/</a></p>")

            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Server error: {str(e)}".encode('utf-8'))
            logger.error(f"GET请求处理失败: {str(e)}")

    def do_PUT(self):
        db = Database()
        try:
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
            self.wfile.write(f"Server error: {str(e)}".encode('utf-8'))
            logger.error(f"PUT请求处理失败: {str(e)}")

    def do_PROPFIND(self):
        try:
            # 简化版PROPFIND响应，仅返回200 OK
            self.send_response(207)
            self.send_header('Content-Type', 'text/xml; charset="utf-8"')
            self.end_headers()

            # 返回一个基本的WebDAV多状态响应
            response = """<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
    <D:response>
        <D:href>{}</D:href>
        <D:propstat>
            <D:prop>
                <D:resourcetype/>
            </D:prop>
            <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
    </D:response>
</D:multistatus>""".format(self.path)

            self.wfile.write(response.encode('utf-8'))
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Server error: {str(e)}".encode('utf-8'))
            logger.error(f"PROPFIND请求处理失败: {str(e)}")

    def do_OPTIONS(self):
        try:
            # 返回服务器支持的HTTP方法
            self.send_response(200)
            self.send_header('Allow', 'OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND')
            self.send_header('DAV', '1, 2')
            self.end_headers()
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Server error: {str(e)}".encode('utf-8'))
            logger.error(f"OPTIONS请求处理失败: {str(e)}")

    def log_message(self, format, *args):
        # 自定义日志输出，避免在控制台打印过多信息
        pass


# ======================
# GUI 应用
# ======================
class DAVServerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("私人 CardDAV/CalDAV 服务")
        self.root.geometry("1000x700")

        # 创建数据库实例
        self.db = Database('dav_data.db')
        self.server = None
        self.server_thread = None
        self.import_queue = queue.Queue()
        self.import_in_progress = False
        self.import_cancel_requested = False

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

        # 开始处理导入队列
        self.root.after(100, self.process_import_queue)

        # 绑定快捷键
        self.root.bind("<Control-a>", self.select_all)
        self.root.bind("<Delete>", self.on_delete_key)

        # 注册文件拖拽事件
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.handle_drop)

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
        files = event.data.split()

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

        columns = ("uid", "name", "email", "phone")
        self.contacts_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings", selectmode="extended"
        )

        self.contacts_tree.heading("uid", text="ID")
        self.contacts_tree.heading("name", text="姓名")
        self.contacts_tree.heading("email", text="邮箱")
        self.contacts_tree.heading("phone", text="电话")

        self.contacts_tree.column("uid", width=100, anchor=tk.CENTER)
        self.contacts_tree.column("name", width=150)
        self.contacts_tree.column("email", width=200)
        self.contacts_tree.column("phone", width=150)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.contacts_tree.yview)
        self.contacts_tree.configure(yscroll=scrollbar.set)

        self.contacts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 添加双击编辑功能
        self.contacts_tree.bind('<Double-1>', self.on_contact_double_click)

        # 绑定Ctrl+A快捷键
        self.contacts_tree.bind("<Control-a>", lambda e: self.select_all(e, self.contacts_tree))

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

        columns = ("uid", "summary", "start", "end")
        self.events_tree = ttk.Treeview(
            list_frame, columns=columns, show="headings", selectmode="extended"
        )

        self.events_tree.heading("uid", text="ID")
        self.events_tree.heading("summary", text="事件")
        self.events_tree.heading("start", text="开始时间")
        self.events_tree.heading("end", text="结束时间")

        self.events_tree.column("uid", width=100, anchor=tk.CENTER)
        self.events_tree.column("summary", width=200)
        self.events_tree.column("start", width=150)
        self.events_tree.column("end", width=150)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.events_tree.yview)
        self.events_tree.configure(yscroll=scrollbar.set)

        self.events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 添加双击编辑功能
        self.events_tree.bind('<Double-1>', self.on_event_double_click)

        # 绑定Ctrl+A快捷键
        self.events_tree.bind("<Control-a>", lambda e: self.select_all(e, self.events_tree))

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

    def select_all(self, event, tree=None):
        """全选当前列表项"""
        if tree is None:
            # 确定当前活动的标签页
            current_tab = self.notebook.select()
            tab_text = self.notebook.tab(current_tab, "text")

            if tab_text == "联系人":
                tree = self.contacts_tree
            elif tab_text == "日历事件":
                tree = self.events_tree
            else:
                return

        items = tree.get_children()
        tree.selection_set(items)
        return "break"  # 阻止默认行为

    def on_contact_double_click(self, event):
        """双击联系人列表项时触发编辑"""
        self.edit_contact()

    def on_event_double_click(self, event):
        """双击事件列表项时触发编辑"""
        self.edit_event()

    def refresh_contacts(self):
        for item in self.contacts_tree.get_children():
            self.contacts_tree.delete(item)

        contacts = self.db.get_contacts()
        for contact in contacts:
            # 确保所有值都是字符串
            contact = [str(item) if item is not None else "" for item in contact]
            self.contacts_tree.insert("", tk.END, values=contact)

        self.update_status_bar()

    def refresh_events(self):
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)

        events = self.db.get_events()
        for event in events:
            # 确保所有值都是字符串
            event = [str(item) if item is not None else "" for item in event]
            self.events_tree.insert("", tk.END, values=event)

        self.update_status_bar()

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
                    self.log_message(f"添加联系人: {dialog.result['name']} ({operation})")
                else:
                    messagebox.showerror("错误", f"添加联系人失败: {operation}")
            except Exception as e:
                messagebox.showerror("错误", f"添加联系人失败: {str(e)}")
                logger.error(f"添加联系人失败: {str(e)}")

    def edit_contact(self):
        selected = self.contacts_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个联系人")
            return

        # 只编辑第一个选中的联系人（双击或单个选择）
        item = self.contacts_tree.item(selected[0])
        # 确保所有值都是字符串
        values = [str(v) if v is not None else "" for v in item['values']]
        uid, name, email, phone = values

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
                    self.log_message(f"更新联系人: {dialog.result['name']} ({operation})")
                else:
                    messagebox.showerror("错误", f"更新联系人失败: {operation}")
            except Exception as e:
                messagebox.showerror("错误", f"更新联系人失败: {str(e)}")
                logger.error(f"更新联系人失败: {str(e)}")

    def delete_contact(self):
        selected = self.contacts_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要删除的联系人")
            return

        # 获取所有选中的联系人
        contacts_to_delete = []
        for item_id in selected:
            item = self.contacts_tree.item(item_id)
            # 确保所有值都是字符串
            values = [str(v) if v is not None else "" for v in item['values']]
            uid, name, email, phone = values
            contacts_to_delete.append((uid, name))

        # 确认删除
        names = ", ".join([name for _, name in contacts_to_delete])
        if messagebox.askyesno("确认删除", f"确定要删除以下联系人吗?\n{names}"):
            success_count = 0
            fail_count = 0

            for uid, name in contacts_to_delete:
                try:
                    if self.db.delete_contact(uid):
                        success_count += 1
                        self.log_message(f"删除联系人: {name}")
                    else:
                        fail_count += 1
                except Exception as e:
                    fail_count += 1
                    self.log_message(f"删除联系人失败: {name} - {str(e)}")

            self.refresh_contacts()
            if fail_count > 0:
                messagebox.showinfo("删除完成",
                                    f"成功删除 {success_count} 个联系人\n失败 {fail_count} 个")
            else:
                messagebox.showinfo("删除完成", f"成功删除 {success_count} 个联系人")

    def show_contact_raw(self):
        selected = self.contacts_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个联系人")
            return

        item = self.contacts_tree.item(selected[0])
        uid = item['values'][0]
        vcard_data = self.db.get_contact(uid)

        self.show_raw_data(vcard_data, "联系人原始数据")

    def export_selected_contacts(self):
        """导出选中的联系人"""
        selected = self.contacts_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择要导出的联系人")
            return

        # 获取选中的UID
        uids = []
        for item_id in selected:
            item = self.contacts_tree.item(item_id)
            uid = item['values'][0]
            uids.append(uid)

        # 获取选中的联系人数据
        contacts = self.db.get_selected_contacts(uids)
        if not contacts:
            messagebox.showerror("错误", "没有找到选中的联系人数据")
            return

        # 询问保存位置
        file_path = filedialog.asksaveasfilename(
            title="保存联系人文件",
            filetypes=[("vCard 文件", "*.vcf")],
            defaultextension=".vcf"
        )
        if not file_path:
            return

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

        # 获取选中的UID
        uids = []
        for item_id in selected:
            item = self.events_tree.item(item_id)
            uid = item['values'][0]
            uids.append(uid)

        # 获取选中的事件数据
        events = self.db.get_selected_events(uids)
        if not events:
            messagebox.showerror("错误", "没有找到选中的事件数据")
            return

        # 询问保存位置
        file_path = filedialog.asksaveasfilename(
            title="保存日历文件",
            filetypes=[("iCalendar 文件", "*.ics")],
            defaultextension=".ics"
        )
        if not file_path:
            return

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//MyDAVServer//EN\n")
                for event in events:
                    # 去除每个事件的外部VCALENDAR标签
                    event_lines = event.splitlines()
                    if event_lines[0].startswith("BEGIN:VCALENDAR"):
                        event_lines = event_lines[1:-1]  # 去掉第一行和最后一行
                    f.write("\n".join(event_lines))
                    f.write("\n")
                f.write("END:VCALENDAR\n")
            messagebox.showinfo("导出成功", f"已成功导出 {len(events)} 个日历事件")
            self.log_message(f"导出事件: {len(events)} 个到 {file_path}")
        except Exception as e:
            messagebox.showerror("导出失败", f"导出日历时出错: {str(e)}")
            logger.error(f"导出日历失败: {str(e)}")

    def import_contacts(self):
        # 创建选择导入方式的对话框
        import_dialog = tk.Toplevel(self.root)
        import_dialog.title("导入联系人")
        import_dialog.geometry("400x200")
        import_dialog.transient(self.root)
        import_dialog.grab_set()

        ttk.Label(import_dialog, text="请选择导入方式:", font=("Arial", 12)).pack(pady=10)

        button_frame = ttk.Frame(import_dialog)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="从文件导入", width=15,
                   command=lambda: self._import_contacts_from_file(import_dialog)).pack(pady=10)
        ttk.Button(button_frame, text="从URL导入", width=15,
                   command=lambda: self._import_contacts_from_url(import_dialog)).pack(pady=10)

    def _import_contacts_from_file(self, dialog=None):
        if dialog:
            dialog.destroy()

        file_paths = filedialog.askopenfilenames(
            title="选择联系人文件",
            filetypes=[("vCard 文件", "*.vcf *.vcard"), ("所有文件", "*.*")]
        )
        if not file_paths:
            return

        self._start_import_contacts(file_paths, "文件")

    def _import_contacts_from_url(self, dialog=None):
        if dialog:
            dialog.destroy()

        url = simpledialog.askstring("从URL导入", "请输入联系人文件的URL:", parent=self.root)
        if not url:
            return

        # 验证URL格式
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            messagebox.showerror("错误", "无效的URL格式")
            return

        self._start_import_contacts([url], "URL")

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

        cancel_btn = ttk.Button(progress_window, text="取消",
                                command=lambda: self.cancel_import(progress_window))
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
        """在后台线程中执行联系人导入"""
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

                # 更新状态
                source_name = os.path.basename(source) if os.path.exists(source) else source
                status_var.set(f"正在处理: {source_name} ({i + 1}/{total_sources})")
                progress_var.set((i / total_sources) * 100)

                try:
                    # 判断是文件还是URL
                    if os.path.exists(source):
                        with open(source, 'r', encoding='utf-8') as f:
                            data = f.read()
                    else:
                        # 从URL下载
                        try:
                            response = requests.get(source, timeout=30)
                            response.raise_for_status()
                            data = response.text
                        except Exception as e:
                            raise Exception(f"下载文件失败: {str(e)}")

                    # 支持多个vCard文件
                    components = list(vobject.readComponents(data))
                    total_contacts = len(components)

                    for j, comp in enumerate(components):
                        if self.import_cancel_requested:
                            status_var.set("导入已取消")
                            return

                        # 更新状态
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
                                error_details = f"未知操作: {operation}"
                                errors.append(error_details)

                            # 更新统计信息
                            self.root.after(0, lambda: self.update_import_stats(
                                inserted_count, updated_count, unchanged_count, error_count))
                        except Exception as e:
                            error_count += 1
                            error_details = f"源: {source_name} - 错误: {str(e)}"
                            errors.append(error_details)
                            error_var.set(error_details)
                            self.log_message(f"导入错误: {error_details}")
                except Exception as e:
                    error_count += 1
                    error_details = f"源: {source_name} - 错误: {str(e)}"
                    errors.append(error_details)
                    error_var.set(error_details)
                    self.log_message(f"导入错误: {error_details}")

            # 导入完成
            progress_var.set(100)
            status_var.set(
                f"导入完成! 新增: {inserted_count}, 更新: {updated_count}, 相同: {unchanged_count}, 失败: {error_count}")

            # 将结果放入队列，在主线程中显示
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
            self.log_message(f"导入过程中发生严重错误: {str(e)}")
            traceback.print_exc()
        finally:
            # 关闭进度窗口
            self.root.after(0, progress_window.destroy)
            self.import_in_progress = False

    def update_import_stats(self, inserted, updated, unchanged, errors):
        """更新导入统计信息"""
        self.inserted_var.set(str(inserted))
        self.updated_var.set(str(updated))
        self.unchanged_var.set(str(unchanged))
        self.error_var.set(str(errors))

    def import_events(self):
        # 创建选择导入方式的对话框
        import_dialog = tk.Toplevel(self.root)
        import_dialog.title("导入日历事件")
        import_dialog.geometry("400x200")
        import_dialog.transient(self.root)
        import_dialog.grab_set()

        ttk.Label(import_dialog, text="请选择导入方式:", font=("Arial", 12)).pack(pady=10)

        button_frame = ttk.Frame(import_dialog)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="从文件导入", width=15,
                   command=lambda: self._import_events_from_file(import_dialog)).pack(pady=10)
        ttk.Button(button_frame, text="从URL导入", width=15,
                   command=lambda: self._import_events_from_url(import_dialog)).pack(pady=10)

    def _import_events_from_file(self, dialog=None):
        if dialog:
            dialog.destroy()

        file_paths = filedialog.askopenfilenames(
            title="选择日历事件文件",
            filetypes=[("iCalendar 文件", "*.ics"), ("所有文件", "*.*")]
        )
        if not file_paths:
            return

        self._start_import_events(file_paths, "文件")

    def _import_events_from_url(self, dialog=None):
        if dialog:
            dialog.destroy()

        url = simpledialog.askstring("从URL导入", "请输入日历文件的URL:", parent=self.root)
        if not url:
            return

        # 验证URL格式
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            messagebox.showerror("错误", "无效的URL格式")
            return

        self._start_import_events([url], "URL")

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
        """在后台线程中执行事件导入"""
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

                # 更新状态
                source_name = os.path.basename(source) if os.path.exists(source) else source
                status_var.set(f"正在处理: {source_name} ({i + 1}/{total_sources})")
                progress_var.set((i / total_sources) * 100)

                try:
                    # 判断是文件还是URL
                    if os.path.exists(source):
                        with open(source, 'r', encoding='utf-8') as f:
                            data = f.read()
                    else:
                        # 从URL下载
                        try:
                            response = requests.get(source, timeout=30)
                            response.raise_for_status()
                            data = response.text
                        except Exception as e:
                            raise Exception(f"下载文件失败: {str(e)}")

                    # 解析日历数据
                    cal = vobject.readOne(data)

                    # 提取所有事件
                    events = [comp for comp in cal.components() if comp.name == 'VEVENT']
                    total_events = len(events)

                    for j, event in enumerate(events):
                        if self.import_cancel_requested:
                            status_var.set("导入已取消")
                            return

                        # 更新状态
                        status_var.set(f"导入: {source_name} - 事件 {j + 1}/{total_events}")
                        progress_var.set((i + (j / total_events)) / total_sources * 100)

                        try:
                            # 为每个事件创建一个新的日历对象
                            new_cal = vobject.iCalendar()
                            new_cal.add(event)
                            ical_str = new_cal.serialize()

                            # 添加到数据库
                            uid, operation = self.db.add_event(ical_str)

                            if operation == "inserted":
                                inserted_count += 1
                            elif operation == "updated":
                                updated_count += 1
                            elif operation == "unchanged":
                                unchanged_count += 1
                            else:
                                error_count += 1
                                error_details = f"未知操作: {operation}"
                                errors.append(error_details)

                            # 更新统计信息
                            self.root.after(0, lambda: self.update_import_stats(
                                inserted_count, updated_count, unchanged_count, error_count))
                        except Exception as e:
                            error_count += 1
                            # 尝试获取事件标题
                            try:
                                summary = event.summary.value
                            except:
                                summary = "未知事件"
                            error_details = f"源: {source_name} - 事件: {summary} - 错误: {str(e)}"
                            errors.append(error_details)
                            error_var.set(error_details)
                            self.log_message(f"导入错误: {error_details}")
                except Exception as e:
                    error_count += 1
                    error_details = f"源: {source_name} - 错误: {str(e)}"
                    errors.append(error_details)
                    error_var.set(error_details)
                    self.log_message(f"导入错误: {error_details}")

            # 导入完成
            progress_var.set(100)
            status_var.set(
                f"导入完成! 新增: {inserted_count}, 更新: {updated_count}, 相同: {unchanged_count}, 失败: {error_count}")

            # 将结果放入队列，在主线程中显示
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
            self.log_message(f"导入过程中发生严重错误: {str(e)}")
            traceback.print_exc()
        finally:
            # 关闭进度窗口
            self.root.after(0, progress_window.destroy)
            self.import_in_progress = False

    def monitor_import_progress(self, progress_var, status_var, error_var, progress_window):
        """监控导入进度并更新UI"""
        if self.import_in_progress:
            # 更新进度条
            progress_window.update()
            # 继续监控
            self.root.after(100, lambda: self.monitor_import_progress(
                progress_var, status_var, error_var, progress_window))
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

                # 显示导入结果
                if result["errors"] == 0:
                    message = f"导入完成!\n新增: {result['inserted']}, 更新: {result['updated']}, 相同: {result['unchanged']}"
                    messagebox.showinfo("导入完成", message)
                else:
                    # 显示详细的错误信息
                    error_msg = f"导入完成!\n新增: {result['inserted']}, 更新: {result['updated']}, 相同: {result['unchanged']}, 失败: {result['errors']}\n\n错误详情:\n"
                    for i, err in enumerate(result["error_list"][:10]):  # 最多显示前10个错误
                        error_msg += f"{i + 1}. {err}\n"

                    if len(result["error_list"]) > 10:
                        error_msg += f"\n...以及另外 {len(result['error_list']) - 10} 条错误"

                    messagebox.showinfo("导入完成", error_msg)

                self.log_message(
                    f"导入{result['type']}: 新增 {result['inserted']}, 更新 {result['updated']}, 相同 {result['unchanged']}, 失败 {result['errors']}")
        except queue.Empty:
            pass

        # 继续检查队列
        self.root.after(500, self.process_import_queue)

    def add_event(self):
        dialog = EventDialog(self.root)
        if dialog.result:
            # try:
            ical = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//MyDAVServer//EN
BEGIN:VEVENT
UID:{dialog.result['uid']}
DTSTAMP:{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}
SUMMARY:{dialog.result['summary']}
DTSTART:{dialog.result['start']}
DTEND:{dialog.result['end']}
LOCATION:{dialog.result.get('location', '')}
DESCRIPTION:{dialog.result.get('description', '')}
END:VEVENT
END:VCALENDAR"""
            uid, operation = self.db.add_event(ical)
            if uid:
                self.refresh_events()
                self.log_message(f"添加事件: {dialog.result['summary']} ({operation})")
            else:
                # messagebox.showerror("错误", f"添加事件失败: {operation}")
                pass
        # except Exception as e:
        #     messagebox.showerror("错误", f"添加事件失败: {str(e)}")
        #     logger.error(f"添加事件失败: {str(e)}")

    def edit_event(self):
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个事件")
            return

        # 只编辑第一个选中的事件（双击或单个选择）
        item = self.events_tree.item(selected[0])
        # 确保所有值都是字符串
        values = [str(v) if v is not None else "" for v in item['values']]
        uid, summary, start, end = values

        # 从数据库获取完整事件数据
        event_data = self.db.get_event(uid)
        location = ""
        description = ""

        if event_data:
            try:
                ical = vobject.readOne(event_data)
                vevent = ical.vevent

                location = vevent.location.value if hasattr(vevent, 'location') else ""
                description = vevent.description.value if hasattr(vevent, 'description') else ""
            except Exception as e:
                self.log_message(f"解析事件错误: {str(e)}")
                logger.error(f"解析事件错误: {str(e)}")

        dialog = EventDialog(self.root, initial={
            'uid': uid,
            'summary': summary,
            'start': start,
            'end': end,
            'location': location,
            'description': description
        })

        if dialog.result:
            # try:
            ical = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//MyDAVServer//EN
BEGIN:VEVENT
UID:{dialog.result['uid']}
DTSTAMP:{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}
SUMMARY:{dialog.result['summary']}
DTSTART:{dialog.result['start']}
DTEND:{dialog.result['end']}
LOCATION:{dialog.result.get('location', '')}
DESCRIPTION:{dialog.result.get('description', '')}
END:VEVENT
END:VCALENDAR"""
            uid, operation = self.db.add_event(ical)
            if uid:
                self.refresh_events()
                self.log_message(f"更新事件: {dialog.result['summary']} ({operation})")
            else:
                messagebox.showerror("错误", f"更新事件失败: {operation}")
        # except Exception as e:
        #     messagebox.showerror("错误", f"更新事件失败: {str(e)}")
        #     logger.error(f"更新事件失败: {str(e)}")

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
            uid, summary, start, end = values
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
                        self.log_message(f"删除事件: {summary}")
                    else:
                        fail_count += 1
                except Exception as e:
                    fail_count += 1
                    self.log_message(f"删除事件失败: {summary} - {str(e)}")

            self.refresh_events()
            if fail_count > 0:
                messagebox.showinfo("删除完成",
                                    f"成功删除 {success_count} 个事件\n失败 {fail_count} 个")
            else:
                messagebox.showinfo("删除完成", f"成功删除 {success_count} 个事件")

    def show_event_raw(self):
        selected = self.events_tree.selection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个事件")
            return

        item = self.events_tree.item(selected[0])
        uid = item['values'][0]
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
        class CustomHandler(SimpleDAVHandler):
            pass

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

        self.log_message(f"服务器启动: 端口 {port}")
        logger.info(f"服务器启动: 端口 {port}")

    def stop_server(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join()
            self.server = None
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

            # 更新日志
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, "服务器已停止\n")
            self.log_text.config(state=tk.DISABLED)

            self.log_message("服务器已停止")
            logger.info("服务器已停止")

    def log_message(self, message):
        timestamp = time.strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        # 输出到GUI日志
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_line + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        # 输出到控制台（通过logging）
        logger.info(message)

    def on_closing(self):
        if self.server:
            self.stop_server()
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
            # 生成唯一ID
            uid = f"contact-{int(datetime.now().timestamp())}"
            self.uid_entry.insert(0, uid)

        # 添加更多字段按钮
        if self.vcard:
            ttk.Button(self, text="显示完整 vCard", command=self.show_full_vcard).pack(pady=5)

        # 添加按钮
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
        if not self.vcard:
            return

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
        if not uid:
            missing_fields.append("UID")
        if not name:
            missing_fields.append("姓名")

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
    REPEAT_OPTIONS = [
        "不重复",
        "每天",
        "每周",
        "每两周",
        "每月",
        "每年",
        "自定义"
    ]

    # 星期选项
    WEEKDAYS = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
    WEEKDAYS_RRULE = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"]

    # 结束条件选项
    END_CONDITIONS = ["永不结束", "按日期结束", "按次数结束"]

    def __init__(self, parent, initial=None, software_name="PrivateDAV", software_version="1.0"):
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
        self.repeat_days = []  # 存储重复的星期几
        self.end_count_var = tk.StringVar(value="5")  # 默认重复5次

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

        # 配置网格权重
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        # UID
        ttk.Label(frame, text="事件ID:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.uid_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.uid_var, width=40).grid(row=0, column=1, columnspan=3, sticky="we", padx=5,
                                                                   pady=5)

        # 摘要
        ttk.Label(frame, text="事件标题*:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.summary_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.summary_var, width=40).grid(row=1, column=1, columnspan=3, sticky="we",
                                                                       padx=5, pady=5)

        # 地点
        ttk.Label(frame, text="地点:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.location_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.location_var, width=40).grid(row=2, column=1, columnspan=3, sticky="we",
                                                                        padx=5, pady=5)

        # 描述
        ttk.Label(frame, text="描述:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.description_text = tk.Text(frame, height=5, width=50)
        self.description_text.grid(row=3, column=1, columnspan=3, sticky="nsew", padx=5, pady=5)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(frame, command=self.description_text.yview)
        scrollbar.grid(row=3, column=4, sticky="ns")
        self.description_text.config(yscrollcommand=scrollbar.set)

        # 状态 - 使用中文选项
        ttk.Label(frame, text="事件状态:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.status_var = tk.StringVar()
        status_options = ["待定", "已确认", "已取消"]
        ttk.Combobox(frame, textvariable=self.status_var, values=status_options, width=15, state="readonly").grid(
            row=4, column=1, sticky="w", padx=5, pady=5)

        # 日历版本
        ttk.Label(frame, text="日历版本:").grid(row=4, column=2, sticky="e", padx=5, pady=5)
        self.version_var = tk.StringVar(value="2.0")
        version_options = ["1.0", "2.0", "2.1", "3.0"]
        ttk.Combobox(frame, textvariable=self.version_var, values=version_options, width=8, state="readonly").grid(
            row=4, column=3, sticky="w", padx=5, pady=5)

    def create_time_tab(self):
        frame = ttk.LabelFrame(self.time_frame, text="时间设置")
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # 配置网格权重
        frame.columnconfigure(1, weight=1)

        # 全天事件
        self.allday_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="全天事件", variable=self.allday_var).grid(
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

        # 结束时间 - 使用框架组织
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
        ttk.Checkbutton(frame, text="结束时间使用相同时区", variable=self.sync_timezone_var,
                        command=self.toggle_timezone_sync).grid(row=5, column=0, columnspan=3, sticky="w", padx=5,
                                                                pady=5)

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
        repeat_combo = ttk.Combobox(repeat_frame, textvariable=self.repeat_var,
                                    values=self.REPEAT_OPTIONS, width=10, state="readonly")
        repeat_combo.grid(row=0, column=0, sticky="w")

        # 当选择"自定义"时，显示详细设置按钮
        self.custom_repeat_btn = ttk.Button(repeat_frame, text="详细设置...",
                                            command=self.custom_repeat_settings, state="disabled")
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
            ttk.Radiobutton(self.end_cond_frame, text=option, variable=self.end_cond_var, value=option).grid(
                row=0, column=i, padx=(0, 10), sticky="w")

        # 结束日期/次数输入
        self.end_input_frame = ttk.Frame(frame)
        self.end_input_frame.grid(row=8, column=1, columnspan=2, sticky="w", padx=5, pady=5)

        # 初始隐藏
        self.end_input_frame.grid_remove()

        # 根据重复规则更新结束条件状态
        self.on_repeat_changed()

    def on_end_cond_changed(self, *args):
        """当结束条件改变时更新UI"""
        self.update_end_condition_input(self.end_cond_var.get())

    def create_reminder_tab(self):
        frame = ttk.LabelFrame(self.reminder_frame, text="提醒设置")
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # 配置网格权重
        frame.columnconfigure(1, weight=1)

        # 提醒列表框架
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

        # 提醒类型
        ttk.Label(frame, text="提醒类型:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.reminder_type_var = tk.StringVar(value="显示")
        reminder_types = ["显示", "声音", "邮件"]
        ttk.Combobox(frame, textvariable=self.reminder_type_var, values=reminder_types, width=10,
                     state="readonly").grid(
            row=1, column=1, sticky="w", padx=5, pady=5)

        # 提醒时间
        ttk.Label(frame, text="提前时间:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.reminder_time_frame = ttk.Frame(frame)
        self.reminder_time_frame.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        self.reminder_days_var = tk.StringVar(value="0")
        ttk.Label(self.reminder_time_frame, text="天:").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=365, textvariable=self.reminder_days_var, width=3).grid(
            row=0, column=1, padx=(5, 10))

        self.reminder_hours_var = tk.StringVar(value="0")
        ttk.Label(self.reminder_time_frame, text="小时:").grid(row=0, column=2, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=23, textvariable=self.reminder_hours_var, width=3).grid(
            row=0, column=3, padx=(5, 10))

        self.reminder_minutes_var = tk.StringVar(value="15")
        ttk.Label(self.reminder_time_frame, text="分钟:").grid(row=0, column=4, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=59, textvariable=self.reminder_minutes_var, width=3).grid(
            row=0, column=5, padx=5)

        # 强制提醒
        self.force_reminder_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="强制提醒", variable=self.force_reminder_var).grid(
            row=3, column=0, columnspan=2, sticky="w", padx=5, pady=10)

    def create_advanced_tab(self):
        frame = ttk.LabelFrame(self.advanced_frame, text="高级设置")
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # 配置网格权重
        frame.columnconfigure(1, weight=1)

        # 分类
        ttk.Label(frame, text="分类:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.categories_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.categories_var, width=30).grid(
            row=0, column=1, sticky="we", padx=5, pady=5)

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
        ttk.Combobox(frame, textvariable=self.transparency_var, values=transparencies,
                     width=15, state="readonly").grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # 序列号
        ttk.Label(frame, text="序列号:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.sequence_var = tk.StringVar(value="0")
        ttk.Entry(frame, textvariable=self.sequence_var, width=10).grid(
            row=3, column=1, sticky="w", padx=5, pady=5)

        # URL
        ttk.Label(frame, text="URL:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.url_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.url_var, width=30).grid(
            row=4, column=1, sticky="we", padx=5, pady=5)

        # 组织者
        ttk.Label(frame, text="组织者:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
        self.organizer_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.organizer_var, width=30).grid(
            row=5, column=1, sticky="we", padx=5, pady=5)

        # 参与者
        ttk.Label(frame, text="参与者:").grid(row=6, column=0, sticky="nw", padx=5, pady=5)
        self.attendee_text = tk.Text(frame, height=3, width=40)
        self.attendee_text.grid(row=6, column=1, sticky="nsew", padx=5, pady=5)

        # 添加滚动条
        scrollbar = ttk.Scrollbar(frame, command=self.attendee_text.yview)
        scrollbar.grid(row=6, column=2, sticky="ns")
        self.attendee_text.config(yscrollcommand=scrollbar.set)

    def set_initial_values(self):
        # 获取本地时区 ID
        local_tz_id = self.get_local_timezone_id()

        # 查找本地时区在列表中的显示字符串
        local_tz_display = None
        for tz_display in self.start_timezone_combo['values']:
            if local_tz_id in tz_display:
                local_tz_display = tz_display
                break

        # 设置默认时区
        if local_tz_display:
            self.start_timezone_var.set(local_tz_display)
            self.end_timezone_var.set(local_tz_display)
        else:
            # 如果找不到，使用 UTC
            for tz_display in self.start_timezone_combo['values']:
                if "UTC" in tz_display:
                    self.start_timezone_var.set(tz_display)
                    self.end_timezone_var.set(tz_display)
                    break
        # 如果有初始数据，填充表单
        if self.initial:
            self.uid_var.set(self.initial.get('uid', f"event-{uuid.uuid4().hex}"))
            self.summary_var.set(self.initial.get('summary', ''))
            self.location_var.set(self.initial.get('location', ''))

            if 'description' in self.initial:
                self.description_text.insert("1.0", self.initial['description'])

            # 状态转换（英文->中文）
            status_en = self.initial.get('status', 'CONFIRMED')
            status_zh = next((k for k, v in self.STATUS_MAPPING.items() if v == status_en), "已确认")
            self.status_var.set(status_zh)

            self.version_var.set(self.initial.get('version', '2.0'))
            self.allday_var.set(self.initial.get('allday', False))

            # 设置时间
            if 'start' in self.initial:
                try:
                    if self.initial['start']:
                        start_dt = parser.parse(self.initial['start'])
                        self.start_date.set_date(start_dt.strftime("%Y-%m-%d"))
                        self.start_hour.set(start_dt.strftime("%H"))
                        self.start_minute.set(start_dt.strftime("%M"))

                        # 获取时区信息
                        if start_dt.tzinfo:
                            tz_name = start_dt.tzinfo.tzname(start_dt)
                            # 在列表中找到匹配项（使用括号内的部分）
                            for option in self.start_timezone_combo['values']:
                                if tz_name in option.split('(')[-1]:
                                    self.start_timezone_var.set(option)
                                    break
                except Exception as e:
                    logger.error(f"解析开始时间错误: {str(e)}")

            if 'end' in self.initial:
                try:
                    # 确保有结束时间值
                    if self.initial['end']:
                        end_dt = parser.parse(self.initial['end'])
                        self.end_date.set_date(end_dt.strftime("%Y-%m-%d"))
                        self.end_hour.set(end_dt.strftime("%H"))
                        self.end_minute.set(end_dt.strftime("%M"))

                        # 获取时区信息
                        if end_dt.tzinfo:
                            tz_name = end_dt.tzinfo.tzname(end_dt)
                            # 在列表中找到匹配项
                            for option in self.end_timezone_combo['values']:
                                if tz_name in option:
                                    self.end_timezone_var.set(option)
                                    break
                except Exception as e:
                    logger.error(f"解析结束时间错误: {str(e)}")
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
            if 'end_date' in self.initial:
                self.end_date_entry.set_date(self.initial['end_date'])
            if 'end_count' in self.initial:
                self.end_count_var.set(str(self.initial['end_count']))

            # 设置重复规则
            rrule = self.initial.get('rrule', '')
            if rrule:
                # 简单解析重复规则
                if 'FREQ=DAILY' in rrule:
                    self.repeat_var.set('每天')
                elif 'FREQ=WEEKLY' in rrule:
                    if 'INTERVAL=2' in rrule:
                        self.repeat_var.set('每两周')
                    else:
                        self.repeat_var.set('每周')
                elif 'FREQ=MONTHLY' in rrule:
                    self.repeat_var.set('每月')
                elif 'FREQ=YEARLY' in rrule:
                    self.repeat_var.set('每年')
                else:
                    self.repeat_var.set('自定义')
                    self.custom_repeat_btn.config(state="normal")
            else:
                self.repeat_var.set('不重复')

            # 设置结束条件
            if 'UNTIL=' in rrule:
                self.end_cond_var.set('按日期结束')
                # 尝试解析结束日期
                try:
                    until_str = rrule.split('UNTIL=')[1].split(';')[0]
                    until_date = parser.parse(until_str).strftime("%Y-%m-%d")
                    self.end_date_entry.set_date(until_date)
                except:
                    pass
            elif 'COUNT=' in rrule:
                self.end_cond_var.set('按次数结束')
                try:
                    count = rrule.split('COUNT=')[1].split(';')[0]
                    self.end_count_var.set(count)
                except:
                    pass

            # 提醒设置
            self.force_reminder_var.set(self.initial.get('force_reminder', False))

            # 高级设置
            self.categories_var.set(self.initial.get('categories', ''))

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

            if 'attendees' in self.initial:
                self.attendee_text.insert("1.0", "\n".join(self.initial['attendees']))

            # 提醒列表
            if 'alarms' in self.initial:
                self.alarms = self.initial['alarms']
                for alarm in self.alarms:
                    trigger = alarm.get('trigger', '')
                    action = alarm.get('action', 'DISPLAY')

                    # 将英文类型转换为中文
                    action_mapping = {"DISPLAY": "显示", "AUDIO": "声音", "EMAIL": "邮件"}
                    action_zh = action_mapping.get(action, "显示")

                    # 解析触发时间
                    time_str = ""
                    if trigger.startswith('-PT'):
                        time_str = trigger[3:]  # 去掉 -PT
                        if time_str.endswith('M'):
                            time_str = time_str[:-1] + "分钟"
                        elif time_str.endswith('H'):
                            time_str = time_str[:-1] + "小时"
                        elif time_str.endswith('D'):
                            time_str = time_str[:-1] + "天"

                    self.reminder_listbox.insert("end", f"{action_zh} - 提前{time_str}")
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

            # 设置默认时区
            local_tz_str = self.get_local_timezone_str()
            self.start_timezone_var.set(local_tz_str)
            self.end_timezone_var.set(local_tz_str)
            self.sync_timezone_var.set(True)

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
            for widget in self.end_cond_frame.winfo_children():
                widget.config(state="disabled")
            self.end_input_frame.grid_remove()
        else:
            # 启用结束条件选项
            for widget in self.end_cond_frame.winfo_children():
                widget.config(state="normal")
            self.update_end_condition_input(self.end_cond_var.get())

        # 更新结束条件输入框
        self.update_end_condition_input(self.end_cond_var.get())

    def update_end_condition_input(self, end_cond):
        """根据结束条件显示相应的输入控件"""
        # 清除现有控件
        for widget in self.end_input_frame.winfo_children():
            widget.destroy()

        if end_cond == "按日期结束":
            self.end_input_frame.grid()
            ttk.Label(self.end_input_frame, text="结束日期:").grid(row=0, column=0, padx=(0, 5))
            self.end_date_entry = DateEntry(self.end_input_frame, date_pattern='yyyy-mm-dd', width=12)
            self.end_date_entry.grid(row=0, column=1)
        elif end_cond == "按次数结束":
            self.end_input_frame.grid()
            ttk.Label(self.end_input_frame, text="重复次数:").grid(row=0, column=0, padx=(0, 5))
            # 使用 self.end_count_var
            ttk.Entry(self.end_input_frame, textvariable=self.end_count_var, width=5).grid(row=0, column=1)
            ttk.Label(self.end_input_frame, text="次").grid(row=0, column=2, padx=(5, 0))
        else:
            self.end_input_frame.grid_remove()

    def custom_repeat_settings(self):
        """打开自定义重复设置对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("自定义重复设置")
        dialog.geometry("500x450")
        dialog.transient(self.root)
        dialog.grab_set()

        # 主框架
        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # 创建自定义设置数据结构（如果不存在）
        if not hasattr(self, 'custom_repeat_data'):
            self.custom_repeat_data = {
                'freq': 'WEEKLY',  # 默认每周
                'interval': '1',  # 默认间隔1
                'byday': [],  # 选择的星期
                'bymonthday': []  # 选择的月份日期
            }

        # 频率设置
        freq_frame = ttk.LabelFrame(main_frame, text="重复频率")
        freq_frame.pack(fill="x", padx=5, pady=5)

        self.repeat_freq_var = tk.StringVar(value="每周")
        freqs = ["每天", "每周", "每月", "每年"]
        freq_map = {"每天": "DAILY", "每周": "WEEKLY", "每月": "MONTHLY", "每年": "YEARLY"}

        # 加载保存的频率
        saved_freq = next((k for k, v in freq_map.items() if v == self.custom_repeat_data.get('freq', 'WEEKLY')),
                          "每周")
        self.repeat_freq_var.set(saved_freq)

        for freq in freqs:
            ttk.Radiobutton(freq_frame, text=freq, variable=self.repeat_freq_var, value=freq).pack(
                anchor="w", padx=5, pady=2)

        # 间隔设置
        interval_frame = ttk.Frame(freq_frame)
        interval_frame.pack(fill="x", padx=5, pady=5)

        ttk.Label(interval_frame, text="每").pack(side="left")
        self.interval_var = tk.StringVar(value=self.custom_repeat_data.get('interval', '1'))
        ttk.Spinbox(interval_frame, from_=1, to=365, textvariable=self.interval_var, width=3).pack(side="left", padx=5)

        # 动态更新单位标签
        self.unit_label_var = tk.StringVar(value="周")
        ttk.Label(interval_frame, textvariable=self.unit_label_var).pack(side="left")

        # 根据频率更新单位
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
        update_unit()  # 初始调用

        # 每周设置
        week_frame = ttk.LabelFrame(main_frame, text="每周重复 (选择星期)")
        week_frame.pack(fill="x", padx=5, pady=5)

        self.weekday_vars = []
        weekday_frame = ttk.Frame(week_frame)
        weekday_frame.pack(padx=5, pady=5)

        # 加载保存的星期设置
        saved_days = self.custom_repeat_data.get('byday', [])

        for i, day in enumerate(self.WEEKDAYS):
            var = tk.BooleanVar()
            # 检查是否已保存
            if self.WEEKDAYS_RRULE[i] in saved_days:
                var.set(True)
            self.weekday_vars.append(var)
            cb = ttk.Checkbutton(weekday_frame, text=day, variable=var)
            cb.grid(row=i // 4, column=i % 4, sticky="w", padx=10, pady=2)

        # 每月设置
        month_frame = ttk.LabelFrame(main_frame, text="每月重复 (选择日期)")
        month_frame.pack(fill="x", padx=5, pady=5)

        # 创建1-31的复选框，每行7个
        self.day_vars = []
        days_frame = ttk.Frame(month_frame)
        days_frame.pack(padx=5, pady=5)

        # 加载保存的日期设置
        saved_days = self.custom_repeat_data.get('bymonthday', [])

        for i in range(31):
            var = tk.BooleanVar()
            # 检查是否已保存
            if str(i + 1) in saved_days:
                var.set(True)
            self.day_vars.append(var)
            row = i // 7
            col = i % 7
            cb = ttk.Checkbutton(days_frame, text=str(i + 1), variable=var, width=3)
            cb.grid(row=row, column=col, padx=2, pady=2)

        # 根据频率显示/隐藏相关框架
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
        toggle_frames()  # 初始调用

        # 按钮框架（放在底部）
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(side="bottom", fill="x", pady=10)

        ttk.Button(btn_frame, text="确定",
                   command=lambda: self.save_custom_settings(dialog)).pack(side="right", padx=5)
        ttk.Button(btn_frame, text="取消",
                   command=dialog.destroy).pack(side="right", padx=5)

    def save_custom_settings(self, dialog):
        """保存自定义重复设置"""
        # 保存频率和间隔
        freq_map = {
            "每天": "DAILY",
            "每周": "WEEKLY",
            "每月": "MONTHLY",
            "每年": "YEARLY"
        }
        self.custom_repeat_data['freq'] = freq_map.get(self.repeat_freq_var.get(), "WEEKLY")
        self.custom_repeat_data['interval'] = self.interval_var.get()

        # 保存每周设置
        if self.repeat_freq_var.get() == "每周":
            byday = []
            for i, var in enumerate(self.weekday_vars):
                if var.get():
                    byday.append(self.WEEKDAYS_RRULE[i])
            self.custom_repeat_data['byday'] = byday
        else:
            self.custom_repeat_data['byday'] = []

        # 保存每月设置
        if self.repeat_freq_var.get() == "每月":
            bymonthday = []
            for i, var in enumerate(self.day_vars):
                if var.get():
                    bymonthday.append(str(i + 1))
            self.custom_repeat_data['bymonthday'] = bymonthday
        else:
            self.custom_repeat_data['bymonthday'] = []

        dialog.destroy()

    def update_end_condition_custom(self, dialog):
        """更新自定义对话框中的结束条件输入"""
        # 清除现有控件
        for widget in self.end_input_custom_frame.winfo_children():
            widget.destroy()

        end_cond = self.end_cond_custom_var.get()

        if end_cond == "按日期结束":
            ttk.Label(self.end_input_custom_frame, text="结束日期:").grid(row=0, column=0, padx=(0, 5))
            self.end_date_custom = DateEntry(self.end_input_custom_frame, date_pattern='yyyy-mm-dd', width=12)
            self.end_date_custom.grid(row=0, column=1)
        elif end_cond == "按次数结束":
            ttk.Label(self.end_input_custom_frame, text="重复次数:").grid(row=0, column=0, padx=(0, 5))
            self.end_count_custom_var = tk.StringVar(value="5")
            ttk.Entry(self.end_input_custom_frame, textvariable=self.end_count_custom_var, width=5).grid(row=0,
                                                                                                         column=1)
            ttk.Label(self.end_input_custom_frame, text="次").grid(row=0, column=2, padx=(5, 0))

    def get_local_timezone_id(self):
        """获取本地时区对应的 pytz 时区 ID"""
        try:
            # 获取本地时区对象
            local_tz = get_localzone()
            local_tz_name = str(local_tz)

            # 如果本地时区名称已经是 pytz 支持的时区 ID，直接返回
            if local_tz_name in pytz.all_timezones:
                return local_tz_name

            # 如果不是标准时区 ID，尝试匹配
            for tz_id in pytz.all_timezones:
                if tz_id.endswith(local_tz_name):
                    return tz_id

            # 如果都匹配不到，使用 UTC 作为备选
            return "UTC"
        except Exception as e:
            print(f"Error occurred: {e}")
            return "UTC"

    def get_timezone_list(self):
        """获取带偏移量的时区列表（使用本地化名称）"""
        timezones = []
        now = datetime.utcnow()

        # 获取本地时区 ID
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

                # 提取城市名称
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

                # 创建显示字符串
                display = f"{offset_str} - {city_name} ({tz_id}) {localized_name}"

                # 标记本地时区
                if tz_id == local_tz_id:
                    display = f"{display} [本地]"

                timezones.append(display)
            except Exception as e:
                print(f"Error occurred for {tz_id}: {e}")
                continue

        # 按偏移量排序
        timezones.sort()
        return timezones

    def get_local_timezone_str(self):
        """获取本地时区的字符串表示（带偏移量）"""
        local_tz = datetime.now().astimezone().tzinfo
        now = datetime.utcnow()
        offset = local_tz.utcoffset(now)
        total_seconds = offset.total_seconds()
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        sign = '+' if hours >= 0 else '-'
        offset_str = f"UTC{sign}{abs(hours):02d}:{minutes:02d}"
        return f"{offset_str} - {local_tz}"

    def toggle_timezone_sync(self):
        """切换时区同步状态"""
        if self.sync_timezone_var.get():
            # 同步时区
            self.end_timezone_var.set(self.start_timezone_var.get())
            self.end_timezone_combo.config(state="disabled")
        else:
            # 不同步时区
            self.end_timezone_combo.config(state="readonly")

    def sync_timezones(self, *args):
        """同步时区"""
        if self.sync_timezone_var.get():
            self.end_timezone_var.set(self.start_timezone_var.get())

    def show_raw_data(self):
        """显示事件的原始数据"""
        ical = self.generate_ical()
        if not ical:
            return

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
        days = int(self.reminder_days_var.get() or 0)
        hours = int(self.reminder_hours_var.get() or 0)
        minutes = int(self.reminder_minutes_var.get() or 0)

        # 将中文类型转换为英文
        action_zh = self.reminder_type_var.get()
        action_mapping = {"显示": "DISPLAY", "声音": "AUDIO", "邮件": "EMAIL"}
        action = action_mapping.get(action_zh, "DISPLAY")

        # 创建触发时间字符串 (ISO 8601格式)
        trigger_parts = []
        if days > 0:
            trigger_parts.append(f"{days}D")
        if hours > 0:
            trigger_parts.append(f"{hours}H")
        if minutes > 0:
            trigger_parts.append(f"{minutes}M")

        trigger_str = "PT" + "".join(trigger_parts)
        trigger = f"-{trigger_str}"  # 负号表示提前

        # 添加到提醒列表
        alarm = {'action': action, 'trigger': trigger}
        self.alarms.append(alarm)

        # 创建显示文本
        time_parts = []
        if days > 0:
            time_parts.append(f"{days}天")
        if hours > 0:
            time_parts.append(f"{hours}小时")
        if minutes > 0:
            time_parts.append(f"{minutes}分钟")

        display_time = "".join(time_parts) or "0分钟"
        self.reminder_listbox.insert("end", f"{action_zh} - 提前{display_time}")

    def edit_reminder(self):
        """编辑选中的提醒"""
        selected = self.reminder_listbox.curselection()
        if not selected:
            messagebox.showinfo("提示", "请先选择一个提醒")
            return

        index = selected[0]
        alarm = self.alarms[index]

        # 解析触发时间
        trigger = alarm['trigger']
        match = re.match(r"-PT(\d+)M", trigger)
        if match:
            total_minutes = int(match.group(1))
            hours, minutes = divmod(total_minutes, 60)
            days, hours = divmod(hours, 24)

            self.reminder_days_var.set(str(days))
            self.reminder_hours_var.set(str(hours))
            self.reminder_minutes_var.set(str(minutes))

        # 将英文类型转换为中文
        action_mapping = {"DISPLAY": "显示", "AUDIO": "声音", "EMAIL": "邮件"}
        action_zh = action_mapping.get(alarm['action'], "显示")
        self.reminder_type_var.set(action_zh)

        # 删除原有提醒
        self.delete_reminder()

        # 添加更新后的提醒
        self.add_reminder()

    def delete_reminder(self):
        """删除选中的提醒"""
        selected = self.reminder_listbox.curselection()
        if not selected:
            return

        index = selected[0]
        self.reminder_listbox.delete(index)
        del self.alarms[index]

    def encode_text(self, text):
        """对文本进行编码处理，防止特殊字符问题"""
        if not text:
            return ""

        # 检查是否包含非ASCII字符
        if any(ord(char) > 127 for char in text):
            encoded = quopri.encodestring(text.encode('utf-8')).decode('ascii')
            return f"ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:{encoded}"
        return text

    def generate_ical(self):
        """生成iCalendar格式的内容"""
        # 创建日历对象
        version = self.version_var.get()
        cal = vobject.iCalendar()
        cal.add('version').value = version
        cal.add('prodid').value = f"-//{self.software_name}//{self.software_version}//EN"

        # 创建事件
        event = cal.add('vevent')

        # 设置事件基本属性
        event.add('uid').value = self.uid_var.get()
        event.add('dtstamp').value = datetime.utcnow()

        # 编码并设置摘要、地点和描述
        summary = self.summary_var.get()
        if summary:
            event.add('summary').value = self.encode_text(summary)

        location = self.location_var.get()
        if location:
            event.add('location').value = self.encode_text(location)

        description = self.description_text.get("1.0", "end").strip()
        if description:
            event.add('description').value = self.encode_text(description)

        # 设置状态（中文->英文）
        status_zh = self.status_var.get()
        status = self.STATUS_MAPPING.get(status_zh, "CONFIRMED")
        event.add('status').value = status

        # 设置开始和结束时间
        start_date_str = self.start_date.get_date()
        end_date_str = self.end_date.get_date()

        # 修复日期格式问题 - 使用正确的 iCalendar 格式
        if self.allday_var.get():
            # 全天事件 - 使用日期对象 (YYYYMMDD 格式)
            start_date_fixed = start_date_str.replace("-", "")
            end_date_fixed = end_date_str.replace("-", "")
            event.add('dtstart').value = start_date_fixed
            event.add('dtend').value = end_date_fixed
        else:
            # 带时间的事件
            start_hour = self.start_hour.get()
            start_minute = self.start_minute.get()
            end_hour = self.end_hour.get()
            end_minute = self.end_minute.get()

            # 获取开始和结束时区名称
            try:
                start_tz_str = self.start_timezone_var.get().split('(')[-1].split(')')[0]
                if not start_tz_str or start_tz_str == "":
                    start_tz_str = "UTC"
            except:
                start_tz_str = "UTC"

            try:
                end_tz_str = self.end_timezone_var.get().split('(')[-1].split(')')[0]
                if not end_tz_str or end_tz_str == "":
                    end_tz_str = "UTC"
            except:
                end_tz_str = "UTC"

            # 创建带时区的 datetime 对象
            start_time = datetime.strptime(
                f"{start_date_str} {start_hour}:{start_minute}",
                "%Y-%m-%d %H:%M"
            ).replace(tzinfo=pytz.timezone(start_tz_str))

            end_time = datetime.strptime(
                f"{end_date_str} {end_hour}:{end_minute}",
                "%Y-%m-%d %H:%M"
            ).replace(tzinfo=pytz.timezone(end_tz_str))

            # 设置带时区的开始和结束时间 (使用正确的格式)
            event.add('dtstart').value = start_time.strftime("%Y%m%dT%H%M%S")
            event.add('dtend').value = end_time.strftime("%Y%m%dT%H%M%S")

        # 设置重复规则
        repeat_option = self.repeat_var.get()
        if repeat_option != "不重复":
            rrule = self.generate_rrule()
            if rrule:
                event.add('rrule').value = rrule

        # 设置强制提醒
        if self.force_reminder_var.get():
            event.add('force-reminder').value = "1"

        # 添加提醒
        for alarm in self.alarms:
            valarm = event.add('valarm')
            valarm.add('action').value = alarm['action']
            valarm.add('trigger').value = alarm['trigger']
            valarm.add('description').value = "提醒"

        # 设置高级属性
        categories = self.categories_var.get()
        if categories:
            event.add('categories').value = categories

        priority = str(self.priority_var.get())
        if priority != "0":
            event.add('priority').value = priority

        # 设置透明度（中文->英文）
        transparency_zh = self.transparency_var.get()
        transparency = self.TRANSPARENCY_MAPPING.get(transparency_zh, "OPAQUE")
        event.add('transp').value = transparency

        sequence = self.sequence_var.get()
        if sequence:
            event.add('sequence').value = sequence

        url = self.url_var.get()
        if url:
            event.add('url').value = url

        organizer = self.organizer_var.get()
        if organizer:
            event.add('organizer').value = organizer

        attendees = self.attendee_text.get("1.0", "end").strip().splitlines()
        for attendee in attendees:
            if attendee.strip():
                event.add('attendee').value = attendee.strip()

        return cal.serialize()

    def generate_rrule(self):
        """生成重复规则字符串"""
        repeat_option = self.repeat_var.get()

        if repeat_option == "每天":
            return "FREQ=DAILY"
        elif repeat_option == "每周":
            return "FREQ=WEEKLY"
        elif repeat_option == "每两周":
            return "FREQ=WEEKLY;INTERVAL=2"
        elif repeat_option == "每月":
            return "FREQ=MONTHLY"
        elif repeat_option == "每年":
            return "FREQ=YEARLY"
        elif repeat_option == "自定义":
            # 使用自定义设置生成规则
            parts = []

            # 添加频率
            freq = self.custom_repeat_data.get('freq', 'WEEKLY')
            parts.append(f"FREQ={freq}")

            # 添加间隔
            interval = self.custom_repeat_data.get('interval', '1')
            if interval != '1':
                parts.append(f"INTERVAL={interval}")

            # 添加每周设置
            if freq == 'WEEKLY':
                byday = self.custom_repeat_data.get('byday', [])
                if byday:
                    parts.append(f"BYDAY={','.join(byday)}")

            # 添加每月设置
            if freq == 'MONTHLY':
                bymonthday = self.custom_repeat_data.get('bymonthday', [])
                if bymonthday:
                    parts.append(f"BYMONTHDAY={','.join(bymonthday)}")

            # 添加结束条件
            if 'until' in self.custom_repeat_data:
                until_date = self.custom_repeat_data['until']
                parts.append(f"UNTIL={until_date}T000000Z")
            elif 'count' in self.custom_repeat_data:
                count = self.custom_repeat_data['count']
                parts.append(f"COUNT={count}")

            return ";".join(parts)

        return ""

    def save(self):
        """保存事件但不关闭窗口"""
        ical = self.generate_ical()
        if ical:
            # 在实际应用中，这里可以调用回调函数保存事件
            messagebox.showinfo("保存成功", "事件已成功保存")
            return True
        return False

    def ok(self):
        """保存并关闭窗口"""
        if self.save():
            self.result = {
                'ical': self.generate_ical(),
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
