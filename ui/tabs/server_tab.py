import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import logging
import os
import socket
from network.dav_server import DAVServer
from ui.widgets.right_click_menu import RightClickMenu
from services.ftp_service import FTPService
from utils.logger import logger, GUIHandler

from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED, EVENT_SERVER_STATE_CHANGED
from utils.validators import validate_port


SERVER_ENCODINGS = [
    "utf-8", "utf-16be", "utf-16le", "utf-32be", "utf-32le",
    "gb2312", "gb18030", "gbk", "big5", "big5-hkscs",
    "cesu-8", "euc-jp", "euc-kr",
    "ibm866", "ibm850",
    "iso-2022-jp", "iso-2022-kr", "iso-8859-1",
    "koi8-r", "koi8-u",
    "shift-jis",
    "cp1250", "cp1251", "cp1252", "cp1253", "cp1254",
    "cp1255", "cp1256", "cp1257", "cp1258",
]


class ServerTab(ttk.Frame):
    """服务器控制标签页"""
    def __init__(self, parent, settings_service):
        super().__init__(parent)
        self.settings_service = settings_service
        self.server_thread = None
        self.server_instance = None

        self.ssl_enabled = tk.BooleanVar(value=self.settings_service.get_setting("ssl_enabled", "False") == "True")
        self.ssl_cert_var = tk.StringVar(value=self.settings_service.get_setting("ssl_certfile", ""))
        self.ssl_key_var = tk.StringVar(value=self.settings_service.get_setting("ssl_keyfile", ""))

        # FTP/SFTP/TFTP 服务器相关变量
        self.ftp_enabled = tk.BooleanVar(value=self.settings_service.get_setting("ftp_enabled", "True") == "True")
        self.ftp_port_var = tk.StringVar(value=self.settings_service.get_setting("ftp_port", "21"))
        self.ftp_root_var = tk.StringVar(value=self.settings_service.get_setting("ftp_root", "./ftp_root"))
        self.ftp_auto_save = tk.BooleanVar(value=self.settings_service.get_setting("ftp_auto_save", "True") == "True")
        self.ftp_password_var = tk.StringVar(value=self.settings_service.get_setting("ftp_password", ""))
        self.ftp_encoding_var = tk.StringVar(value=self.settings_service.get_setting("ftp_encoding", "utf-8"))
        self.ftps_enabled = tk.BooleanVar(value=self.settings_service.get_setting("ftps_enabled", "False") == "True")
        self.dav_root_var = tk.StringVar(value=self.settings_service.get_setting("dav_root", "./dav_root"))
        self.sftp_enabled = tk.BooleanVar(value=self.settings_service.get_setting("sftp_enabled", "False") == "True")
        self.sftp_port_var = tk.StringVar(value=self.settings_service.get_setting("sftp_port", "22"))
        self.sftp_root_var = tk.StringVar(value=self.settings_service.get_setting("sftp_root", "./sftp_root"))
        self.tftp_enabled = tk.BooleanVar(value=self.settings_service.get_setting("tftp_enabled", "False") == "True")
        self.tftp_port_var = tk.StringVar(value=self.settings_service.get_setting("tftp_port", "69"))
        self.tftp_root_var = tk.StringVar(value=self.settings_service.get_setting("tftp_root", "./tftp_root"))

        self.ftp_service = FTPService()
        self.create_widgets()
        event_bus.subscribe(EVENT_SETTINGS_CHANGED, self.on_settings_changed)

    def on_settings_changed(self, *args):
        if not self.server_instance:
            new_port = self.settings_service.get_setting("default_port", "8000")
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, new_port)
        self.ssl_enabled.set(self.settings_service.get_setting("ssl_enabled", "False") == "True")
        self.ssl_cert_var.set(self.settings_service.get_setting("ssl_certfile", ""))
        self.ssl_key_var.set(self.settings_service.get_setting("ssl_keyfile", ""))
        self.ftp_enabled.set(self.settings_service.get_setting("ftp_enabled", "True") == "True")
        self.ftp_port_var.set(self.settings_service.get_setting("ftp_port", "21"))
        self.ftp_root_var.set(self.settings_service.get_setting("ftp_root", "./ftp_root"))
        self.ftp_password_var.set(self.settings_service.get_setting("ftp_password", ""))
        self.ftp_encoding_var.set(self.settings_service.get_setting("ftp_encoding", "utf-8"))
        self.ftps_enabled.set(self.settings_service.get_setting("ftps_enabled", "False") == "True")
        self.dav_root_var.set(self.settings_service.get_setting("dav_root", "./dav_root"))
        self.sftp_enabled.set(self.settings_service.get_setting("sftp_enabled", "False") == "True")
        self.sftp_port_var.set(self.settings_service.get_setting("sftp_port", "22"))
        self.sftp_root_var.set(self.settings_service.get_setting("sftp_root", "./sftp_root"))
        self.tftp_enabled.set(self.settings_service.get_setting("tftp_enabled", "False") == "True")
        self.tftp_port_var.set(self.settings_service.get_setting("tftp_port", "69"))
        self.tftp_root_var.set(self.settings_service.get_setting("tftp_root", "./tftp_root"))
        self._update_info()

    def create_widgets(self):
        # 可滚动容器
        canvas = tk.Canvas(self, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw", tags="inner")
        canvas.bind("<Configure>", lambda e: canvas.itemconfig("inner", width=e.width))
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)

        # 端口设置
        port_frame = ttk.LabelFrame(inner, text="服务器控制")
        port_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(port_frame, text="端口号:").pack(side=tk.LEFT, padx=5, pady=10)
        self.port_var = tk.StringVar(value=self.settings_service.get_setting("default_port", "8000"))
        self.port_entry = ttk.Entry(port_frame, textvariable=self.port_var, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_var.trace("w", lambda *a: self._update_info())
        self.port_hint = ttk.Label(port_frame, text="", font=("", 8)); self.port_hint.pack(side=tk.LEFT, padx=5)
        def _port_keyup(*_):
            ok, msg = validate_port(self.port_var.get())
            if not ok: self.port_hint.config(text=msg, foreground="red")
            elif msg: self.port_hint.config(text=msg, foreground="orange")
            else: self.port_hint.config(text="")
        self.port_entry.bind("<KeyRelease>", _port_keyup)

        self.start_btn = ttk.Button(port_frame, text="启动服务器", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(port_frame, text="停止服务器", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Label(port_frame, text="DAV 目录:").pack(side=tk.LEFT, padx=5)
        self.dav_root_entry = ttk.Entry(port_frame, textvariable=self.dav_root_var, width=25)
        self.dav_root_entry.pack(side=tk.LEFT, padx=2)
        self.dav_root_browse_btn = ttk.Button(port_frame, text="浏览...", width=6, command=lambda: self._browse_dir(self.dav_root_var))
        self.dav_root_browse_btn.pack(side=tk.LEFT, padx=2)

        # FTP / SFTP / TFTP 服务控制
        ftp_frame = ttk.LabelFrame(inner, text="FTP / SFTP / TFTP 文件服务")
        ftp_frame.pack(fill=tk.X, padx=10, pady=(5, 5))

        # FTP 设置
        ftp_row = ttk.Frame(ftp_frame)
        ftp_row.pack(fill=tk.X, padx=5, pady=2)
        self.ftp_check = ttk.Checkbutton(ftp_row, text="FTP 服务器", variable=self.ftp_enabled)
        self.ftp_check.pack(side=tk.LEFT, padx=5)
        self.ftps_check = ttk.Checkbutton(ftp_row, text="FTPS(SSL)", variable=self.ftps_enabled)
        self.ftps_check.pack(side=tk.LEFT, padx=2)
        ttk.Label(ftp_row, text="端口:").pack(side=tk.LEFT, padx=5)
        self.ftp_port_entry = ttk.Entry(ftp_row, textvariable=self.ftp_port_var, width=6)
        self.ftp_port_entry.pack(side=tk.LEFT)
        ttk.Label(ftp_row, text="根目录:").pack(side=tk.LEFT, padx=5)
        self.ftp_root_entry = ttk.Entry(ftp_row, textvariable=self.ftp_root_var, width=40)
        self.ftp_root_entry.pack(side=tk.LEFT, padx=2)
        self.ftp_browse_btn = ttk.Button(ftp_row, text="浏览...", width=6, command=lambda: self._browse_dir(self.ftp_root_var))
        self.ftp_browse_btn.pack(side=tk.LEFT, padx=2)
        self.ftp_path_status = ttk.Label(ftp_row, text="", width=3)
        self.ftp_path_status.pack(side=tk.LEFT, padx=2)
        self.ftp_root_var.trace("w", lambda *a: self._validate_path(self.ftp_root_var, self.ftp_path_status))

        # SFTP 设置
        sftp_row = ttk.Frame(ftp_frame)
        sftp_row.pack(fill=tk.X, padx=5, pady=2)
        self.sftp_check = ttk.Checkbutton(sftp_row, text="SFTP 服务器", variable=self.sftp_enabled)
        self.sftp_check.pack(side=tk.LEFT, padx=5)
        ttk.Label(sftp_row, text="端口:").pack(side=tk.LEFT, padx=5)
        self.sftp_port_entry = ttk.Entry(sftp_row, textvariable=self.sftp_port_var, width=6)
        self.sftp_port_entry.pack(side=tk.LEFT)
        ttk.Label(sftp_row, text="根目录:").pack(side=tk.LEFT, padx=5)
        self.sftp_root_entry = ttk.Entry(sftp_row, textvariable=self.sftp_root_var, width=40)
        self.sftp_root_entry.pack(side=tk.LEFT, padx=2)
        self.sftp_browse_btn = ttk.Button(sftp_row, text="浏览...", width=6, command=lambda: self._browse_dir(self.sftp_root_var))
        self.sftp_browse_btn.pack(side=tk.LEFT, padx=2)
        self.sftp_path_status = ttk.Label(sftp_row, text="", width=3)
        self.sftp_path_status.pack(side=tk.LEFT, padx=2)
        self.sftp_root_var.trace("w", lambda *a: self._validate_path(self.sftp_root_var, self.sftp_path_status))

        # TFTP 设置
        tftp_row = ttk.Frame(ftp_frame)
        tftp_row.pack(fill=tk.X, padx=5, pady=2)
        self.tftp_check = ttk.Checkbutton(tftp_row, text="TFTP 服务器", variable=self.tftp_enabled)
        self.tftp_check.pack(side=tk.LEFT, padx=5)
        ttk.Label(tftp_row, text="端口:").pack(side=tk.LEFT, padx=5)
        self.tftp_port_entry = ttk.Entry(tftp_row, textvariable=self.tftp_port_var, width=6)
        self.tftp_port_entry.pack(side=tk.LEFT)
        ttk.Label(tftp_row, text="根目录:").pack(side=tk.LEFT, padx=5)
        self.tftp_root_entry = ttk.Entry(tftp_row, textvariable=self.tftp_root_var, width=40)
        self.tftp_root_entry.pack(side=tk.LEFT, padx=2)
        self.tftp_browse_btn = ttk.Button(tftp_row, text="浏览...", width=6, command=lambda: self._browse_dir(self.tftp_root_var))
        self.tftp_browse_btn.pack(side=tk.LEFT, padx=2)
        self.tftp_path_status = ttk.Label(tftp_row, text="", width=3)
        self.tftp_path_status.pack(side=tk.LEFT, padx=2)
        self.tftp_root_var.trace("w", lambda *a: self._validate_path(self.tftp_root_var, self.tftp_path_status))

        # 认证与编码（位于所有协议行下方）
        auth_row = ttk.Frame(ftp_frame)
        auth_row.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(auth_row, text="FTP 独立密码:").pack(side=tk.LEFT, padx=5)
        self.ftp_password_entry = ttk.Entry(auth_row, textvariable=self.ftp_password_var, width=16, show="*")
        self.ftp_password_entry.pack(side=tk.LEFT, padx=2)
        ttk.Label(auth_row, text="（留空=统一账号）").pack(side=tk.LEFT, padx=2)
        ttk.Label(auth_row, text="  编码:").pack(side=tk.LEFT, padx=5)
        self.ftp_encoding_combo = ttk.Combobox(auth_row, textvariable=self.ftp_encoding_var,
                                                values=list(SERVER_ENCODINGS), state="readonly", width=10)
        self.ftp_encoding_combo.pack(side=tk.LEFT, padx=2)

        # 自动保存 + 控制按钮
        ctrl_row = ttk.Frame(ftp_frame)
        ctrl_row.pack(fill=tk.X, padx=5, pady=2)
        self.auto_save_check = ttk.Checkbutton(ctrl_row, text="自动保存设置", variable=self.ftp_auto_save)
        self.auto_save_check.pack(side=tk.LEFT, padx=5)

        self.ftp_start_btn = ttk.Button(ctrl_row, text="启动所有服务", command=self.start_ftp_services)
        self.ftp_start_btn.pack(side=tk.LEFT, padx=5)
        self.ftp_stop_btn = ttk.Button(ctrl_row, text="停止所有服务", command=self.stop_ftp_services, state=tk.DISABLED)
        self.ftp_stop_btn.pack(side=tk.LEFT, padx=5)

        self.ftp_status_label = ttk.Label(ctrl_row, text="状态: 已停止")
        self.ftp_status_label.pack(side=tk.LEFT, padx=10)

        # 日志显示
        log_frame = ttk.LabelFrame(inner, text="运行日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        self.log_text = tk.Text(log_frame, state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.tag_config("CRITICAL", foreground="white", background="darkred")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.tag_config("WARNING", foreground="orange")
        self.log_text.tag_config("INFO", foreground="black")
        self.log_text.tag_config("DEBUG", foreground="gray")
        RightClickMenu(self.log_text, "text")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)

        # 客户端配置信息
        info_frame = ttk.LabelFrame(inner, text="客户端配置信息")
        info_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        self.info_label = ttk.Label(info_frame, text="", justify=tk.LEFT, font=('Consolas', 9))
        self.info_label.pack(padx=5, pady=5)
        self._update_info()

    def _browse_dir(self, var):
        path = filedialog.askdirectory(title="选择根目录")
        if path:
            var.set(path)

    def _validate_path(self, var, status_label):
        path = var.get().strip()
        if not path:
            status_label.config(text="", foreground="black")
            return
        expanded = os.path.expanduser(os.path.expandvars(path))
        if os.path.exists(expanded):
            status_label.config(text="✓", foreground="green")
        else:
            status_label.config(text="✗", foreground="red")

    def _save_ftp_settings(self):
        if self.ftp_auto_save.get():
            for name, var in [("FTP 端口", self.ftp_port_var), ("SFTP 端口", self.sftp_port_var),
                              ("TFTP 端口", self.tftp_port_var)]:
                ok, msg = validate_port(var.get())
                if not ok:
                    messagebox.showerror("端口错误", f"{name}: {msg}", parent=self)
                    return
            self.settings_service.set_setting("ftp_enabled", str(self.ftp_enabled.get()))
            self.settings_service.set_setting("ftp_port", self.ftp_port_var.get())
            self.settings_service.set_setting("ftp_root", self.ftp_root_var.get())
            self.settings_service.set_setting("ftp_password", self.ftp_password_var.get())
            self.settings_service.set_setting("ftp_encoding", self.ftp_encoding_var.get())
            self.settings_service.set_setting("ftps_enabled", str(self.ftps_enabled.get()))
            self.settings_service.set_setting("sftp_enabled", str(self.sftp_enabled.get()))
            self.settings_service.set_setting("sftp_port", self.sftp_port_var.get())
            self.settings_service.set_setting("sftp_root", self.sftp_root_var.get())
            self.settings_service.set_setting("tftp_enabled", str(self.tftp_enabled.get()))
            self.settings_service.set_setting("tftp_port", self.tftp_port_var.get())
            self.settings_service.set_setting("tftp_root", self.tftp_root_var.get())

    def _set_ftp_config_state(self, disabled: bool):
        state = tk.DISABLED if disabled else tk.NORMAL
        for w in (self.ftp_check, self.sftp_check, self.tftp_check,
                  self.ftp_port_entry, self.sftp_port_entry, self.tftp_port_entry,
                  self.ftp_root_entry, self.sftp_root_entry, self.tftp_root_entry,
                  self.ftp_browse_btn, self.sftp_browse_btn, self.tftp_browse_btn,
                  self.ftp_password_entry, self.ftp_encoding_combo,
                  self.ftps_check, self.auto_save_check):
            w.config(state=state)

    def start_ftp_services(self):
        checks = []
        if self.ftp_enabled.get():
            checks.append(("FTP", self.ftp_root_var))
        if self.sftp_enabled.get():
            checks.append(("SFTP", self.sftp_root_var))
        if self.tftp_enabled.get():
            checks.append(("TFTP", self.tftp_root_var))

        for name, var in checks:
            path = var.get().strip()
            if not path:
                msg = f"{name} 根目录为空"
                messagebox.showwarning("提示", msg, parent=self)
                return
            expanded = os.path.expanduser(os.path.expandvars(path))
            if not os.path.exists(expanded):
                msg = f"{name} 根目录不存在: {expanded}"
                messagebox.showerror("错误", msg, parent=self)
                return

        self._save_ftp_settings()
        try:
            if self.ftp_service.start():
                self._set_ftp_config_state(True)
                self.ftp_start_btn.config(state=tk.DISABLED)
                self.ftp_stop_btn.config(state=tk.NORMAL)
                self.ftp_status_label.config(text="状态: 运行中")
                msg = "FTP/SFTP/TFTP 服务已启动"
                logger.info(msg)
                self.log_message(msg, logging.INFO)
            else:
                msg = "文件服务启动失败（请检查设置与端口占用）"
                logger.error(msg)
                self.log_message(msg, logging.ERROR)
        except Exception as e:
            msg = f"启动异常: {e}"
            logger.error(msg)
            self.log_message(msg, logging.ERROR)

    def _auto_start_ftp(self):
        """启动时自动启动文件服务 — 无对话框，失败只记日志。"""
        for name, var, port_var, root_var in [
            ("FTP", self.ftp_enabled, self.ftp_port_var, self.ftp_root_var),
            ("SFTP", self.sftp_enabled, self.sftp_port_var, self.sftp_root_var),
            ("TFTP", self.tftp_enabled, self.tftp_port_var, self.tftp_root_var),
        ]:
            if not var.get():
                continue
            path = os.path.expanduser(os.path.expandvars(root_var.get().strip()))
            if not path or not os.path.exists(path):
                logger.warning(f"{name} 自动启动跳过: 根目录无效 ({root_var.get()})")
                return
        try:
            if self.ftp_service.start():
                self._set_ftp_config_state(True)
                self.ftp_start_btn.config(state=tk.DISABLED)
                self.ftp_stop_btn.config(state=tk.NORMAL)
                self.ftp_status_label.config(text="状态: 运行中")
                logger.info("文件服务 (FTP/SFTP/TFTP) 已自动启动")
        except Exception as e:
            logger.warning(f"文件服务自动启动失败: {e}")

    def stop_ftp_services(self):
        self.ftp_service.stop()
        self._set_ftp_config_state(False)
        self.ftp_start_btn.config(state=tk.NORMAL)
        self.ftp_stop_btn.config(state=tk.DISABLED)
        self.ftp_status_label.config(text="状态: 已停止")
        msg = "文件服务已停止"
        logger.info(msg)
        self.log_message(msg, logging.INFO)

    @staticmethod
    def _get_local_ips():
        ips = []
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                if ip not in ips and not ip.startswith("127."):
                    ips.append(ip)
        except Exception:
            pass
        ips.append("127.0.0.1")
        return ips

    def _update_info(self):
        port = self.port_entry.get() or "8000"
        scheme = "https" if self.ssl_enabled.get() else "http"
        ips = self._get_local_ips()
        ip_lines = "  ".join(ips[:3])

        ftp_port = self.ftp_port_var.get() or "21"
        sftp_port = self.sftp_port_var.get() or "22"
        tftp_port = self.tftp_port_var.get() or "69"
        ftp_encoding = self.ftp_encoding_var.get()

        ftp_enabled = self.ftp_enabled.get()
        ftps_enabled = self.ftps_enabled.get()
        sftp_enabled = self.sftp_enabled.get()
        tftp_enabled = self.tftp_enabled.get()

        ftp_lines = ""
        if ftp_enabled:
            proto = "FTPS" if ftps_enabled else "FTP"
            ftp_lines += f"\n  {proto}:      {proto.lower()}://[账户@]{ip_lines}:{ftp_port}  (编码: {ftp_encoding})"
        if sftp_enabled:
            ftp_lines += f"\n  SFTP:     sftp://[账户@]{ip_lines}:{sftp_port}"
        if tftp_enabled:
            ftp_lines += f"\n  TFTP:     tftp://{ip_lines}:{tftp_port}"

        self.info_label.config(text=f"""CardDAV 配置:
  服务器地址: {scheme}://localhost:{port}/contacts/
  用户名: (任意)  密码: (任意)

CalDAV 配置:
  服务器地址: {scheme}://localhost:{port}/events/
  用户名: (任意)  密码: (任意)

WebDAV 文件服务:
  服务器地址: {scheme}://localhost:{port}/dav/
  用户名: (任意)  密码: (任意)

文件服务:{ftp_lines}

在浏览器中测试:
  {scheme}://localhost:{port}/ - 查看服务信息
  {scheme}://localhost:{port}/contacts/ - 所有联系人
  {scheme}://localhost:{port}/events/ - 所有日历事件""")

    LEVEL_TAGS = {50: "CRITICAL", 40: "ERROR", 30: "WARNING", 20: "INFO", 10: "DEBUG"}

    def start_server(self):
        ok, msg = validate_port(self.port_entry.get())
        if not ok:
            messagebox.showerror("端口错误", msg, parent=self)
            return
        if msg:
            from ui.widgets.toast import Toast
            Toast.warning(self, msg)
        port = int(self.port_entry.get())
        if self.settings_service.get_setting("auto_save_port", "True") == "True":
            self.settings_service.set_setting("default_port", self.port_entry.get())

        ssl_enabled = self.ssl_enabled.get()
        ssl_cert = self.ssl_cert_var.get().strip()
        ssl_key = self.ssl_key_var.get().strip()

        self.settings_service.set_setting("ssl_enabled", str(ssl_enabled))
        self.settings_service.set_setting("ssl_certfile", ssl_cert)
        self.settings_service.set_setting("ssl_keyfile", ssl_key)

        dav_root = self.dav_root_var.get().strip() or "./dav_root"
        self.settings_service.set_setting("dav_root", dav_root)
        os.makedirs(os.path.expanduser(os.path.expandvars(dav_root)), exist_ok=True)

        try:
            self.server_instance = DAVServer(port, ssl_enabled, ssl_cert, ssl_key)
            self.server_thread = threading.Thread(target=self.server_instance.start, daemon=True)
            self.server_thread.start()
        except Exception as e:
            logger.error(f"服务器启动失败: {e}")
            self.log_message(f"服务器启动失败: {e}", logging.ERROR)
            self.server_instance = None
            return

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.DISABLED)
        self.dav_root_entry.config(state=tk.DISABLED)
        self.dav_root_browse_btn.config(state=tk.DISABLED)
        scheme = "HTTPS" if ssl_enabled else "HTTP"
        msg = f"服务器已启动 ({scheme}) 在端口 {port}"
        logger.info(msg)
        self.log_message(msg, logging.INFO)
        event_bus.publish(EVENT_SERVER_STATE_CHANGED)

    def stop_server(self):
        if self.server_instance:
            self.server_instance.stop()
            self.server_instance = None
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.NORMAL)
            self.dav_root_entry.config(state=tk.NORMAL)
            self.dav_root_browse_btn.config(state=tk.NORMAL)
            msg = "服务器已停止"
            logger.info(msg)
            self.log_message(msg, logging.INFO)
            event_bus.publish(EVENT_SERVER_STATE_CHANGED)

    def log_message(self, message, levelno=logging.INFO):
        tag = self.LEVEL_TAGS.get(levelno // 10 * 10, "INFO")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
