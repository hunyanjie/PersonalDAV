import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
import os
import socket
from personaldavd.config import DaemonConfig
from personaldavd.daemon import DaemonServer
from ui.widgets.right_click_menu import RightClickMenu
from services.ftp_service import FTPService
from ui.widgets.collapsible_frame import CollapsibleFrame
from utils.logger import logger, GUIHandler

from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED, EVENT_SERVER_STATE_CHANGED
from utils.validators import validate_port


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
        self.webui_enabled = tk.BooleanVar(value=self.settings_service.get_setting("webui_enabled", "True") == "True")

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
        self.webui_enabled.set(self.settings_service.get_setting("webui_enabled", "True") == "True")
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
        self.port_hint = ttk.Label(port_frame, text="", font=("", 8)); self.port_hint.pack(side=tk.LEFT, padx=5)
        self._setup_port_validation(self.port_entry, self.port_var, self.port_hint)
        self.port_var.trace("w", lambda *a: self._update_info())

        self.start_btn = ttk.Button(port_frame, text="启动服务器", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(port_frame, text="停止服务器", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self._webui_cb = ttk.Checkbutton(port_frame, text="Web面板", variable=self.webui_enabled)
        self._webui_cb.pack(side=tk.LEFT, padx=2)

        # FTP / SFTP / TFTP 快速控制（配置已移至 设置→FTP/SFTP/TFTP/WebDAV 设置）
        ftp_collapse = CollapsibleFrame(inner, text="FTP / SFTP / TFTP 文件服务", expanded=False)
        ftp_collapse.pack(fill=tk.X, padx=10, pady=(2, 5))

        ftp_ctrl = ttk.Frame(ftp_collapse.body)
        ftp_ctrl.pack(fill=tk.X, padx=5, pady=5)
        self.ftp_start_btn = ttk.Button(ftp_ctrl, text="启动选中服务", command=self.start_ftp_services)
        self.ftp_start_btn.pack(side=tk.LEFT, padx=5)
        self.ftp_stop_btn = ttk.Button(ftp_ctrl, text="停止选中服务", command=self.stop_ftp_services, state=tk.DISABLED)
        self.ftp_stop_btn.pack(side=tk.LEFT, padx=5)
        self.ftp_status_label = ttk.Label(ftp_ctrl, text="状态: 已停止")
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

    def _setup_port_validation(self, entry, var, hint_label=None):
        def _ck(*_):
            ok, msg = validate_port(var.get())
            entry.config(foreground="red" if not ok else "orange" if msg else "black")
            if hint_label:
                if not ok: hint_label.config(text=msg, foreground="red")
                elif msg: hint_label.config(text=msg, foreground="orange")
                else: hint_label.config(text="")
        var.trace("w", _ck)
        _ck()

    def _read_ftp_checklist(self):
        """从 DB 读取 FTP/SFTP/TFTP 配置，返回 (name, root_path) 列表。"""
        s = self.settings_service
        checks = []
        for name, enabled_key, root_key in [
            ("FTP", "ftp_enabled", "ftp_root"),
            ("SFTP", "sftp_enabled", "sftp_root"),
            ("TFTP", "tftp_enabled", "tftp_root"),
        ]:
            if s.get_setting(enabled_key, "False") == "True":
                checks.append((name, s.get_setting(root_key, "")))
        return checks

    def start_ftp_services(self):
        checks = self._read_ftp_checklist()
        for name, root in checks:
            if not root.strip():
                messagebox.showwarning("提示", f"{name} 根目录为空", parent=self)
                return
            expanded = os.path.expanduser(os.path.expandvars(root.strip()))
            if not os.path.exists(expanded):
                messagebox.showerror("错误", f"{name} 根目录不存在: {expanded}", parent=self)
                return

        try:
            if self.ftp_service.start():
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
        checks = self._read_ftp_checklist()
        if not checks:
            return
        for name, root in checks:
            path = os.path.expanduser(os.path.expandvars(root.strip()))
            if not path or not os.path.exists(path):
                logger.warning(f"{name} 自动启动跳过: 根目录无效 ({root})")
                return
        try:
            if self.ftp_service.start():
                self.ftp_start_btn.config(state=tk.DISABLED)
                self.ftp_stop_btn.config(state=tk.NORMAL)
                self.ftp_status_label.config(text="状态: 运行中")
                logger.info("文件服务 (FTP/SFTP/TFTP) 已自动启动")
        except Exception as e:
            logger.warning(f"文件服务自动启动失败: {e}")

    def stop_ftp_services(self):
        self.ftp_service.stop()
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
        ssl_enabled = self.ssl_enabled.get()
        scheme = "https" if ssl_enabled else "http"
        ips = self._get_local_ips()
        ip_lines = "  ".join(ips[:3])
        ssl_port = str(int(port) + 1) if ssl_enabled else ""
        ssl_suffix = f" (HTTPS: {ssl_port})" if ssl_enabled else ""

        s = self.settings_service
        ftp_enabled = s.get_setting("ftp_enabled", "True") == "True"
        ftp_port = s.get_setting("ftp_port", "21")
        ftp_encoding = s.get_setting("ftp_encoding", "utf-8")
        ftps_enabled = s.get_setting("ftps_enabled", "False") == "True"
        sftp_enabled = s.get_setting("sftp_enabled", "False") == "True"
        sftp_port = s.get_setting("sftp_port", "22")
        tftp_enabled = s.get_setting("tftp_enabled", "False") == "True"
        tftp_port = s.get_setting("tftp_port", "69")

        ftp_lines = ""
        if ftp_enabled:
            proto = "FTPS" if ftps_enabled else "FTP"
            ftp_lines += f"\n  {proto}:      {proto.lower()}://[账户@]{ip_lines}:{ftp_port}  (编码: {ftp_encoding})"
        if sftp_enabled:
            ftp_lines += f"\n  SFTP:     sftp://[账户@]{ip_lines}:{sftp_port}"
        if tftp_enabled:
            ftp_lines += f"\n  TFTP:     tftp://{ip_lines}:{tftp_port}"

        webui_lines = ""
        if self.webui_enabled.get():
            http_label = (
                f"\n  HTTPS (SSL): https://localhost:{ssl_port}/" if ssl_enabled else ""
            )
            webui_lines = f"""
Web 管理面板:
  HTTP: http://localhost:{port}/{http_label}

REST API 文档:
  http://localhost:{port}/api/docs - Swagger 接口文档{(" (HTTPS: https://localhost:" + ssl_port + "/api/docs)") if ssl_enabled else ""}

在浏览器中测试:
  http://localhost:{port}/ - 管理面板{(" (HTTPS: https://localhost:" + ssl_port + "/)") if ssl_enabled else ""}"""

        self.info_label.config(text=f"""DAV 服务:
  CardDAV/CalDAV/WebDAV(DAV): {scheme}://localhost:{port}/{ssl_suffix}
  原始数据: {scheme}://localhost:{port}/contacts/  {scheme}://localhost:{port}/events/{webui_lines}

文件服务:{ftp_lines}""")

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
        self.settings_service.set_setting("webui_enabled", str(self.webui_enabled.get()))

        cfg = DaemonConfig(
            host="0.0.0.0",
            port=port,
            log_level=self.settings_service.get_setting("log_level", "INFO"),
            dav_root="",
            ssl_enabled=ssl_enabled,
            ssl_certfile=ssl_cert,
            ssl_keyfile=ssl_key,
            webui_enabled=self.webui_enabled.get(),
        )
        try:
            self.server_instance = DaemonServer(cfg)
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
        self._webui_cb.config(state=tk.DISABLED)
        if ssl_enabled:
            msg = f"服务器已启动 (HTTP:{port} + HTTPS:{int(port)+1})"
        else:
            msg = f"服务器已启动 (HTTP:{port})"
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
            self._webui_cb.config(state=tk.NORMAL)
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
