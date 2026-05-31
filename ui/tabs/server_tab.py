import tkinter as tk
from tkinter import ttk
import threading
import logging
from network.dav_server import DAVServer
from ui.widgets.right_click_menu import RightClickMenu
from utils.logger import logger, GUIHandler

from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED, EVENT_SERVER_STATE_CHANGED

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
        self._update_info()

    def create_widgets(self):
        # 端口设置
        port_frame = ttk.LabelFrame(self, text="服务器控制")
        port_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(port_frame, text="端口号:").pack(side=tk.LEFT, padx=5, pady=10)
        self.port_var = tk.StringVar(value=self.settings_service.get_setting("default_port", "8000"))
        self.port_entry = ttk.Entry(port_frame, textvariable=self.port_var, width=10)
        self.port_entry.pack(side=tk.LEFT, padx=5)
        self.port_var.trace("w", lambda *a: self._update_info())

        self.start_btn = ttk.Button(port_frame, text="启动服务器", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(port_frame, text="停止服务器", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # 日志显示
        log_frame = ttk.LabelFrame(self, text="运行日志")
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
        info_frame = ttk.LabelFrame(self, text="客户端配置信息")
        info_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        self.info_label = ttk.Label(info_frame, text="", justify=tk.LEFT, font=('Consolas', 9))
        self.info_label.pack(padx=5, pady=5)
        self._update_info()

    def _update_info(self):
        port = self.port_entry.get() or "8000"
        scheme = "https" if self.ssl_enabled.get() else "http"
        self.info_label.config(text=f"""CardDAV 配置:
  服务器地址: {scheme}://localhost:{port}/contacts/
  用户名: (任意)
  密码: (任意)

CalDAV 配置:
  服务器地址: {scheme}://localhost:{port}/events/
  用户名: (任意)
  密码: (任意)

在浏览器中测试:
  {scheme}://localhost:{port}/ - 查看服务信息
  {scheme}://localhost:{port}/contacts/ - 所有联系人
  {scheme}://localhost:{port}/events/ - 所有日历事件""")

    LEVEL_TAGS = {50: "CRITICAL", 40: "ERROR", 30: "WARNING", 20: "INFO", 10: "DEBUG"}

    def start_server(self):
        port = int(self.port_entry.get())
        if self.settings_service.get_setting("auto_save_port", "True") == "True":
            self.settings_service.set_setting("default_port", port)

        ssl_enabled = self.ssl_enabled.get()
        ssl_cert = self.ssl_cert_var.get().strip()
        ssl_key = self.ssl_key_var.get().strip()

        self.settings_service.set_setting("ssl_enabled", str(ssl_enabled))
        self.settings_service.set_setting("ssl_certfile", ssl_cert)
        self.settings_service.set_setting("ssl_keyfile", ssl_key)

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
