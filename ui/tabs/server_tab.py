import tkinter as tk
from tkinter import ttk
import threading
from network.dav_server import DAVServer
from ui.widgets.right_click_menu import RightClickMenu
from utils.logger import logger, GUIHandler

from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED

class ServerTab(ttk.Frame):
    """服务器控制标签页"""
    def __init__(self, parent, settings_service):
        super().__init__(parent)
        self.settings_service = settings_service
        self.server_thread = None
        self.server_instance = None
        
        self.create_widgets()
        event_bus.subscribe(EVENT_SETTINGS_CHANGED, self.on_settings_changed)

    def on_settings_changed(self, *args):
        """同步设置中的默认端口"""
        new_port = self.settings_service.get_setting("default_port", "8000")
        if not self.server_instance: # 如果没在运行，更新显示
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, new_port)

    def create_widgets(self):
        # 端口设置
        port_frame = ttk.LabelFrame(self, text="服务器控制")
        port_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(port_frame, text="端口号:").pack(side=tk.LEFT, padx=5, pady=10)
        self.port_entry = ttk.Entry(port_frame, width=10)
        self.port_entry.insert(0, self.settings_service.get_setting("default_port", "8000"))
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        self.start_btn = ttk.Button(port_frame, text="启动服务器", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(port_frame, text="停止服务器", command=self.stop_server, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # 日志显示
        log_frame = ttk.LabelFrame(self, text="运行日志")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, state=tk.DISABLED, wrap=tk.WORD)
        RightClickMenu(self.log_text, "text")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scrollbar.set)

        # 客户端配置信息
        info_frame = ttk.LabelFrame(self, text="客户端配置信息")
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
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT, font=('Consolas', 9)).pack(padx=5, pady=5)

    def start_server(self):
        port = int(self.port_entry.get())
        if self.settings_service.get_setting("auto_save_port", "True") == "True":
            self.settings_service.set_setting("default_port", port)
            
        self.server_instance = DAVServer(port)
        self.server_thread = threading.Thread(target=self.server_instance.start, daemon=True)
        self.server_thread.start()
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log_message(f"服务器已启动在端口 {port}")

    def stop_server(self):
        if self.server_instance:
            self.server_instance.stop()
            self.server_instance = None
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.log_message("服务器已停止")

    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
