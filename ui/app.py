import tkinter as tk
from tkinter import ttk, messagebox
import queue
from tkinterdnd2 import TkinterDnD
from ui.tabs.server_tab import ServerTab
from ui.tabs.contacts_tab import ContactsTab
from ui.tabs.calendar_tab import CalendarTab
from ui.dialogs.settings_dialog import SettingsDialog
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from utils.logger import GUIHandler, logger
from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED, EVENT_EVENTS_CHANGED
from config import SOFTWARE_NAME, SOFTWARE_VERSION

class DAVServerApp:
    """主应用程序类"""
    def __init__(self, root):
        self.root = root
        self.root.title(f"{SOFTWARE_NAME} v{SOFTWARE_VERSION}")
        self.root.geometry("1000x700")
        
        # 初始化服务
        self.settings_service = SettingsService()
        self.contact_service = ContactService()
        self.event_service = EventService()
        
        # 初始化队列用于日志
        self.log_queue = queue.Queue()
        self.setup_logging()
        
        self.create_widgets()
        
        # 启动日志处理循环
        self.root.after(100, self.process_log_queue)
        
        # 注册全局快捷键
        self.root.bind("<Delete>", self.on_global_delete)
        self.root.bind("<Control-a>", self.on_global_select_all)

    def on_global_delete(self, event):
        """全局删除快捷键：自动识别当前活动的标签页并执行删除"""
        tab_index = self.notebook.index("current")
        if tab_index == 1: # 联系人
            self.contacts_tab.delete_contact()
        elif tab_index == 2: # 日历
            self.calendar_tab.delete_event()

    def on_global_select_all(self, event):
        """全局全选快捷键"""
        tab_index = self.notebook.index("current")
        if tab_index == 1:
            self.contacts_tab.select_all(event)
        elif tab_index == 2:
            self.calendar_tab.select_all(event)

    def setup_logging(self):
        """配置 GUI 和控制台日志处理器"""
        import logging
        # 确保根日志记录器也配置了控制台输出
        root_logger = logging.getLogger()
        if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            root_logger.addHandler(console_handler)
            root_logger.setLevel(logging.INFO)

        gui_handler = GUIHandler(self.log_queue)
        logger.addHandler(gui_handler)

    def create_widgets(self):
        # 菜单栏
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="设置", command=self.show_settings)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.on_closing)

        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="帮助", menu=help_menu)
        from ui.dialogs.text_import_dialog import show_about
        help_menu.add_command(label="关于", command=lambda: show_about(self.root))

        # 选项卡
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.server_tab = ServerTab(self.notebook, self.settings_service)
        self.contacts_tab = ContactsTab(self.notebook, self.contact_service, self.root)
        self.calendar_tab = CalendarTab(self.notebook, self.event_service, self.settings_service, self.root)

        self.notebook.add(self.server_tab, text="服务器")
        self.notebook.add(self.contacts_tab, text="联系人")
        self.notebook.add(self.calendar_tab, text="日历")

        # 根据设置自动启动服务器
        if self.settings_service.get_setting("auto_start_server", "False") == "True":
            self.server_tab.start_server()

        # 状态栏
        self.status_bar = ttk.Label(self.root, text="就绪", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 初始刷新状态栏
        self.update_status_bar()
        
        # 订阅事件以更新状态栏
        event_bus.subscribe(EVENT_CONTACTS_CHANGED, self.update_status_bar)
        event_bus.subscribe(EVENT_EVENTS_CHANGED, self.update_status_bar)

    def update_status_bar(self, *args):
        c_count = self.contact_service.repo.db.count_contacts()
        e_count = self.event_service.repo.db.count_events()
        self.status_bar.config(text=f"联系人: {c_count} | 事件: {e_count} | 服务器状态: {'运行中' if self.server_tab.server_instance else '已停止'}")

    def show_settings(self):
        dialog = SettingsDialog(self.root, self.settings_service, self.on_settings_saved)
        self.root.wait_window(dialog)

    def on_settings_saved(self):
        messagebox.showinfo("成功", "设置已保存")

    def process_log_queue(self):
        """将队列中的日志刷新到 UI"""
        try:
            while not self.log_queue.empty():
                msg = self.log_queue.get_nowait()
                self.server_tab.log_message(msg)
        except queue.Empty:
            pass
        self.root.after(100, self.process_log_queue)

    def on_closing(self):
        if messagebox.askokcancel("退出", "确定要退出吗？"):
            self.server_tab.stop_server()
            self.root.destroy()
