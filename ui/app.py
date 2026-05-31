import tkinter as tk
from tkinter import ttk, messagebox
import queue
from database.db_manager import Database
import logging
import webbrowser
from tkinterdnd2 import TkinterDnD, DND_FILES
from ui.tabs.server_tab import ServerTab
from ui.tabs.contacts_tab import ContactsTab
from ui.tabs.calendar_tab import CalendarTab
from ui.dialogs.settings_dialog import SettingsDialog
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from utils.logger import GUIHandler, logger
from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED, EVENT_EVENTS_CHANGED, EVENT_SETTINGS_CHANGED, EVENT_SERVER_STATE_CHANGED
from config import SOFTWARE_NAME, SOFTWARE_VERSION
from services.mcp_server import MCPServer

class DAVServerApp:
    """主应用程序类"""
    def __init__(self, root, cli_port=None, cli_log_level=None):
        self.root = root
        self.root.title(f"{SOFTWARE_NAME} v{SOFTWARE_VERSION}")

        self.settings_service = SettingsService()
        if cli_port is not None:
            self.settings_service.set_setting("default_port", str(cli_port))
        if cli_log_level is not None:
            self.settings_service.set_setting("log_level", cli_log_level)

        fmt = self.settings_service.get_setting("timezone_format",
            "{offset} - {city} ({tz_id}) {localized}{local_tag}")
        from utils.timezone_helper import TimezoneHelper
        TimezoneHelper.set_format(fmt)
        self.contact_service = ContactService()
        self.event_service = EventService()
        
        # 初始化队列用于日志
        self.log_queue = queue.Queue()
        self.file_handler = None
        self.setup_logging()

        self.create_widgets()

        # 启动日志处理循环
        self.root.after(100, self.process_log_queue)

        # 注册全局快捷键
        self.root.bind("<Delete>", self.on_global_delete)
        self.root.bind("<Control-a>", self.on_global_select_all)

        # 注册全局文件拖拽
        self.setup_global_dnd()

        # 绑定标签页切换事件
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # 订阅设置变更事件
        event_bus.subscribe(EVENT_SETTINGS_CHANGED, self.on_settings_changed)

        # MCP 服务器（根据设置自动启停）
        self.mcp_server = MCPServer()
        self._sync_mcp_server()

    def on_global_delete(self, event):
        """全局删除快捷键：自动识别当前活动的标签页并执行删除"""
        current_tab = self.notebook.nametowidget(self.notebook.select())
        if hasattr(current_tab, 'delete_selected'):
            current_tab.delete_selected()

    def on_global_select_all(self, event):
        """全局全选快捷键"""
        current_tab = self.notebook.nametowidget(self.notebook.select())
        if hasattr(current_tab, 'select_all'):
            current_tab.select_all(event)

    def setup_global_dnd(self):
        """设置全局文件拖拽支持"""
        try:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self.handle_drop)
        except Exception as e:
            logger.warning(f"无法注册全局拖拽: {e}")

    def handle_drop(self, event):
        """处理文件拖拽事件 — 解析后走预览对话框"""
        import os
        files = []

        if isinstance(event.data, (list, tuple)):
            files = [f for f in event.data if os.path.exists(f)]
        else:
            raw_paths = event.data
            if raw_paths.startswith('{') and raw_paths.endswith('}'):
                raw_paths = raw_paths[1:-1]
                possible_paths = raw_paths.split('} {')
                for path in possible_paths:
                    if os.path.exists(path):
                        files.append(path)
            else:
                if os.path.exists(raw_paths):
                    files.append(raw_paths)
                else:
                    possible_paths = raw_paths.split()
                    for path in possible_paths:
                        if os.path.exists(path):
                            files.append(path)

        if not files: return

        tab_text = self.notebook.tab(self.notebook.select(), "text")

        if tab_text not in ["联系人", "日历"]:
            messagebox.showinfo("提示", "请切换到联系人或日历标签页进行导入")
            return

        tab = self.contacts_tab if tab_text == "联系人" else self.calendar_tab

        all_data = []
        for f in files:
            try:
                with open(f, 'r', encoding='utf-8') as fh:
                    all_data.append(fh.read())
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败 {f}: {e}")
                return

        data = "\n".join(all_data)
        items = tab._parse_data_to_items(data)
        if not items:
            label = "vCard" if tab_text == "联系人" else "iCalendar"
            messagebox.showinfo("提示", f"未识别到有效 {label} 数据", parent=tab)
            return

        from ui.dialogs.import_preview_dialog import ImportPreviewDialog
        dialog = ImportPreviewDialog(tab, tab._import_type,
            on_import_callback=lambda sel: tab._import_selected(sel, "拖拽文件"),
            items=items)
        self.root.wait_window(dialog)

    def on_tab_changed(self, event):
        """标签页切换时自动刷新列表"""
        current_tab = self.notebook.select()
        tab_text = self.notebook.tab(current_tab, "text")

        if tab_text == "联系人":
            self.contacts_tab.refresh_contacts()
        elif tab_text == "日历":
            self.calendar_tab.refresh_events()

    def setup_logging(self):
        """配置 GUI 日志处理器，挂在 app 的 logger 上（非根日志器）"""
        gui_handler = GUIHandler(self.log_queue)
        logger.addHandler(gui_handler)
        self._setup_file_logging()

    def _setup_file_logging(self):
        """根据设置配置日志文件（挂载到 app logger 上）"""
        enable_file = self.settings_service.get_setting("enable_log_file", "False") == "True"

        if self.file_handler:
            logger.removeHandler(self.file_handler)
            self.file_handler = None

        if enable_file:
            log_file = self.settings_service.get_setting("log_file_path", "dav_server.log")
            log_level = self.settings_service.get_setting("log_level", "INFO")

            try:
                self.file_handler = logging.FileHandler(log_file, encoding='utf-8')
                self.file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                self.file_handler.setLevel(getattr(logging, log_level, logging.INFO))
                logger.addHandler(self.file_handler)
                logger.info(f"日志文件已启用，路径: {log_file}，级别: {log_level}")
            except Exception as e:
                logger.warning(f"无法创建日志文件: {e}")

    def on_settings_changed(self, *args):
        """设置变更时重新配置日志并同步 MCP 服务"""
        self._setup_file_logging()
        self._sync_mcp_server()

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
        help_menu.add_command(label="项目地址", command=self.open_project_url)
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
        event_bus.subscribe(EVENT_SERVER_STATE_CHANGED, self.update_status_bar)
        event_bus.subscribe(EVENT_SETTINGS_CHANGED, self.update_status_bar)

    def update_status_bar(self, *args):
        c_count = self.contact_service.count()
        e_count = self.event_service.count()
        mcp = "MCP 运行中" if self.mcp_server.is_running else "MCP 已关闭"
        self.status_bar.config(text=f"联系人: {c_count} | 事件: {e_count} | MCP: {mcp} | 服务器: {'运行中' if self.server_tab.server_instance else '已停止'}")

    def show_settings(self):
        dialog = SettingsDialog(self.root, self.settings_service, self.on_settings_saved)
        self.root.wait_window(dialog)

    def on_settings_saved(self, ssl_toggled=False):
        if ssl_toggled and self.server_tab.server_instance is not None:
            if messagebox.askyesno("重启服务器", "HTTPS 设置已更改，是否立即重启服务器以生效？"):
                self.server_tab.stop_server()
                self.server_tab.start_server()
            else:
                messagebox.showinfo("提示", "HTTPS 设置将在下次启动服务器时生效。")
        messagebox.showinfo("成功", "设置已保存")

    def _sync_mcp_server(self):
        enabled = self.settings_service.get_setting("mcp_enabled", "False") == "True"
        if enabled and not self.mcp_server.is_running:
            port = int(self.settings_service.get_setting("mcp_port", "8100"))
            self.mcp_server.start(port=port)
        elif not enabled and self.mcp_server.is_running:
            self.mcp_server.stop()

    def process_log_queue(self):
        """将队列中的日志刷新到 UI，附带级别信息用于着色"""
        try:
            while not self.log_queue.empty():
                levelno, msg = self.log_queue.get_nowait()
                self.server_tab.log_message(msg, levelno)
        except queue.Empty:
            pass
        self.root.after(100, self.process_log_queue)

    def on_closing(self):
        if messagebox.askokcancel("退出", "确定要退出吗？"):
            self.server_tab.stop_server()
            self.mcp_server.stop()
            Database().close()
            self.root.destroy()

    def open_project_url(self):
        """打开项目地址"""
        webbrowser.open("https://github.com/hunyanjie/PersonalDAV")
