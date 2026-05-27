import tkinter as tk
from tkinter import ttk, messagebox
import queue
import logging
import webbrowser
from tkinterdnd2 import TkinterDnD
from ui.tabs.server_tab import ServerTab
from ui.tabs.contacts_tab import ContactsTab
from ui.tabs.calendar_tab import CalendarTab
from ui.dialogs.settings_dialog import SettingsDialog
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from utils.logger import GUIHandler, logger
from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED, EVENT_EVENTS_CHANGED, EVENT_SETTINGS_CHANGED
from config import SOFTWARE_NAME, SOFTWARE_VERSION

class DAVServerApp:
    """主应用程序类"""
    def __init__(self, root):
        self.root = root
        self.root.title(f"{SOFTWARE_NAME} v{SOFTWARE_VERSION}")
        # self.root.geometry("1000x700")
        
        # 初始化服务
        self.settings_service = SettingsService()
        self.contact_service = ContactService()
        self.event_service = EventService()
        
        # 初始化队列用于日志和导入
        self.log_queue = queue.Queue()
        self.import_queue = queue.Queue()
        self.import_in_progress = False
        self.import_cancel_requested = False
        self.file_handler = None
        self.setup_logging()

        self.create_widgets()

        # 启动日志处理循环
        self.root.after(100, self.process_log_queue)
        # 启动导入队列处理循环
        self.root.after(100, self.process_import_queue)

        # 注册全局快捷键
        self.root.bind("<Delete>", self.on_global_delete)
        self.root.bind("<Control-a>", self.on_global_select_all)

        # 注册全局文件拖拽
        self.setup_global_dnd()

        # 绑定标签页切换事件
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        # 订阅设置变更事件
        event_bus.subscribe(EVENT_SETTINGS_CHANGED, self.on_settings_changed)

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

    def setup_global_dnd(self):
        """设置全局文件拖拽支持 - 1:1 还原 main_old.py"""
        try:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self.handle_drop)
        except Exception as e:
            logger.warning(f"无法注册全局拖拽: {e}")

    def handle_drop(self, event):
        """处理文件拖拽事件 - 1:1 还原 main_old.py:2277-2320"""
        import os
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
            logger.warning(f"未找到有效文件路径: {event.data}")
            return

        logger.info(f"拖拽导入文件: {', '.join(files)}")

        current_tab = self.notebook.select()
        tab_text = self.notebook.tab(current_tab, "text")

        if tab_text == "联系人":
            self._start_import_contacts(files)
        elif tab_text == "日历":
            self._start_import_events(files)
        else:
            messagebox.showinfo("提示", "请切换到联系人或日历标签页进行导入")

    def _start_import_contacts(self, files):
        """开始导入联系人文件"""
        for f in files:
            if f.lower().endswith('.vcf'):
                try:
                    with open(f, 'r', encoding='utf-8') as file:
                        self.contact_service.add_contact(file.read())
                except Exception as e:
                    logger.error(f"导入文件失败 {f}: {e}")
        event_bus.publish(EVENT_CONTACTS_CHANGED)
        logger.info(f"联系人导入完成: 从文件导入")

    def _start_import_events(self, files):
        """开始导入事件文件"""
        for f in files:
            if f.lower().endswith('.ics'):
                try:
                    with open(f, 'r', encoding='utf-8') as file:
                        self.event_service.add_event(file.read())
                except Exception as e:
                    logger.error(f"导入文件失败 {f}: {e}")
        event_bus.publish(EVENT_EVENTS_CHANGED)
        logger.info(f"事件导入完成: 从文件导入")

    def on_tab_changed(self, event):
        """标签页切换时自动刷新列表 - 1:1 还原 main_old.py:2322-2330"""
        current_tab = self.notebook.select()
        tab_text = self.notebook.tab(current_tab, "text")

        if tab_text == "联系人":
            self.contacts_tab.refresh_contacts()
        elif tab_text == "日历":
            self.calendar_tab.refresh_events()

    def setup_logging(self):
        """配置 GUI、控制台和文件日志处理器"""
        # 配置根日志器，确保只输出一次
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        # 禁用根日志器的向上传播
        root_logger.propagate = False

        # 清除根日志器已有的处理器（防止重复）
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # 添加控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        root_logger.addHandler(console_handler)

        gui_handler = GUIHandler(self.log_queue)
        root_logger.addHandler(gui_handler)

        # 根据设置配置日志文件
        self._setup_file_logging()

    def _setup_file_logging(self):
        """根据设置配置日志文件"""
        enable_file = self.settings_service.get_setting("enable_log_file", "False") == "True"
        root_logger = logging.getLogger()

        # 移除现有的文件处理器
        if self.file_handler:
            root_logger.removeHandler(self.file_handler)
            self.file_handler = None

        # 如果启用日志文件，添加新的文件处理器
        if enable_file:
            log_file = self.settings_service.get_setting("log_file_path", "dav_server.log")
            log_level = self.settings_service.get_setting("log_level", "INFO")

            try:
                self.file_handler = logging.FileHandler(log_file, encoding='utf-8')
                self.file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                self.file_handler.setLevel(getattr(logging, log_level, logging.INFO))
                root_logger.addHandler(self.file_handler)
                logger.info(f"日志文件已启用，路径: {log_file}，级别: {log_level}")
            except Exception as e:
                logger.warning(f"无法创建日志文件: {e}")

    def on_settings_changed(self, *args):
        """设置变更时重新配置日志"""
        self._setup_file_logging()

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

    def process_import_queue(self):
        """处理导入队列 - 1:1 还原 main_old.py"""
        if self.import_in_progress or self.import_cancel_requested:
            self.root.after(100, self.process_import_queue)
            return
        
        try:
            while not self.import_queue.empty() and not self.import_cancel_requested:
                task = self.import_queue.get_nowait()
                self._execute_import_task(task)
        except queue.Empty:
            pass
        
        self.root.after(100, self.process_import_queue)
    
    def _execute_import_task(self, task):
        """执行单个导入任务"""
        self.import_in_progress = True
        try:
            import_type = task.get('type')
            data = task.get('data')
            source = task.get('source', '未知')
            
            if import_type == 'contacts':
                if isinstance(data, list):
                    for item in data:
                        if self.import_cancel_requested:
                            break
                        self.contact_service.add_contact(item)
                else:
                    self.contact_service.add_contact(data)
                event_bus.publish(EVENT_CONTACTS_CHANGED)
                logger.info(f"联系人导入完成: 从 {source} 导入")
            elif import_type == 'events':
                if isinstance(data, list):
                    for item in data:
                        if self.import_cancel_requested:
                            break
                        self.event_service.add_event(item)
                else:
                    self.event_service.add_event(data)
                event_bus.publish(EVENT_EVENTS_CHANGED)
                logger.info(f"事件导入完成: 从 {source} 导入")
        except Exception as e:
            logger.error(f"导入任务失败: {str(e)}")
        finally:
            self.import_in_progress = False
    
    def queue_import(self, import_type, data, source="未知"):
        """将导入任务加入队列"""
        self.import_queue.put({'type': import_type, 'data': data, 'source': source})
    
    def cancel_import(self):
        """取消当前导入操作"""
        self.import_cancel_requested = True
        logger.info("用户请求取消导入操作")
        # 清空队列
        while not self.import_queue.empty():
            try:
                self.import_queue.get_nowait()
            except queue.Empty:
                break
        self.import_cancel_requested = False
        self.import_in_progress = False

    def on_closing(self):
        if messagebox.askokcancel("退出", "确定要退出吗？"):
            self.server_tab.stop_server()
            self.root.destroy()

    def open_project_url(self):
        """打开项目地址"""
        webbrowser.open("https://github.com/hunyanjie/PersonalDAV")
