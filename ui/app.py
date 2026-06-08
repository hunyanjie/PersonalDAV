import tkinter as tk
from tkinter import ttk, messagebox
import queue
import time
import os
import webbrowser
from ui.tabs.server_tab import ServerTab
from ui.tabs.contacts_tab import ContactsTab
from ui.tabs.calendar_tab import CalendarTab
from ui.tabs.remote_tab import RemoteTab
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from utils.logger import logger
from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED, EVENT_EVENTS_CHANGED, EVENT_SETTINGS_CHANGED, EVENT_SERVER_STATE_CHANGED
from config import SOFTWARE_NAME, SOFTWARE_VERSION
from ui.logging_manager import LoggingManager
from ui.drag_drop_handler import DragDropHandler
from ui.status_bar_manager import StatusBarManager


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

        self.log_queue = queue.Queue()
        self.logging_manager = LoggingManager(self.settings_service, self.log_queue)
        self.logging_manager.setup()

        self.mcp_server = None
        self.start_time = time.time()

        self.create_widgets()

        self.status_bar_mgr.tick(self.root)

        self.root.after_idle(self._deferred_startup)

        self.root.after(100, self.process_log_queue)

        self.root.bind("<Delete>", self.on_global_delete)
        self.root.bind("<Control-a>", self.on_global_select_all)

        self.dnd_handler = DragDropHandler(self.root, self.notebook, self.contacts_tab, self.calendar_tab)
        self.dnd_handler.setup()

        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        event_bus.subscribe(EVENT_SETTINGS_CHANGED, self.on_settings_changed)

        self._tray = None
        self._tray_available = False
        try:
            import pystray
            self._tray_available = True
        except ImportError:
            self._tray_available = False
        if self._tray_available:
            from ui.tray_manager import TrayManager
            self._tray = TrayManager(self.root, on_show=self._tray_show, on_quit=self._tray_quit)
            self._tray.start()

    def on_global_delete(self, event):
        current_tab = self.notebook.nametowidget(self.notebook.select())
        if hasattr(current_tab, 'delete_selected'):
            current_tab.delete_selected()

    def on_global_select_all(self, event):
        current_tab = self.notebook.nametowidget(self.notebook.select())
        if hasattr(current_tab, 'select_all'):
            current_tab.select_all(event)

    def on_tab_changed(self, event):
        current_tab = self.notebook.select()
        tab_text = self.notebook.tab(current_tab, "text")
        if tab_text == "联系人":
            self.contacts_tab.refresh_contacts()
        elif tab_text == "日历":
            self.calendar_tab.refresh_events()

    def on_settings_changed(self, *args):
        self.logging_manager.reconfigure()
        self._sync_mcp_server()

    def create_widgets(self):
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
        help_menu.add_command(label="检查更新", command=self.check_update_now)
        from ui.dialogs.about_dialog import AboutDialog
        help_menu.add_command(label="关于", command=lambda: AboutDialog(self.root))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.server_tab = ServerTab(self.notebook, self.settings_service)
        self.contacts_tab = ContactsTab(self.notebook, self.contact_service, self.root)
        self.calendar_tab = CalendarTab(self.notebook, self.event_service, self.settings_service, self.root)
        self.smb_tab = RemoteTab(self.notebook, self.settings_service)

        self.notebook.add(self.server_tab, text="服务器")
        self.notebook.add(self.contacts_tab, text="联系人")
        self.notebook.add(self.calendar_tab, text="日历")
        self.notebook.add(self.smb_tab, text="远程文件")

        self.status_bar = ttk.Label(self.root, text="就绪", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_bar_mgr = StatusBarManager(
            self.status_bar, self.contact_service, self.event_service,
            lambda: self.mcp_server, self.server_tab)

        self.status_bar_mgr.refresh()

        event_bus.subscribe(EVENT_CONTACTS_CHANGED, self.status_bar_mgr.refresh)
        event_bus.subscribe(EVENT_EVENTS_CHANGED, self.status_bar_mgr.refresh)
        event_bus.subscribe(EVENT_SERVER_STATE_CHANGED, self.status_bar_mgr.refresh)
        event_bus.subscribe(EVENT_SETTINGS_CHANGED, self.status_bar_mgr.refresh)

    def _show_setup_wizard(self):
        completed = self.settings_service.get_setting("setup_wizard_completed", "")
        if completed == "1":
            return
        from ui.dialogs.setup_wizard import SetupWizard
        wiz = SetupWizard(self.root)
        self.root.wait_window(wiz)
        self.settings_service.set_setting("setup_wizard_completed", "1")

    def _deferred_startup(self):
        self._sync_mcp_server()
        if self.settings_service.get_setting("auto_start_server", "False") == "True":
            self.server_tab.start_server()
        if self.settings_service.get_setting("auto_start_ftp", "False") == "True":
            self.server_tab._auto_start_ftp()
        from utils.auto_start import set_auto_start, is_auto_start
        auto_start = self.settings_service.get_setting("auto_start_app", "False") == "True"
        if auto_start and not is_auto_start():
            set_auto_start(True)
        elif not auto_start and is_auto_start():
            set_auto_start(False)
        self.status_bar_mgr.refresh()
        self._auto_check_update()
        self._check_cert_renew()
        self._start_periodic_sync()

    def _start_periodic_sync(self):
        if self.settings_service.get_setting("sync_enabled", "False") != "True":
            return
        from services.sync_service import SyncService
        interval = int(self.settings_service.get_setting("sync_interval", "30"))
        svc = SyncService()
        if svc.is_configured():
            svc.start_periodic_sync(interval)
            logger.info(f"定时同步已启动，间隔 {interval} 分钟")

    def _check_cert_renew(self):
        if self.settings_service.get_setting("ssl_auto_renew", "True") != "True":
            return
        cert_path = self.settings_service.get_setting("ssl_certfile", "")
        if not cert_path:
            return
        from utils.cert_helper import should_renew, generate_self_signed_cert
        if should_renew(cert_path):
            key_path = self.settings_service.get_setting("ssl_keyfile", "")
            if key_path:
                try:
                    generate_self_signed_cert(cert_path, key_path)
                    logger.info("SSL证书已自动续期")
                except Exception as e:
                    logger.error(f"SSL证书自动续期失败: {e}")

    def show_settings(self):
        from ui.dialogs.settings_dialog import SettingsDialog
        dialog = SettingsDialog(self.root, self.settings_service, self.on_settings_saved)
        self.root.wait_window(dialog)

    def on_settings_saved(self, ssl_toggled=False):
        if ssl_toggled and self.server_tab.server_instance is not None:
            if messagebox.askyesno("重启服务器", "HTTPS 设置已更改，是否立即重启服务器以生效？"):
                self.server_tab.stop_server()
                self.server_tab.start_server()
            else:
                messagebox.showinfo("提示", "HTTPS 设置将在下次启动服务器时生效。")
        from utils.auto_start import set_auto_start
        auto_start = self.settings_service.get_setting("auto_start_app", "False") == "True"
        set_auto_start(auto_start)
        from ui.widgets.toast import Toast
        Toast.success(self.root, "设置已保存")

    def _sync_mcp_server(self):
        enabled = self.settings_service.get_setting("mcp_enabled", "False") == "True"
        if enabled:
            if self.mcp_server is None:
                from services.mcp_server import MCPServer
                self.mcp_server = MCPServer()
            if not self.mcp_server.is_running:
                port = int(self.settings_service.get_setting("mcp_port", "8100"))
                self.mcp_server.start(port=port,
                    on_ready=lambda: event_bus.publish(EVENT_SERVER_STATE_CHANGED))
        elif self.mcp_server is not None and self.mcp_server.is_running:
            self.mcp_server.stop()
            event_bus.publish(EVENT_SERVER_STATE_CHANGED)

    def process_log_queue(self):
        self.logging_manager.process_queue(self.server_tab)
        self.root.after(100, self.process_log_queue)

    def on_closing(self):
        if not self._tray_available:
            self._do_quit()
            return
        action = self.settings_service.get_setting("close_action", "ask")
        if action == "exit":
            self._do_quit()
            return
        if action == "tray":
            self._hide_to_tray()
            return
        self._show_close_dialog()

    def _show_close_dialog(self):
        from utils.window_utils import center_window
        dialog = tk.Toplevel(self.root); dialog.title("退出确认")
        dialog.transient(self.root); dialog.grab_set(); dialog.resizable(False, False)
        center_window(dialog, self.root)
        ttk.Label(dialog, text="关闭窗口时执行的操作：", font=('', 11)).pack(pady=(15, 5))
        var = tk.StringVar(value="tray")
        ttk.Radiobutton(dialog, text="退出程序", variable=var, value="exit").pack(anchor="w", padx=40, pady=2)
        ttk.Radiobutton(dialog, text="隐藏到系统托盘", variable=var, value="tray").pack(anchor="w", padx=40, pady=2)
        remember_var = tk.BooleanVar()
        ttk.Checkbutton(dialog, text="记住选择，不再询问", variable=remember_var).pack(anchor="w", padx=40, pady=5)
        btn_f = ttk.Frame(dialog); btn_f.pack(pady=10)
        def confirm():
            chosen = var.get()
            if remember_var.get():
                self.settings_service.set_setting("close_action", chosen)
            dialog.destroy()
            if chosen == "exit":
                self._do_quit()
            else:
                self._hide_to_tray()
        ttk.Button(btn_f, text="确定", command=confirm).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="取消", command=lambda: dialog.destroy() or None).pack(side=tk.LEFT, padx=5)

    def _hide_to_tray(self):
        self.root.withdraw()
        self._tray_notify("仍在后台运行，点击托盘图标可恢复窗口")

    def _do_quit(self):
        self.server_tab.stop_server()
        if self.mcp_server is not None:
            self.mcp_server.stop()
        if hasattr(self, '_tray'):
            self._tray.stop()
        from database.db_manager import Database
        Database().close()
        self.root.destroy()

    def _tray_notify(self, text):
        try:
            if self._tray and self._tray._icon:
                self._tray._icon.notify(text, SOFTWARE_NAME)
        except Exception:
            pass

    def _tray_show(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _tray_quit(self):
        self._do_quit()

    def check_update_now(self):
        from utils.update_checker import check_update_async
        self.status_bar.config(text="正在检查更新…")
        def _on_result(r):
            self.root.after(0, lambda: self._show_update_result(r))
        check_update_async(_on_result)

    def _show_update_result(self, r):
        from tkinter import Toplevel, scrolledtext
        self.status_bar_mgr.tick(self.root)
        if not r.get("has_update"):
            messagebox.showinfo("检查更新", f"已是最新版本（v{r['current']}）", parent=self.root)
            return

        releases = r["releases"]
        latest = r["latest"]

        dialog = Toplevel(self.root)
        dialog.title(f"发现新版本 v{latest}")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("520x440")
        dialog.minsize(420, 320)
        from utils.window_utils import center_window
        center_window(dialog, self.root)

        ttk.Label(dialog, text=f"当前版本: v{r['current']}  →  最新版本: v{latest}",
                  font=('', 11)).pack(anchor="w", padx=12, pady=(10, 5))

        ttk.Label(dialog, text="以下版本更新内容:", foreground="gray").pack(
            anchor="w", padx=12, pady=(0, 5))

        txt = scrolledtext.ScrolledText(dialog, wrap="word", state="normal",
                                         font=('Consolas', 10), height=14)
        txt.pack(fill=tk.BOTH, expand=True, padx=12, pady=5)

        for rel in releases:
            ver = rel["version"]
            body = rel["body"]
            is_latest = (ver == latest)
            tag = f"  ★ v{ver}（最新）" if is_latest else f"  v{ver}"
            txt.insert(tk.END, tag + "\n", "header")
            txt.insert(tk.END, body.rstrip() + "\n\n", "body")

        txt.tag_config("header", font=('', 10, 'bold'), foreground="#2563eb")
        txt.tag_config("body", font=('Consolas', 9), foreground="#374151")
        txt.config(state="disabled")

        btn_f = ttk.Frame(dialog)
        btn_f.pack(fill=tk.X, padx=12, pady=(0, 12))
        ttk.Label(btn_f, text="下载按钮将下载最新版本。",
                  foreground="gray").pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="下载", command=lambda: self._open_download(r["url"])
                   ).pack(side=tk.RIGHT, padx=3)
        ttk.Button(btn_f, text="关闭", command=dialog.destroy).pack(side=tk.RIGHT, padx=3)

    @staticmethod
    def _open_download(url):
        webbrowser.open(url)

    def _auto_check_update(self):
        from utils.update_checker import check_update_async
        s = self.settings_service
        if s.get_setting("auto_check_update", "True") != "True":
            return
        def _on_result(r):
            self.root.after(0, lambda: self._on_auto_update_result(r))
        self.status_bar_mgr.set_pending_update(None)
        check_update_async(_on_result)

    def _on_auto_update_result(self, r):
        if r.get("has_update"):
            self.status_bar_mgr.set_pending_update(r["latest"])

    def open_project_url(self):
        webbrowser.open("https://github.com/hunyanjie/PersonalDAV")
