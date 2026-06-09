import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
from ui.widgets.collapsible_frame import CollapsibleFrame
from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED
from ui.dialogs.settings_security import SecuritySettingsSection
from ui.dialogs.settings_reminders import ReminderPresetSection
from utils.timezone_helper import TimezoneHelper
from utils.cert_helper import generate_self_signed_cert, get_cert_info
from models.setting_defs import SettingDef
from models.constants import STATUS_MAPPING, TRANSPARENCY_MAPPING, REPEAT_OPTIONS, END_CONDITIONS
from services.auth_service import AuthService
from datetime import datetime
from utils.validators import validate_port
from ui.dialogs.confirm_dialog import ConfirmDialog


SIMPLE_SETTINGS = [
    # 新增设置只需在此列表添加一行 SettingDef。
    # 参数: (key, label, widget_type, section, default, [db_default], [options], [width], [spin_from/to], [columnspan], [display_map])
    # widget_type: "check" 复选框 | "entry" 输入框 | "combo" 下拉框 | "spin" 数字框 | "scale" 滑块 | "sep" 分隔线
    # display_map: {显示值: 数据库值}，用于 combo 中显示中文、存储英文的场景
    # ========== 服务器控制 ==========
    SettingDef("auto_save_port", "自动保存端口号", "check", "服务器控制", default=True, db_default="True"),
    SettingDef("auto_start_server", "启动时自动启动服务器", "check", "服务器控制", default=False, db_default="False"),
    SettingDef("default_port", "默认端口号:", "entry", "服务器控制", default="8000", width=10),

    # ========== MCP 设置 ==========
    SettingDef("mcp_enabled", "启用 MCP 服务", "check", "MCP 服务", default=False, db_default="False"),
    SettingDef("mcp_port", "MCP 服务端口:", "entry", "MCP 服务", default="8100", width=10),
    SettingDef("auto_check_update", "启动时自动检查更新", "check", "基本设置", default=True, db_default="True"),
    SettingDef("mcp_readonly", "只读模式（禁止写操作）", "check", "MCP 服务", default=False, db_default="False"),

    # ========== 基本设置 ==========
    SettingDef("default_status", "默认事件状态:", "combo", "基本设置",
               default="已确认", db_default="CONFIRMED",
               options=list(STATUS_MAPPING.keys()),
               display_map=STATUS_MAPPING),
    SettingDef("default_version", "默认日历版本:", "combo", "基本设置",
                default="2.0", options=["1.0", "2.0", "2.1", "3.0"], width=10),
    SettingDef("default_priority", "默认优先级 (0-9):", "scale", "基本设置",
               default=5, db_default="5", spin_from=0, spin_to=9),
    SettingDef("default_transparency", "默认透明度:", "combo", "基本设置",
               default="忙碌", db_default="OPAQUE",
               options=list(TRANSPARENCY_MAPPING.keys()),
               display_map=TRANSPARENCY_MAPPING, width=10),
    SettingDef("default_sync_timezone", "结束时间使用相同时区", "check", "基本设置",
               default=True, db_default="True", columnspan=2),
    SettingDef("_sep1", "", "sep", "基本设置"),
    SettingDef("default_repeat", "默认重复规则:", "combo", "基本设置",
               default="不重复", options=REPEAT_OPTIONS, width=12),
    SettingDef("default_end_cond", "默认结束条件:", "combo", "基本设置",
               default="永不结束", options=END_CONDITIONS, width=12),
    SettingDef("default_end_count", "默认结束次数:", "spin", "基本设置",
               default="5", spin_from=1, spin_to=999, width=5),
    SettingDef("default_allday", "默认创建全天事件", "check", "基本设置",
               default=False, db_default="False", columnspan=2),
    SettingDef("default_force_reminder", "默认勾选强制提醒", "check", "基本设置",
               default=False, db_default="False", columnspan=2),
    SettingDef("_sep2", "", "sep", "基本设置"),
    SettingDef("auto_start_app", "开机时自动启动程序", "check", "服务器控制",
               default=False, db_default="False"),
    SettingDef("auto_start_ftp", "启动时自动启动文件服务 (FTP/SFTP/TFTP)", "check",
               "服务器控制", default=False, db_default="False"),
    SettingDef("ftps_enabled", "启用 FTPS (SSL)", "check", "服务器控制",
               default=False, db_default="False"),
    SettingDef("ftp_encoding", "FTP 文件编码:", "combo", "服务器控制",
               default="utf-8",
               options=["utf-8", "gbk", "gb2312", "big5", "shift-jis",
                        "euc-kr", "euc-jp", "cp1252", "iso-8859-1",
                        "cp1250", "cp1251", "koi8-r"],
               width=10),
    SettingDef("attachment_mode", "日历附件模式:", "combo", "服务器控制",
               default="内联 Base64", db_default="inline",
               options=["内联 Base64", "HTTP 链接"],
               display_map={"内联 Base64": "inline", "HTTP 链接": "uri"}, width=12),
    # ========== 安全设置 ==========
    # force_password / rate_limit 手工构建于 create_security_settings
    SettingDef("start_time_snap", "新建日程默认开始时间:", "combo", "基本设置",
               default="当前时间", db_default="current",
               options=["当前时间", "5整数倍", "10整数倍", "15整数倍", "30整数倍"],
               display_map={"当前时间": "current", "5整数倍": "5", "10整数倍": "10",
                            "15整数倍": "15", "30整数倍": "30"}, width=12),
]


class SettingsDialog(tk.Toplevel):
    """系统设置对话框 - 声明式设置管理"""
    def __init__(self, parent, db_service, on_save_callback):
        super().__init__(parent)
        self.title("设置")
        # self.geometry("800x750")
        self.transient(parent)
        self.grab_set()
        self.db = db_service
        self.on_save_callback = on_save_callback
        self._port_ck_fns = {}
        self._security_section = SecuritySettingsSection(self)
        self._reminder_section = ReminderPresetSection(self)

        main_frame = ttk.Frame(self); main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook = ttk.Notebook(main_frame); notebook.pack(fill=tk.BOTH, expand=True)

        server_frame = ttk.Frame(notebook); notebook.add(server_frame, text="服务器设置")
        calendar_frame = ttk.Frame(notebook); notebook.add(calendar_frame, text="日历设置")
        log_frame = ttk.Frame(notebook); notebook.add(log_frame, text="日志设置")
        security_frame = ttk.Frame(notebook); notebook.add(security_frame, text="安全设置")
        sync_frame = ttk.Frame(notebook); notebook.add(sync_frame, text="同步设置")
        audit_frame = ttk.Frame(notebook); notebook.add(audit_frame, text="审计日志")
        mcp_frame = ttk.Frame(notebook); notebook.add(mcp_frame, text="MCP 服务")

        self.create_server_settings(server_frame)
        self.create_calendar_settings(calendar_frame)
        self.create_log_settings(log_frame)
        self._security_section.create_ui(security_frame)
        self.create_sync_settings(sync_frame)
        self.create_audit_log_viewer(audit_frame)
        self.create_mcp_settings(mcp_frame)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="重置设置", command=self.reset_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="保存", command=self.save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=5)

        self.load_settings()
        from utils.window_utils import center_window
        center_window(self, parent)

    # ── 声明式引擎 ──────────────────────────────────────────────

    def _build_simple(self, parent, section, start_row=0):
        row = start_row
        for d in SIMPLE_SETTINGS:
            if d.section != section:
                continue
            if d.widget_type == "check":
                var = tk.BooleanVar()
                ttk.Checkbutton(parent, text=d.label, variable=var).grid(
                    row=row, column=0, columnspan=max(1, d.columnspan), sticky="w", padx=5, pady=5)
                setattr(self, f"{d.key}_var", var)
            elif d.widget_type == "entry":
                ttk.Label(parent, text=d.label).grid(row=row, column=0, sticky="w", padx=5, pady=5)
                var = tk.StringVar()
                ttk.Entry(parent, textvariable=var, width=d.width or 20).grid(row=row, column=1, sticky="w")
                setattr(self, f"{d.key}_var", var)
            elif d.widget_type == "combo":
                ttk.Label(parent, text=d.label).grid(row=row, column=0, sticky="w", padx=5, pady=5)
                var = tk.StringVar()
                ttk.Combobox(parent, textvariable=var, values=d.options, state="readonly",
                             width=d.width or 12).grid(row=row, column=1, sticky="w")
                setattr(self, f"{d.key}_var", var)
            elif d.widget_type == "spin":
                ttk.Label(parent, text=d.label).grid(row=row, column=0, sticky="w", padx=5, pady=5)
                var = tk.StringVar()
                ttk.Spinbox(parent, textvariable=var, from_=d.spin_from or 1, to=d.spin_to or 99,
                            width=d.width or 5).grid(row=row, column=1, sticky="w")
                setattr(self, f"{d.key}_var", var)
            elif d.widget_type == "scale":
                ttk.Label(parent, text=d.label).grid(row=row, column=0, sticky="w", padx=5, pady=5)
                var = tk.IntVar()
                frame = ttk.Frame(parent)
                frame.grid(row=row, column=1, sticky="w")
                label = ttk.Label(frame, text=f" {d.default} ", width=3, relief=tk.RIDGE, anchor="center")
                ttk.Scale(frame, from_=d.spin_from or 0, to=d.spin_to or 9, variable=var,
                          orient='horizontal', length=150,
                          command=lambda v, lb=label: lb.config(text=f" {int(float(v))} ")).pack(side=tk.LEFT)
                label.pack(side=tk.LEFT, padx=5)
                setattr(self, f"{d.key}_var", var)
                setattr(self, f"{d.key}_label", label)
            elif d.widget_type == "sep":
                ttk.Separator(parent, orient='horizontal').grid(
                    row=row, column=0, columnspan=2, sticky='ew', pady=5)
            row += 1
        return row

    def _load_simple(self):
        s = self.db
        for d in SIMPLE_SETTINGS:
            if d.widget_type == "sep":
                continue
            var = getattr(self, f"{d.key}_var")
            if d.widget_type == "check":
                var.set(s.get_setting(d.key, d.db_default) == "True")
            elif d.display_map:
                rev = {v: k for k, v in d.display_map.items()}
                var.set(rev.get(s.get_setting(d.key, d.db_default), d.default))
            elif d.widget_type == "scale":
                val = int(s.get_setting(d.key, d.db_default))
                var.set(val)
                label = getattr(self, f"{d.key}_label", None)
                if label: label.config(text=f" {val} ")
            else:
                var.set(s.get_setting(d.key, d.db_default))

    def _save_simple(self):
        s = self.db
        for d in SIMPLE_SETTINGS:
            if d.widget_type == "sep":
                continue
            var = getattr(self, f"{d.key}_var")
            if d.widget_type == "check":
                s.set_setting(d.key, str(var.get()))
            elif d.display_map:
                s.set_setting(d.key, d.display_map.get(var.get(), d.db_default))
            elif d.widget_type == "scale":
                s.set_setting(d.key, str(var.get()))
            else:
                s.set_setting(d.key, str(var.get()))

    def _reset_simple(self):
        for d in SIMPLE_SETTINGS:
            if d.widget_type == "sep":
                continue
            var = getattr(self, f"{d.key}_var")
            if d.widget_type == "scale":
                var.set(d.default)
                label = getattr(self, f"{d.key}_label", None)
                if label: label.config(text=f" {d.default} ")
            else:
                var.set(d.default)

    # ── 服务器设置 ──────────────────────────────────────────────

    def _setup_port_validation(self, parent_frame, key):
        if not hasattr(self, f"{key}_var"):
            return
        var = getattr(self, f"{key}_var")
        target = str(var)
        for child in parent_frame.winfo_children():
            if not isinstance(child, ttk.Entry):
                continue
            if str(child.cget("textvariable")) != target:
                continue
            def _ck(*_, entry=child):
                ok, msg = validate_port(entry.get())
                entry.config(foreground="red" if not ok else "orange" if msg else "black")
            var.trace("w", _ck)
            self._port_ck_fns[key] = _ck
            break

    def _refresh_port_validations(self):
        for fn in self._port_ck_fns.values():
            fn()

    def create_server_settings(self, parent):
        f = ttk.LabelFrame(parent, text="服务器控制")
        f.pack(fill=tk.X, padx=5, pady=5)
        self._build_simple(f, "服务器控制")
        self._setup_port_validation(f, "default_port")

        close_f = ttk.LabelFrame(parent, text="关闭行为")
        close_f.pack(fill=tk.X, padx=5, pady=5)
        self.close_action_var = tk.StringVar(value="ask")
        ttk.Radiobutton(close_f, text="每次都询问", variable=self.close_action_var, value="ask").pack(anchor="w", padx=10, pady=2)
        ttk.Radiobutton(close_f, text="退出程序", variable=self.close_action_var, value="exit").pack(anchor="w", padx=10, pady=2)
        ttk.Radiobutton(close_f, text="隐藏到系统托盘", variable=self.close_action_var, value="tray").pack(anchor="w", padx=10, pady=2)

        ssl_f = CollapsibleFrame(parent, text="SSL/TLS 设置", expanded=False)
        ssl_f.pack(fill=tk.X, padx=5, pady=2)
        body = ssl_f.body

        self.ssl_enabled_var = tk.BooleanVar()
        ttk.Checkbutton(body, text="启用 HTTPS (SSL/TLS)", variable=self.ssl_enabled_var).grid(
            row=0, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        ttk.Label(body, text="证书文件 (.pem):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.ssl_cert_var = tk.StringVar()
        ttk.Entry(body, textvariable=self.ssl_cert_var).grid(row=1, column=1, sticky="we", padx=2)
        ttk.Button(body, text="浏览...", command=lambda: self._browse_ssl("cert")).grid(row=1, column=2, padx=2)

        ttk.Label(body, text="密钥文件 (.key):").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.ssl_key_var = tk.StringVar()
        ttk.Entry(body, textvariable=self.ssl_key_var).grid(row=2, column=1, sticky="we", padx=2)
        ttk.Button(body, text="浏览...", command=lambda: self._browse_ssl("key")).grid(row=2, column=2, padx=2)

        btn_f = ttk.Frame(body)
        btn_f.grid(row=3, column=0, columnspan=3, pady=5)
        ttk.Button(btn_f, text="一键生成自签名证书", command=self._generate_cert).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="手动创建证书指引", command=self._show_cert_guide).pack(side=tk.LEFT, padx=5)

        self._cert_info_label = ttk.Label(body, text="", foreground="gray")
        self._cert_info_label.grid(row=4, column=0, columnspan=3, sticky="w", padx=5, pady=2)
        self._auto_renew_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="自动续期（证书到期前自动生成新证书）",
                        variable=self._auto_renew_var).grid(row=5, column=0, columnspan=3, sticky="w", padx=5, pady=2)
        body.grid_columnconfigure(1, weight=1)

        # FTP / WebDAV 设置
        extra_f = ttk.LabelFrame(parent, text="FTP / WebDAV 设置")
        extra_f.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(extra_f, text="WebDAV 根目录:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.dav_root_var = tk.StringVar()
        ttk.Entry(extra_f, textvariable=self.dav_root_var).grid(row=0, column=1, sticky="we", padx=2)
        ttk.Button(extra_f, text="浏览...", command=lambda: self._browse_dir(self.dav_root_var)).grid(row=0, column=2, padx=2)
        ttk.Label(extra_f, text="FTP 独立密码:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.ftp_password_var = tk.StringVar()
        ttk.Entry(extra_f, textvariable=self.ftp_password_var, show="*").grid(row=1, column=1, sticky="we", padx=2)
        ttk.Label(extra_f, text="（留空=统一账号）").grid(row=1, column=2, sticky="w", padx=2)
        extra_f.grid_columnconfigure(1, weight=1)

        # 备份与恢复
        bk_f = CollapsibleFrame(parent, text="备份与恢复")
        bk_f.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(bk_f.body, text="备份包含数据库、设置及日志文件。恢复将关闭当前数据库并替换。",
                  foreground="gray", wraplength=500).pack(anchor="w", padx=10, pady=2)
        btn_f = ttk.Frame(bk_f.body)
        btn_f.pack(pady=5)
        ttk.Button(btn_f, text="导出备份 (.zip)", command=self._export_backup).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="从备份恢复", command=self._import_backup).pack(side=tk.LEFT, padx=5)
        ttk.Separator(bk_f.body, orient="horizontal").pack(fill="x", padx=10, pady=5)
        ttk.Label(bk_f.body, text="数据删除后数据库文件不会自动缩小。压缩将重写数据库以释放空闲空间。",
                  foreground="gray", wraplength=500).pack(anchor="w", padx=10, pady=2)
        ttk.Button(bk_f.body, text="压缩数据库", command=self._compact_db).pack(anchor="w", padx=10, pady=3)

    # ── 同步设置 ────────────────────────────────────────────────

    def create_sync_settings(self, parent):
        f = ttk.LabelFrame(parent, text="Nextcloud 同步")
        f.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(f, text="服务器 URL:").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.sync_url_var = tk.StringVar()
        enf = ttk.Frame(f)
        enf.grid(row=0, column=1, columnspan=2, sticky="we", padx=2)
        ttk.Entry(enf, textvariable=self.sync_url_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(enf, text="https://example.com/remote.php/dav/", foreground="gray").pack(side=tk.LEFT, padx=5)

        ttk.Label(f, text="用户名:").grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.sync_user_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.sync_user_var).grid(row=1, column=1, columnspan=2, sticky="we", padx=2, pady=3)

        ttk.Label(f, text="应用密码:").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        self.sync_password_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.sync_password_var, show="*").grid(row=2, column=1, columnspan=2, sticky="we", padx=2, pady=3)

        ttk.Label(f, text="同步间隔:").grid(row=3, column=0, sticky="w", padx=5, pady=3)
        sf = ttk.Frame(f)
        sf.grid(row=3, column=1, columnspan=2, sticky="w", padx=2)
        self.sync_interval_var = tk.StringVar(value="30")
        ttk.Spinbox(sf, from_=5, to=1440, textvariable=self.sync_interval_var, width=6).pack(side=tk.LEFT)
        ttk.Label(sf, text="分钟").pack(side=tk.LEFT, padx=2)

        self.sync_enabled_var = tk.BooleanVar()
        ttk.Checkbutton(f, text="启用定时同步", variable=self.sync_enabled_var).grid(row=4, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        ttk.Label(f, text="提示：在 Nextcloud 安全设置中生成「应用密码」，建议不要使用主密码。",
                  foreground="gray", wraplength=500).grid(row=5, column=0, columnspan=3, sticky="w", padx=5, pady=2)
        f.grid_columnconfigure(1, weight=1)


    # ── 安全设置 ────────────────────────────────────────────────
    # 已提取至 SecuritySettingsSection



    # ── MCP 服务设置 ────────────────────────────────────────────

    def create_mcp_settings(self, parent):
        f = ttk.LabelFrame(parent, text="MCP 服务控制")
        f.pack(fill=tk.X, padx=5, pady=5)
        self._build_simple(f, "MCP 服务")

        info = ttk.LabelFrame(parent, text="连接信息")
        info.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(info, text="启用后在 AI 工具（如 opencode）中配置以下 URL 即可连接：",
                  wraplength=500).pack(anchor="w", padx=10, pady=5)
        self._mcp_url_label = ttk.Label(info, text="", foreground="blue", font=('Consolas', 10))
        self._mcp_url_label.pack(anchor="w", padx=10, pady=5)
        ttk.Label(info, text="提示：更改端口后需重启程序或重新打开设置以刷新 URL。",
                  foreground="gray", wraplength=500).pack(anchor="w", padx=10, pady=5)

        self._setup_port_validation(f, "mcp_port")

        def update_url(*_):
            port = self.mcp_port_var.get() if hasattr(self, 'mcp_port_var') else "8100"
            self._mcp_url_label.config(text=f"URL: http://127.0.0.1:{port}/sse")

        if hasattr(self, 'mcp_port_var'):
            self.mcp_port_var.trace("w", update_url)
        self.after(100, update_url)

        tools = ttk.LabelFrame(parent, text="可用工具列表")
        tools.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        cols = ("工具名", "类别", "说明")
        tree = ttk.Treeview(tools, columns=cols, show="headings", height=20)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=200 if c == "说明" else 100)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(tools, orient=tk.VERTICAL, command=tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scroll.set)

        tool_list = [
            ("server_start(port)", "服务端管理", "启动 DAV 服务器"),
            ("server_stop()", "服务端管理", "停止 DAV 服务器"),
            ("server_status()", "服务端管理", "查询 DAV 服务器状态"),
            ("list_contacts()", "联系人", "列出所有联系人"),
            ("get_contact(uid)", "联系人", "获取联系人 vCard"),
            ("create_contact(vcard)", "联系人", "从 vCard 创建联系人"),
            ("update_contact(uid, vcard)", "联系人", "更新联系人"),
            ("delete_contact(uid)", "联系人", "删除联系人"),
            ("list_events()", "日历", "列出所有事件"),
            ("get_event(uid)", "日历", "获取事件 iCalendar"),
            ("create_event(ical)", "日历", "从 iCal 创建事件"),
            ("update_event(uid, ical)", "日历", "更新事件"),
            ("delete_event(uid)", "日历", "删除事件"),
            ("get_config()", "系统", "返回系统配置"),
            ("dav_health_check(url)", "系统", "验证 DAV 端点"),
            ("ftp_servers_start()", "文件服务", "启动 FTP/SFTP/TFTP"),
            ("ftp_servers_stop()", "文件服务", "停止文件传输服务"),
            ("ftp_servers_status()", "文件服务", "查询文件服务状态"),
            ("ftp_list_dir(...)", "远程文件", "浏览 FTP/FTPS 目录"),
            ("ftp_download(...)", "远程文件", "从远程下载文件"),
            ("ftp_upload(...)", "远程文件", "上传文件到远程"),
            ("ftp_delete(...)", "远程文件", "删除远程文件"),
            ("ftp_rename(...)", "远程文件", "重命名远程文件"),
            ("ftp_mkdir(...)", "远程文件", "远程创建目录"),
            ("ftp_rmdir(...)", "远程文件", "远程删除目录"),
            ("smb_list_shares(...)", "远程文件", "列出 SMB 共享"),
            ("smb_list_files(...)", "远程文件", "浏览 SMB 共享"),
        ]
        for name, cat, desc in tool_list:
            tree.insert("", tk.END, values=(name, cat, desc))

    # ── 审计日志查看器 ──────────────────────────────────────────

    def create_audit_log_viewer(self, parent):
        from services.auth_service import AuthService
        filter_var = tk.StringVar(value="全部")
        filter_frame = ttk.Frame(parent)
        filter_frame.pack(fill=tk.X, padx=5, pady=(5, 0))
        ttk.Label(filter_frame, text="协议筛选:").pack(side=tk.LEFT, padx=2)
        filter_combo = ttk.Combobox(filter_frame, textvariable=filter_var, state="readonly", width=12,
                                    values=["全部", "WebDAV", "FTP", "FTPS", "SFTP", "MCP"])
        filter_combo.pack(side=tk.LEFT, padx=2)

        cols = ("时间", "IP", "状态", "协议", "详情")
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=20)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=180 if c == "时间" else 140 if c == "IP" else 80)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scroll.set)

        def refresh(*_):
            tree.delete(*tree.get_children())
            proto = filter_var.get()
            logs = AuthService().get_auth_logs_filtered(protocol="" if proto == "全部" else proto, limit=500)
            for log in logs:
                tag = "success" if log["success"] else "failure"
                status = "成功" if log["success"] else "失败"
                tree.insert("", tk.END, values=(log["time"], log["ip"], status, log["method"], log["detail"]), tags=(tag,))
            tree.tag_configure("success", foreground="green")
            tree.tag_configure("failure", foreground="red")

        filter_combo.bind("<<ComboboxSelected>>", refresh)

        btn_f = ttk.Frame(parent)
        btn_f.pack(fill=tk.X, padx=5, pady=(0, 5))
        ttk.Button(btn_f, text="刷新", command=refresh).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="清空日志", command=lambda: [
            __import__("database.db_manager", fromlist=["Database"]).Database().execute("DELETE FROM auth_logs"), refresh()
        ]).pack(side=tk.LEFT, padx=2)

        refresh()

    # ── 日历设置 ────────────────────────────────────────────────

    def create_calendar_settings(self, parent):
        nb = ttk.Notebook(parent); nb.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        b_t = ttk.Frame(nb); nb.add(b_t, text="基本设置")
        p_t = ttk.Frame(nb); nb.add(p_t, text="预设提醒")

        row = self._build_simple(b_t, "基本设置")

        # 手动构建持续时间行（小时+分钟 Spinbox + 常用预设按钮）
        ttk.Separator(b_t, orient='horizontal').grid(row=row, column=0, columnspan=2, sticky='ew', pady=(10, 5))
        row += 1
        ttk.Label(b_t, text="默认持续时间:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
        df = ttk.Frame(b_t); df.grid(row=row, column=1, sticky="w", padx=5)
        self._dur_h_var = tk.StringVar(value="1")
        self._dur_m_var = tk.StringVar(value="0")
        ttk.Spinbox(df, textvariable=self._dur_h_var, from_=0, to=23, width=3).pack(side=tk.LEFT)
        ttk.Label(df, text="小时").pack(side=tk.LEFT, padx=1)
        ttk.Spinbox(df, textvariable=self._dur_m_var, from_=0, to=59, width=3).pack(side=tk.LEFT)
        ttk.Label(df, text="分钟").pack(side=tk.LEFT, padx=1)

        ttk.Label(df, text="  预设:").pack(side=tk.LEFT)
        for label, h, m in [("30分", 0, 30), ("1小时", 1, 0), ("1h30m", 1, 30), ("2小时", 2, 0)]:
            ttk.Button(df, text=label, width=6,
                       command=lambda h=h, m=m: (
                           self._dur_h_var.set(str(h)), self._dur_m_var.set(str(m))
                       )).pack(side=tk.LEFT, padx=2)
        row += 1

        # 数据存储目录
        ttk.Separator(b_t, orient='horizontal').grid(row=row, column=0, columnspan=2, sticky='ew', pady=(10, 5))
        row += 1
        ttk.Label(b_t, text="数据存储目录（留空=程序所在目录）:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
        dir_f = ttk.Frame(b_t)
        dir_f.grid(row=row, column=1, sticky="w", padx=5)
        self.data_dir_var = tk.StringVar()
        ttk.Entry(dir_f, textvariable=self.data_dir_var, width=40).pack(side=tk.LEFT)
        ttk.Button(dir_f, text="浏览...", command=self._browse_data_dir).pack(side=tk.LEFT, padx=5)
        row += 1

        self._create_timezone_format_ui(b_t)
        self._reminder_section.create_ui(p_t)

    def _create_timezone_format_ui(self, parent):
        sep = ttk.Separator(parent, orient='horizontal')
        sep.grid(row=100, column=0, columnspan=2, sticky='ew', pady=5)

        ttk.Label(parent, text="时区显示格式:", font=('', 9, 'bold')).grid(row=101, column=0, sticky="w", padx=5)
        ttk.Label(parent, text="{offset} {city} {tz_id} {localized} {local_tag} 等占位符可自由组合",
                  foreground="gray").grid(row=102, column=0, columnspan=2, sticky="w", padx=5)

        self.tz_fmt_var = tk.StringVar()
        entry = ttk.Entry(parent, textvariable=self.tz_fmt_var, width=70)
        entry.grid(row=103, column=0, columnspan=2, sticky="ew", padx=5, pady=(2, 0))

        # 实时预览
        self._tz_preview_label = ttk.Label(parent, text="", foreground="gray", font=('', 8))
        self._tz_preview_label.grid(row=104, column=0, columnspan=2, sticky="w", padx=5, pady=(0, 2))

        def _update_preview(*_):
            fmt = self.tz_fmt_var.get()
            tz_id = TimezoneHelper.get_local_timezone_id()
            try:
                preview = TimezoneHelper._format_one(
                    tz_id, fmt, tz_id, TimezoneHelper._build_sys_locale()
                )
            except Exception:
                preview = "(格式无效)"
            self._tz_preview_label.config(text=f"预览: {preview}")

        self.tz_fmt_var.trace("w", _update_preview)
        self.after(100, _update_preview)

        pf = ttk.Frame(parent); pf.grid(row=105, column=0, columnspan=2, sticky="w", padx=5, pady=2)
        presets = [
            ("完整", "{offset} - {city} ({tz_id}) {localized}{local_tag}"),
            ("城市+ID+名称", "{city} ({tz_id}) {localized}{local_tag}"),
            ("城市+名称+偏移", "{city} {localized} ({offset}){local_tag}"),
            ("名称+城市+ID", "{localized} - {city} ({tz_id}){local_tag}"),
            ("ID+城市", "{tz_id} ({city})"),
            ("仅城市+名称", "{city} {localized}{local_tag}"),
            ("仅ID", "{tz_id}"),
        ]
        for label, fmt in presets:
            ttk.Button(pf, text=label, width=14,
                       command=lambda v=fmt: self.tz_fmt_var.set(v)).pack(side=tk.LEFT, padx=1)

    def create_preset_settings(self, parent):
        p_m_f = ttk.LabelFrame(parent, text="管理预设项 (右键菜单内容)")
        p_m_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(p_m_f, text="常规预设:").grid(row=0, column=0, sticky="w", padx=5)
        p_r_f = ttk.Frame(p_m_f); p_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.preset_reminders_listbox = tk.Listbox(p_r_f, height=4, exportselection=False)
        self.preset_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_r_sb = ttk.Scrollbar(p_r_f, orient=tk.VERTICAL, command=self.preset_reminders_listbox.yview)
        p_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_reminders_listbox.config(yscrollcommand=p_r_sb.set)
        self.preset_reminders_listbox.bind("<Double-1>", lambda e: self.edit_preset_reminder())

        ttk.Label(p_m_f, text="全天预设:").grid(row=0, column=1, sticky="w", padx=5)
        p_a_f = ttk.Frame(p_m_f); p_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.preset_allday_reminders_listbox = tk.Listbox(p_a_f, height=4, exportselection=False)
        self.preset_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_a_sb = ttk.Scrollbar(p_a_f, orient=tk.VERTICAL, command=self.preset_allday_reminders_listbox.yview)
        p_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_allday_reminders_listbox.config(yscrollcommand=p_a_sb.set)
        self.preset_allday_reminders_listbox.bind("<Double-1>", lambda e: self.edit_preset_reminder())

        p_btn = ttk.Frame(p_m_f); p_btn.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Button(p_btn, text="添加预设", command=self.add_preset_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="编辑预设", command=self.edit_preset_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="删除预设", command=self.delete_preset_reminder).pack(side=tk.LEFT, padx=2)

        a_c_f = ttk.LabelFrame(parent, text="新建日程时自动勾选")
        a_c_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(a_c_f, text="常规自动勾选:").grid(row=0, column=0, sticky="w", padx=5)
        d_r_f = ttk.Frame(a_c_f); d_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.default_reminders_listbox = tk.Listbox(d_r_f, selectmode='multiple', height=4, exportselection=False)
        self.default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_r_sb = ttk.Scrollbar(d_r_f, orient=tk.VERTICAL, command=self.default_reminders_listbox.yview)
        d_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.default_reminders_listbox.config(yscrollcommand=d_r_sb.set)
        for opt in ["日程发生时", "5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前", "2天前", "7天前"]:
            self.default_reminders_listbox.insert(tk.END, opt)

        ttk.Label(a_c_f, text="全天自动勾选:").grid(row=0, column=1, sticky="w", padx=5)
        d_a_f = ttk.Frame(a_c_f); d_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.default_allday_reminders_listbox = tk.Listbox(d_a_f, selectmode='multiple', height=4, exportselection=False)
        self.default_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_a_sb = ttk.Scrollbar(d_a_f, orient=tk.VERTICAL, command=self.default_allday_reminders_listbox.yview)
        d_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.default_allday_reminders_listbox.config(yscrollcommand=d_a_sb.set)
        for opt in ["当天上午9点", "1天前上午9点", "2天前上午9点", "3天前上午9点", "5天前上午9点", "7天前上午9点"]:
            self.default_allday_reminders_listbox.insert(tk.END, opt)

        c_d_f = ttk.LabelFrame(parent, text="自定义默认提醒 (新建日程时自动添加详情)")
        c_d_f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Label(c_d_f, text="常规自定义:").grid(row=0, column=0, sticky="w", padx=5)
        c_r_f = ttk.Frame(c_d_f); c_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.custom_default_reminders_listbox = tk.Listbox(c_r_f, height=3, exportselection=False)
        self.custom_default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        c_r_sb = ttk.Scrollbar(c_r_f, orient=tk.VERTICAL, command=self.custom_default_reminders_listbox.yview)
        c_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_default_reminders_listbox.config(yscrollcommand=c_r_sb.set)
        self.custom_default_reminders_listbox.bind("<Double-1>", lambda e: self.edit_custom_default_reminder(False))

        ttk.Label(c_d_f, text="全天自定义:").grid(row=0, column=1, sticky="w", padx=5)
        c_a_f = ttk.Frame(c_d_f); c_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.custom_default_allday_reminders_listbox = tk.Listbox(c_a_f, height=3, exportselection=False)
        self.custom_default_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        c_a_sb = ttk.Scrollbar(c_a_f, orient=tk.VERTICAL, command=self.custom_default_allday_reminders_listbox.yview)
        c_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_default_allday_reminders_listbox.config(yscrollcommand=c_a_sb.set)
        self.custom_default_allday_reminders_listbox.bind("<Double-1>", lambda e: self.edit_custom_default_reminder(True))

        c_btn = ttk.Frame(c_d_f); c_btn.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Button(c_btn, text="添加常规", command=lambda: self.add_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="编辑常规", command=lambda: self.edit_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="删除常规", command=lambda: self.delete_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="添加全天", command=lambda: self.add_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="编辑全天", command=lambda: self.edit_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="删除全天", command=lambda: self.delete_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)

    # ── 日志设置 ────────────────────────────────────────────────

    def create_log_settings(self, parent):
        f = ttk.LabelFrame(parent, text="日志记录"); f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.enable_log_file_var = tk.BooleanVar()
        ttk.Checkbutton(f, text="启用日志文件", variable=self.enable_log_file_var).grid(
            row=0, column=0, columnspan=3, sticky="w", padx=5, pady=10)
        ttk.Label(f, text="日志文件路径:").grid(row=1, column=0, padx=5)
        self.log_path_var = tk.StringVar()
        self.log_path_entry = ttk.Entry(f, textvariable=self.log_path_var, width=35)
        self.log_path_entry.grid(row=1, column=1)
        self.log_browse_btn = ttk.Button(f, text="浏览...", command=self.browse_log_file)
        self.log_browse_btn.grid(row=1, column=2, padx=5)
        ttk.Label(f, text="日志级别:").grid(row=2, column=0, padx=5, pady=10)
        self.log_level_var = tk.StringVar()
        self.log_level_combo = ttk.Combobox(f, textvariable=self.log_level_var,
                                            values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], state="readonly")
        self.log_level_combo.grid(row=2, column=1, sticky="w")
        def on_toggle(*args):
            st = tk.NORMAL if self.enable_log_file_var.get() else tk.DISABLED
            self.log_path_entry.config(state=st)
            self.log_browse_btn.config(state=st)
            self.log_level_combo.config(state=st)
        self.enable_log_file_var.trace("w", on_toggle)

    def browse_log_file(self):
        p = filedialog.asksaveasfilename(title="选择日志文件", filetypes=[("日志文件", "*.log"), ("所有文件", "*.*")], defaultextension=".log")
        if p: self.log_path_var.set(p)

    def _browse_ssl(self, target):
        path = filedialog.askopenfilename(title="选择文件", parent=self)
        if path:
            path = os.path.normpath(path)
            if target == "cert":
                self.ssl_cert_var.set(path)
            else:
                self.ssl_key_var.set(path)
            self._update_cert_info()

    def _browse_dir(self, var):
        path = filedialog.askdirectory(title="选择目录", parent=self)
        if path:
            var.set(os.path.normpath(path))

    def _generate_cert(self):
        dir_path = filedialog.askdirectory(title="选择证书保存目录", parent=self)
        if not dir_path:
            return
        cert_path = os.path.normpath(os.path.join(dir_path, "cert.pem"))
        key_path = os.path.normpath(os.path.join(dir_path, "key.pem"))
        try:
            generate_self_signed_cert(cert_path, key_path)
            self.ssl_cert_var.set(os.path.normpath(cert_path))
            self.ssl_key_var.set(os.path.normpath(key_path))
            self.ssl_enabled_var.set(True)
            self._update_cert_info()
            messagebox.showinfo("成功", f"自签名证书已生成：\n{cert_path}\n\n请将此证书添加到系统的信任列表中。\n\nmacOS: 双击 cert.pem → 钥匙串 → 信任 → 始终信任\niOS: 通过 Safari 下载安装描述文件", parent=self)
        except Exception as e:
            messagebox.showerror("生成失败", str(e), parent=self)

    def _show_cert_guide(self):
        win = tk.Toplevel(self); win.title("手动创建自签名证书")
        win.transient(self); win.grab_set()
        from utils.window_utils import center_window
        center_window(win, self)

        text = tk.Text(win, wrap=tk.WORD, padx=10, pady=10)
        scroll = ttk.Scrollbar(win, command=text.yview)
        text.config(yscrollcommand=scroll.set)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        guide = """一键生成的证书适用于基本使用场景。如果系统要求严格（如 iOS 16+ 证书要求），或需要指定更多参数，可按以下步骤手动创建。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
方法一：使用 OpenSSL（推荐）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. 安装 OpenSSL
   Windows: 从 https://slproweb.com/products/Win32OpenSSL.html 下载安装
   macOS:   brew install openssl
   Linux:   sudo apt install openssl

2. 在终端中运行以下命令：

   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3650 -nodes -subj "/CN=localhost"

   参数说明:
     -x509      生成自签名证书
     -newkey rsa:2048  创建 2048 位 RSA 密钥
     -keyout    私钥输出文件
     -out       证书输出文件
     -days 3650 有效期 10 年
     -nodes     不加密私钥（服务器需要）
     -subj      /CN=localhost  指定通用名

3. 将生成的 cert.pem 和 key.pem 放入同一个目录，
   然后在设置中选择这两个文件即可。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
信任证书（苹果设备必须）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

macOS:
   双击 cert.pem 打开钥匙串访问，
   找到该证书 → 右键"显示简介" → 信任 → 改为"始终信任"

iOS:
   将 cert.pem 上传至可下载的位置，
   用 Safari 打开 → 会提示安装描述文件 → 前往"设置"→"已下载的描述文件"安装
   → 进入"通用"→"关于本机"→"证书信任设置"中开启该证书

Windows:
   双击 cert.pem → 安装证书 → 选择"受信任的根证书颁发机构"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
验证证书是否正确
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  openssl x509 -in cert.pem -text -noout

查看输出中的 Subject: CN = localhost 和
X509v3 Subject Alternative Name: DNS:localhost 是否正确。"""

        text.insert(tk.END, guide)
        text.config(state=tk.DISABLED)

    def _update_cert_info(self):
        cert_path = self.ssl_cert_var.get().strip()
        info = get_cert_info(cert_path) if cert_path else None
        if info:
            color = "red" if info["remaining_days"] <= 30 else ("orange" if info["remaining_days"] <= 90 else "green")
            self._cert_info_label.config(
                text=f"证书状态: 颁发者={info['issuer']} | 有效期至={info['valid_to']} (剩余{info['remaining_days']}天)",
                foreground=color)
        else:
            self._cert_info_label.config(text="证书状态: 未选择证书或无法读取", foreground="gray")

    # ── 显示格式 ────────────────────────────────────────────────
    # 已提取至 ReminderPresetSection

    # ── 加载 ────────────────────────────────────────────────────

    def load_settings(self):
        s = self.db
        self._load_simple()
        s.set_setting("totp_secret", "")

        self._reminder_section.load()
        self._security_section.load()

        self.enable_log_file_var.set(s.get_setting("enable_log_file", "False") == "True")
        self.log_path_var.set(s.get_setting("log_file_path", "log/dav_server.log"))
        self.log_level_var.set(s.get_setting("log_level", "INFO"))
        self.tz_fmt_var.set(s.get_setting("timezone_format",
            "{offset} - {city} ({tz_id}) {localized}{local_tag}"))
        TimezoneHelper.set_format(self.tz_fmt_var.get())

        total_min = int(s.get_setting("default_duration", "60"))

        self.ssl_enabled_var.set(s.get_setting("ssl_enabled", "False") == "True")
        self.ssl_cert_var.set(s.get_setting("ssl_certfile", ""))
        self.ssl_key_var.set(s.get_setting("ssl_keyfile", ""))
        self._auto_renew_var.set(s.get_setting("ssl_auto_renew", "True") == "True")
        self._update_cert_info()

        self.data_dir_var.set(s.get_setting("data_dir", "data"))

        self.close_action_var.set(s.get_setting("close_action", "ask"))

        self.dav_root_var.set(s.get_setting("dav_root", "./dav_root"))
        self.ftp_password_var.set(s.get_setting("ftp_password", ""))

        self.sync_url_var.set(s.get_setting("sync_url", ""))
        self.sync_user_var.set(s.get_setting("sync_user", ""))
        self.sync_password_var.set(s.get_setting("sync_password", ""))
        self.sync_interval_var.set(s.get_setting("sync_interval", "30"))
        self.sync_enabled_var.set(s.get_setting("sync_enabled", "False") == "True")

        self._refresh_port_validations()

    # ── 重置 ────────────────────────────────────────────────────

    def reset_settings(self):
        if not ConfirmDialog.ask(self, "确认重置", "确定要重置所有设置吗？\n此操作无法撤销。"):
            return
        self.db.reset_all()
        self._reset_simple()

        self._reminder_section.reset()
        self._security_section.reset()

        self.enable_log_file_var.set(False)
        self.log_path_var.set("log/dav_server.log")
        self.log_level_var.set("INFO")
        self.tz_fmt_var.set("{offset} - {city} ({tz_id}) {localized}{local_tag}")
        TimezoneHelper.set_format(self.tz_fmt_var.get())

        self._dur_h_var.set("1")
        self._dur_m_var.set("0")

        self.sync_url_var.set("")
        self.sync_user_var.set("")
        self.sync_password_var.set("")
        self.sync_interval_var.set("30")
        self.sync_enabled_var.set(False)

        self.ssl_enabled_var.set(False)
        self.ssl_cert_var.set("")
        self.ssl_key_var.set("")
        self._auto_renew_var.set(True)

        self.close_action_var.set("ask")

        messagebox.showinfo("重置完成", "所有设置已恢复默认值，点击「保存」生效。", parent=self)

    def _browse_data_dir(self):
        dir_path = filedialog.askdirectory(title="选择数据存储目录", parent=self)
        if dir_path:
            self.data_dir_var.set(dir_path)

    def _export_backup(self):
        from datetime import datetime
        default_name = f"personaldav_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        path = filedialog.asksaveasfilename(
            title="导出备份", defaultextension=".zip",
            initialfile=default_name, filetypes=[("ZIP 文件", "*.zip")], parent=self)
        if not path:
            return
        from utils.backup import export_backup
        if export_backup(path):
            from ui.widgets.toast import Toast
            Toast.success(self, f"备份已导出到:\n{path}")
        else:
            messagebox.showerror("备份失败", "导出过程中发生错误，请查看日志。", parent=self)

    def _import_backup(self):
        path = filedialog.askopenfilename(
            title="从备份恢复", filetypes=[("ZIP 文件", "*.zip")], parent=self)
        if not path:
            return
        if not ConfirmDialog.ask(self, "确认恢复",
                                  "恢复将替换当前数据库和设置，\n"
                                  "之后可能需要重启服务器才能完全生效。确定继续？"):
            return
        from utils.backup import import_backup
        if import_backup(path):
            self.restart_requested = True
            self.destroy()
        else:
            messagebox.showerror("恢复失败", "恢复过程中发生错误，请查看日志。", parent=self)

    def _compact_db(self):
        from database.db_manager import Database
        if Database._vacuum_in_progress:
            messagebox.showinfo("提示", "数据库压缩已在运行中，请等待完成。", parent=self)
            return
        if not ConfirmDialog.ask(self, "压缩数据库",
                                  "压缩将重写整个数据库以释放空闲空间。\n"
                                  "期间程序响应会变慢，确定继续？"):
            return

        progress = tk.Toplevel(self)
        progress.title("压缩数据库")
        progress.transient(self)
        progress.grab_set()
        progress.resizable(False, False)
        progress.protocol("WM_DELETE_WINDOW", lambda: None)
        w, h = 320, 100
        sw = progress.winfo_screenwidth()
        sh = progress.winfo_screenheight()
        progress.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

        ttk.Label(progress, text="正在压缩数据库，请稍候…").pack(pady=(15, 5))
        pb = ttk.Progressbar(progress, mode="indeterminate", length=280)
        pb.pack(pady=5)
        pb.start(10)
        progress.update()

        def _done(saved):
            if not progress.winfo_exists():
                return
            progress.destroy()
            if saved is not None:
                from ui.widgets.toast import Toast
                if saved > 0:
                    Toast.show(self, f"数据库压缩完成，释放 {saved / 1024:.1f} KB 空间")
                else:
                    Toast.show(self, "数据库已处于最佳状态，无需压缩")
                self.load_settings()
            else:
                messagebox.showerror("压缩失败",
                                     "数据库压缩过程中发生错误，请查看日志。", parent=self)

        def _run():
            saved = Database().vacuum_full()
            try:
                self.after(0, lambda: _done(saved))
            except tk.TclError:
                pass

        import threading
        t = threading.Thread(target=_run, daemon=True)
        t.start()

    def _load_text_widget_lines(self, widget: tk.Text, raw: str):
        widget.delete("1.0", tk.END)
        for line in raw.replace('\r', '').split('\n'):
            widget.insert(tk.END, line + '\n')

    # ── 保存 ────────────────────────────────────────────────────

    def save_settings(self):
        s = self.db
        self._save_simple()
        self._reminder_section.save()
        self._security_section.save()

        s.set_setting("enable_log_file", str(self.enable_log_file_var.get()))
        s.set_setting("log_file_path", self.log_path_var.get())
        s.set_setting("log_level", self.log_level_var.get())
        s.set_setting("timezone_format", self.tz_fmt_var.get())
        TimezoneHelper.set_format(self.tz_fmt_var.get())

        total_min = int(self._dur_h_var.get() or "0") * 60 + int(self._dur_m_var.get() or "0")
        s.set_setting("default_duration", str(total_min))

        prev_ssl = s.get_setting("ssl_enabled", "False") == "True"
        new_ssl = self.ssl_enabled_var.get()
        ssl_toggled = (prev_ssl != new_ssl)

        s.set_setting("ssl_enabled", str(new_ssl))
        s.set_setting("ssl_certfile", self.ssl_cert_var.get())
        s.set_setting("ssl_keyfile", self.ssl_key_var.get())
        s.set_setting("ssl_auto_renew", str(self._auto_renew_var.get()))

        s.set_setting("data_dir", self.data_dir_var.get())
        s.set_setting("close_action", self.close_action_var.get())

        for name, key in [("DAV 端口", "default_port"), ("MCP 端口", "mcp_port")]:
            if hasattr(self, f"{key}_var"):
                ok, msg = validate_port(getattr(self, f"{key}_var").get())
                if not ok:
                    messagebox.showerror("端口错误", f"{name}: {msg}", parent=self)
                    return

        s.set_setting("dav_root", self.dav_root_var.get())
        s.set_setting("ftp_password", self.ftp_password_var.get())

        s.set_setting("sync_url", self.sync_url_var.get())
        s.set_setting("sync_user", self.sync_user_var.get())
        s.set_setting("sync_password", self.sync_password_var.get())
        s.set_setting("sync_interval", self.sync_interval_var.get())
        s.set_setting("sync_enabled", str(self.sync_enabled_var.get()))

        event_bus.publish(EVENT_SETTINGS_CHANGED)
        if self.on_save_callback:
            self.on_save_callback(ssl_toggled)
        self.destroy()
