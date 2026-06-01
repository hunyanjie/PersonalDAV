import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
from ui.widgets.right_click_menu import RightClickMenu
from ui.dialogs.event_dialog import DetailedReminderEditor, save_alarm_trigger, load_alarm_trigger
from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED
from utils.timezone_helper import TimezoneHelper
from utils.cert_helper import generate_self_signed_cert
from models.setting_defs import SettingDef
from models.constants import STATUS_MAPPING, TRANSPARENCY_MAPPING, REPEAT_OPTIONS, END_CONDITIONS, ALARM_ACTION_MAPPING, ALARM_ACTION_REV_MAPPING
from services.auth_service import AuthService
import json
from datetime import datetime, timedelta


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
        self.geometry("800x750")
        self.transient(parent)
        self.grab_set()
        self.db = db_service
        self.on_save_callback = on_save_callback
        self._custom_reminders_data = []
        self._custom_allday_reminders_data = []

        main_frame = ttk.Frame(self); main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook = ttk.Notebook(main_frame); notebook.pack(fill=tk.BOTH, expand=True)

        server_frame = ttk.Frame(notebook); notebook.add(server_frame, text="服务器设置")
        calendar_frame = ttk.Frame(notebook); notebook.add(calendar_frame, text="日历设置")
        log_frame = ttk.Frame(notebook); notebook.add(log_frame, text="日志设置")
        security_frame = ttk.Frame(notebook); notebook.add(security_frame, text="安全设置")
        mcp_frame = ttk.Frame(notebook); notebook.add(mcp_frame, text="MCP 服务")

        self.create_server_settings(server_frame)
        self.create_calendar_settings(calendar_frame)
        self.create_log_settings(log_frame)
        self.create_security_settings(security_frame)
        self.create_mcp_settings(mcp_frame)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="重置设置", command=self.reset_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="保存", command=self.save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=5)

        self.load_settings()

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

    def create_server_settings(self, parent):
        f = ttk.LabelFrame(parent, text="服务器控制")
        f.pack(fill=tk.X, padx=5, pady=5)
        self._build_simple(f, "服务器控制")

        ssl_f = ttk.LabelFrame(parent, text="SSL/TLS 设置")
        ssl_f.pack(fill=tk.X, padx=5, pady=5)

        self.ssl_enabled_var = tk.BooleanVar()
        ttk.Checkbutton(ssl_f, text="启用 HTTPS (SSL/TLS)", variable=self.ssl_enabled_var).grid(
            row=0, column=0, columnspan=4, sticky="w", padx=5, pady=5)

        ttk.Label(ssl_f, text="证书文件 (.pem):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.ssl_cert_var = tk.StringVar()
        ttk.Entry(ssl_f, textvariable=self.ssl_cert_var, width=50).grid(row=1, column=1, columnspan=2, sticky="we", padx=2)
        ttk.Button(ssl_f, text="浏览...", command=lambda: self._browse_ssl("cert")).grid(row=1, column=3, padx=2)

        ttk.Label(ssl_f, text="密钥文件 (.key):").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.ssl_key_var = tk.StringVar()
        ttk.Entry(ssl_f, textvariable=self.ssl_key_var, width=50).grid(row=2, column=1, columnspan=2, sticky="we", padx=2)
        ttk.Button(ssl_f, text="浏览...", command=lambda: self._browse_ssl("key")).grid(row=2, column=3, padx=2)

        btn_f = ttk.Frame(ssl_f)
        btn_f.grid(row=3, column=0, columnspan=4, pady=5)
        ttk.Button(btn_f, text="一键生成自签名证书", command=self._generate_cert).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="手动创建证书指引", command=self._show_cert_guide).pack(side=tk.LEFT, padx=5)
        ssl_f.grid_columnconfigure(1, weight=1)

    # ── 安全设置 ────────────────────────────────────────────────

    def create_security_settings(self, parent):
        pw_f = ttk.LabelFrame(parent, text="访问密码")
        pw_f.pack(fill=tk.X, padx=5, pady=5)

        self._auth_status_label = ttk.Label(pw_f, text="", font=('', 10))
        self._auth_status_label.grid(row=0, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        ttk.Button(pw_f, text="设置密码", command=self._set_password).grid(row=1, column=0, padx=5, pady=5)
        ttk.Button(pw_f, text="更改密码", command=self._change_password).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(pw_f, text="清除密码", command=self._clear_password).grid(row=1, column=2, padx=5, pady=5)

        ttk.Label(pw_f, text="设置后 WebDAV、MCP 等所有服务均需密码验证。",
                  foreground="gray", wraplength=500).grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=2)

        token_f = ttk.LabelFrame(parent, text="MCP 令牌（AI 连接用）")
        token_f.pack(fill=tk.X, padx=5, pady=5)

        self._mcp_token_var = tk.StringVar()
        token_entry = ttk.Entry(token_f, textvariable=self._mcp_token_var, state="readonly", width=70)
        token_entry.pack(fill=tk.X, padx=5, pady=5)

        btn_f = ttk.Frame(token_f)
        btn_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_f, text="复制令牌", command=self._copy_mcp_token).pack(side=tk.LEFT, padx=2)
        ttk.Label(btn_f, text="  设置密码后令牌自动生成，更改密码会刷新令牌。",
                  foreground="gray").pack(side=tk.LEFT)

        ip_f = ttk.LabelFrame(parent, text="IP 访问控制（留空 = 不限制）")
        ip_f.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(ip_f, text="白名单（每行一个 IP / CIDR / 通配符）:",
                  foreground="gray").grid(row=0, column=0, sticky="w", padx=5, pady=(5, 0))
        self._ip_whitelist_text = tk.Text(ip_f, height=3, width=60)
        self._ip_whitelist_text.grid(row=1, column=0, padx=5, pady=2, sticky="ew")

        ttk.Label(ip_f, text="黑名单（每行一个 IP / CIDR / 通配符）:",
                  foreground="gray").grid(row=2, column=0, sticky="w", padx=5, pady=(5, 0))
        self._ip_blacklist_text = tk.Text(ip_f, height=3, width=60)
        self._ip_blacklist_text.grid(row=3, column=0, padx=5, pady=2, sticky="ew")

        ttk.Label(ip_f, text="示例: 127.0.0.1 | 192.168.1.0/24 | 10.0.* | 白名单非空时只允许白名单 IP 访问",
                  foreground="gray", font=('', 8)).grid(row=4, column=0, sticky="w", padx=5, pady=(0, 5))

        bypass_f = ttk.LabelFrame(parent, text="免密码 IP（这些 IP 访问时不需密码验证）")
        bypass_f.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(bypass_f, text="每行一个 IP / CIDR / 通配符（本机 127.0.0.1 / ::1 永久免密）:",
                  foreground="gray").grid(row=0, column=0, sticky="w", padx=5, pady=(5, 0))
        self._ip_bypass_text = tk.Text(bypass_f, height=3, width=60)
        self._ip_bypass_text.grid(row=1, column=0, padx=5, pady=2, sticky="ew")

        self._refresh_auth_ui()

    def _refresh_auth_ui(self):
        svc = AuthService()
        enabled = svc.is_enabled()
        self._auth_status_label.config(
            text=f"访问密码: {'已设置' if enabled else '未设置'}",
            foreground="green" if enabled else "orange"
        )
        self._mcp_token_var.set(svc.get_mcp_token() if enabled else "(未设置密码)")

    def _set_password(self):
        self._password_dialog(change=False)

    def _change_password(self):
        if not AuthService().is_enabled():
            messagebox.showinfo("提示", "当前未设置密码，请使用「设置密码」", parent=self)
            return
        self._password_dialog(change=True)

    def _password_dialog(self, change=False):
        dialog = tk.Toplevel(self)
        dialog.title("更改密码" if change else "设置密码")
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("400x200")

        row = 0
        if change:
            ttk.Label(dialog, text="当前密码:").grid(row=row, column=0, sticky="w", padx=10, pady=5)
            old_var = tk.StringVar()
            ttk.Entry(dialog, textvariable=old_var, show="*", width=30).grid(row=row, column=1, padx=5)
            row += 1

        ttk.Label(dialog, text="新密码:").grid(row=row, column=0, sticky="w", padx=10, pady=5)
        new_var = tk.StringVar()
        new_entry = ttk.Entry(dialog, textvariable=new_var, show="*", width=30)
        new_entry.grid(row=row, column=1, padx=5)
        row += 1

        ttk.Label(dialog, text="确认密码:").grid(row=row, column=0, sticky="w", padx=10, pady=5)
        confirm_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=confirm_var, show="*", width=30).grid(row=row, column=1, padx=5)
        row += 1

        def do_save():
            if change and not AuthService().verify_password(old_var.get()):
                messagebox.showerror("错误", "当前密码不正确", parent=dialog)
                return
            if not new_var.get():
                messagebox.showerror("错误", "密码不能为空", parent=dialog)
                return
            if new_var.get() != confirm_var.get():
                messagebox.showerror("错误", "两次密码不一致", parent=dialog)
                return
            AuthService().set_password(new_var.get())
            self._refresh_auth_ui()
            dialog.destroy()
            messagebox.showinfo("成功", "密码已更新", parent=self)

        btn_f = ttk.Frame(dialog)
        btn_f.grid(row=row, column=0, columnspan=2, pady=15)
        ttk.Button(btn_f, text="确定", command=do_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def _clear_password(self):
        if not AuthService().is_enabled():
            return
        if not messagebox.askyesno("确认清除", "清除后所有服务将不再需要密码验证，确定吗？", parent=self):
            return
        AuthService().clear_password()
        self._refresh_auth_ui()
        messagebox.showinfo("成功", "密码已清除", parent=self)

    def _copy_mcp_token(self):
        token = AuthService().get_mcp_token()
        if not token:
            messagebox.showinfo("提示", "请先设置密码", parent=self)
            return
        try:
            dialog.focus_get()
        except:
            pass
        self.clipboard_clear()
        self.clipboard_append(token)
        messagebox.showinfo("已复制", "MCP 令牌已复制到剪贴板", parent=self)

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

        def update_url(*_):
            port = self.mcp_port_var.get() if hasattr(self, 'mcp_port_var') else "8100"
            self._mcp_url_label.config(text=f"URL: http://127.0.0.1:{port}/sse")

        if hasattr(self, 'mcp_port_var'):
            self.mcp_port_var.trace("w", update_url)
        self.after(100, update_url)

        tools = ttk.LabelFrame(parent, text="可用工具列表")
        tools.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        cols = ("工具名", "类别", "说明")
        tree = ttk.Treeview(tools, columns=cols, show="headings", height=14)
        for c in cols:
            tree.heading(c, text=c)
            tree.column(c, width=180 if c == "说明" else 100)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ttk.Scrollbar(tools, orient=tk.VERTICAL, command=tree.yview).pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=ttk.Scrollbar(tools, orient=tk.VERTICAL, command=tree.yview).set)

        tool_list = [
            ("server_start(port=8080)", "服务端管理", "启动 DAV 服务器（后台线程）"),
            ("server_stop()", "服务端管理", "停止 DAV 服务器"),
            ("server_status()", "服务端管理", "查询 DAV 服务器运行状态"),
            ("list_contacts()", "联系人", "列出所有联系人 uid + 姓名"),
            ("get_contact(uid)", "联系人", "获取联系人完整 vCard 数据"),
            ("create_contact(vcard_data)", "联系人", "从 vCard 创建联系人"),
            ("update_contact(uid, vcard)", "联系人", "覆盖更新联系人"),
            ("delete_contact(uid)", "联系人", "删除联系人"),
            ("list_events()", "日历", "列出所有事件 uid + 标题 + 时间"),
            ("get_event(uid)", "日历", "获取事件完整 iCalendar 数据"),
            ("create_event(ical_data)", "日历", "从 iCal 创建事件"),
            ("update_event(uid, ical)", "日历", "覆盖更新事件"),
            ("delete_event(uid)", "日历", "删除事件"),
            ("get_config()", "系统", "返回软件配置与数据统计"),
            ("dav_health_check(url)", "系统", "验证 DAV 端点是否正常"),
        ]
        for name, cat, desc in tool_list:
            tree.insert("", tk.END, values=(name, cat, desc))

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

        self._create_timezone_format_ui(b_t)
        self.create_preset_settings(p_t)

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
            except:
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

    # ── 预设提醒增删改 ──────────────────────────────────────────

    def _make_preset_quick_buttons(self, parent, entry):
        common = ["5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前", "2天前", "7天前"]
        allday_common = ["日程发生时", "当天上午9点", "1天前上午9点", "2天前上午9点", "7天前上午9点"]
        qf = ttk.LabelFrame(parent, text="常用预设 (点击快速填入)")
        qf.pack(fill=tk.X, padx=10, pady=5)
        nf = ttk.Frame(qf); nf.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(nf, text="常规:", font=('', 9)).pack(side=tk.LEFT)
        for t in common:
            ttk.Button(nf, text=t, width=10,
                       command=lambda v=t: [entry.delete(0, tk.END), entry.insert(0, v)]).pack(side=tk.LEFT, padx=1)
        af = ttk.Frame(qf); af.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(af, text="全天:", font=('', 9)).pack(side=tk.LEFT)
        for t in allday_common:
            ttk.Button(af, text=t, width=14,
                       command=lambda v=t: [entry.delete(0, tk.END), entry.insert(0, v)]).pack(side=tk.LEFT, padx=1)

    def add_preset_reminder(self):
        dialog = tk.Toplevel(self); dialog.title('添加预设提醒'); dialog.transient(self); dialog.grab_set(); dialog.geometry("520x300")
        ttk.Label(dialog, text="添加预设提醒", font=('Arial', 12, 'bold')).pack(anchor='w', padx=10, pady=(10, 0))
        ttk.Label(dialog, text="输入提醒触发时间，新建日程时可双击预设快速添加。", foreground="gray").pack(anchor='w', padx=10)
        ttk.Label(dialog, text="预设内容:").pack(anchor='w', padx=10, pady=(10, 0))
        entry = ttk.Entry(dialog, width=40); entry.pack(padx=10, pady=5, fill=tk.X)
        entry.focus_set()
        self._make_preset_quick_buttons(dialog, entry)
        var = tk.StringVar(value='normal')
        rf = ttk.Frame(dialog); rf.pack(padx=10, pady=5, anchor='w')
        ttk.Radiobutton(rf, text='常规事件', variable=var, value='normal').pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(rf, text='全天事件', variable=var, value='allday').pack(side=tk.LEFT, padx=2)
        bf = ttk.Frame(dialog); bf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(bf, text='确定', command=lambda: [
            setattr(self, '_tmp_preset_val', entry.get().strip()) if entry.get().strip() else None,
            dialog.destroy() if entry.get().strip() else None
        ][-1]).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text='取消', command=dialog.destroy).pack(side=tk.RIGHT, padx=2)
        dialog.wait_window()
        v = getattr(self, '_tmp_preset_val', None)
        if v:
            lb = self.preset_allday_reminders_listbox if var.get() == 'allday' else self.preset_reminders_listbox
            lb.insert('end', v)

    def edit_preset_reminder(self):
        n_sel = self.preset_reminders_listbox.curselection()
        a_sel = self.preset_allday_reminders_listbox.curselection()
        if not (n_sel or a_sel):
            messagebox.showinfo("提示", "请先选中要编辑的预设项")
            return
        lb = self.preset_reminders_listbox if n_sel else self.preset_allday_reminders_listbox
        idx = n_sel[0] if n_sel else a_sel[0]
        cur = lb.get(idx)
        dialog = tk.Toplevel(self); dialog.title('编辑预设提醒'); dialog.transient(self); dialog.grab_set(); dialog.geometry("520x300")
        ttk.Label(dialog, text="编辑预设提醒", font=('Arial', 12, 'bold')).pack(anchor='w', padx=10, pady=(10, 0))
        ttk.Label(dialog, text="修改提醒触发时间。", foreground="gray").pack(anchor='w', padx=10)
        ttk.Label(dialog, text="预设内容:").pack(anchor='w', padx=10, pady=(10, 0))
        entry = ttk.Entry(dialog, width=40); entry.insert(0, cur); entry.pack(padx=10, pady=5, fill=tk.X)
        entry.focus_set(); entry.selection_range(0, tk.END)
        self._make_preset_quick_buttons(dialog, entry)
        bf = ttk.Frame(dialog); bf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(bf, text='确定', command=lambda: [
            lb.delete(idx), lb.insert(idx, entry.get().strip()), dialog.destroy()
        ] if entry.get().strip() else None).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text='取消', command=dialog.destroy).pack(side=tk.RIGHT, padx=2)

    def delete_preset_reminder(self):
        for lb in [self.preset_reminders_listbox, self.preset_allday_reminders_listbox]:
            sel = lb.curselection()
            if sel: lb.delete(sel[0]); return

    def add_custom_default_reminder(self, is_allday):
        data_list = self._custom_allday_reminders_data if is_allday else self._custom_reminders_data
        listbox = self.custom_default_allday_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        def on_save(new_alarm):
            save_data = new_alarm.copy()
            save_data['trigger'] = save_alarm_trigger(save_data['trigger'])
            if 'duration' in save_data and isinstance(save_data['duration'], timedelta):
                save_data['duration'] = save_data['duration'].total_seconds()
            data_list.append(save_data)
            self._refresh_custom_listbox(listbox, data_list)
        DetailedReminderEditor(self, callback=on_save)

    def edit_custom_default_reminder(self, is_allday):
        data_list = self._custom_allday_reminders_data if is_allday else self._custom_reminders_data
        listbox = self.custom_default_allday_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        sel = listbox.curselection()
        if not sel: return
        idx = sel[0]
        try:
            initial_data = data_list[idx].copy()
            initial_data['trigger'] = load_alarm_trigger(initial_data.get('trigger'))
            if 'duration' in initial_data and isinstance(initial_data['duration'], (int, float)):
                initial_data['duration'] = timedelta(seconds=initial_data['duration'])
        except:
            initial_data = None
        def on_save(new_alarm):
            save_data = new_alarm.copy()
            save_data['trigger'] = save_alarm_trigger(save_data['trigger'])
            if 'duration' in save_data and isinstance(save_data['duration'], timedelta):
                save_data['duration'] = save_data['duration'].total_seconds()
            data_list[idx] = save_data
            self._refresh_custom_listbox(listbox, data_list)
        DetailedReminderEditor(self, initial_alarm=initial_data, callback=on_save)

    def delete_custom_default_reminder(self, is_allday):
        data_list = self._custom_allday_reminders_data if is_allday else self._custom_reminders_data
        listbox = self.custom_default_allday_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        sel = listbox.curselection()
        if sel:
            del data_list[sel[0]]
            self._refresh_custom_listbox(listbox, data_list)

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
            messagebox.showinfo("成功", f"自签名证书已生成：\n{cert_path}\n\n请将此证书添加到系统的信任列表中。\n\nmacOS: 双击 cert.pem → 钥匙串 → 信任 → 始终信任\niOS: 通过 Safari 下载安装描述文件", parent=self)
        except Exception as e:
            messagebox.showerror("生成失败", str(e), parent=self)

    def _show_cert_guide(self):
        win = tk.Toplevel(self); win.title("手动创建自签名证书"); win.geometry("680x520")
        win.transient(self); win.grab_set()

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

    # ── 显示格式 ────────────────────────────────────────────────

    @staticmethod
    def _format_alarm_display(alarm_data):
        action_map = ALARM_ACTION_REV_MAPPING
        action = action_map.get(alarm_data.get('action', ''), alarm_data.get('action', ''))
        trigger = alarm_data.get('trigger', {})
        if isinstance(trigger, dict):
            t_type = trigger.get('type')
            if t_type == 'td':
                seconds = trigger.get('seconds', 0)
                prefix = "前" if seconds < 0 else ""
                seconds = abs(seconds)
                days = int(seconds // 86400)
                hours = int((seconds % 86400) // 3600)
                mins = int((seconds % 3600) // 60)
                parts = []
                if days: parts.append(f"{days}天")
                if hours: parts.append(f"{hours}小时")
                if mins: parts.append(f"{mins}分钟")
                trigger_str = "".join(parts) + prefix if parts else ("发生时" if prefix else str(seconds))
            elif t_type == 'dt':
                trigger_str = trigger.get('iso', '')
            else:
                trigger_str = str(trigger)
        elif isinstance(trigger, str):
            trigger_str = trigger
        else:
            trigger_str = str(trigger)
        desc = alarm_data.get('description', '')
        result = f"{action} - {trigger_str}"
        if desc: result += f" | 描述: {desc}"
        return result

    def _refresh_custom_listbox(self, listbox, data_list):
        listbox.delete(0, tk.END)
        for alarm_data in data_list:
            listbox.insert(tk.END, self._format_alarm_display(alarm_data))

    # ── 加载 ────────────────────────────────────────────────────

    def load_settings(self):
        s = self.db
        self._load_simple()

        for key, lb in [('preset_reminders', self.preset_reminders_listbox),
                        ('preset_allday_reminders', self.preset_allday_reminders_listbox)]:
            val = s.get_setting(key, '')
            if val:
                for item in val.split(';'):
                    if item: lb.insert(tk.END, item)

        self._custom_reminders_data = []
        self._custom_allday_reminders_data = []
        for key, data_list, lb in [
            ('custom_default_reminders', self._custom_reminders_data, self.custom_default_reminders_listbox),
            ('custom_default_allday_reminders', self._custom_allday_reminders_data, self.custom_default_allday_reminders_listbox)
        ]:
            val = s.get_setting(key, '')
            if val:
                for item_str in val.split(';'):
                    if not item_str: continue
                    if not item_str.startswith('{'):
                        parts = item_str.split(':', 3)
                        if len(parts) >= 3:
                            act = ALARM_ACTION_MAPPING.get(parts[0], "DISPLAY")
                            trig_str = parts[2]
                            if ":" in trig_str:
                                h, m = map(int, trig_str.split(':'))
                                t_val = {'type': 'td', 'seconds': h*3600 + m*60}
                            else:
                                t_val = {'type': 'td', 'seconds': -900}
                            item_str = json.dumps({'action': act, 'trigger': t_val, 'description': parts[3] if len(parts)>3 else ""}, ensure_ascii=False)
                    try:
                        alarm_data = json.loads(item_str)
                        data_list.append(alarm_data)
                    except:
                        data_list.append({'action': 'DISPLAY', 'trigger': {'type': 'td', 'seconds': -900}, 'description': item_str})
            self._refresh_custom_listbox(lb, data_list)

        for key, lb in [('default_reminders', self.default_reminders_listbox),
                        ('default_allday_reminders', self.default_allday_reminders_listbox)]:
            sel_str = s.get_setting(key, '')
            for i in range(lb.size()):
                if lb.get(i) in sel_str.split(';'): lb.selection_set(i)

        self.enable_log_file_var.set(s.get_setting("enable_log_file", "False") == "True")
        self.log_path_var.set(s.get_setting("log_file_path", "dav_server.log"))
        self.log_level_var.set(s.get_setting("log_level", "INFO"))
        self.tz_fmt_var.set(s.get_setting("timezone_format",
            "{offset} - {city} ({tz_id}) {localized}{local_tag}"))
        TimezoneHelper.set_format(self.tz_fmt_var.get())

        total_min = int(s.get_setting("default_duration", "60"))
        if total_min <= 24:  # 旧版 DB 存小时数 → 转为分钟
            total_min *= 60
        self._dur_h_var.set(str(total_min // 60))
        self._dur_m_var.set(str(total_min % 60))

        self.ssl_enabled_var.set(s.get_setting("ssl_enabled", "False") == "True")
        self.ssl_cert_var.set(s.get_setting("ssl_certfile", ""))
        self.ssl_key_var.set(s.get_setting("ssl_keyfile", ""))

        self._load_text_widget_lines(self._ip_whitelist_text, s.get_setting("ip_whitelist", ""))
        self._load_text_widget_lines(self._ip_blacklist_text, s.get_setting("ip_blacklist", ""))
        self._load_text_widget_lines(self._ip_bypass_text, s.get_setting("ip_bypass_auth", ""))

    # ── 重置 ────────────────────────────────────────────────────

    def reset_settings(self):
        if not messagebox.askyesno("确认重置", "确定要重置所有设置吗？\n此操作无法撤销。", parent=self):
            return
        self.db.reset_all()
        self._reset_simple()

        self.preset_reminders_listbox.delete(0, tk.END)
        for p in ["5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前"]:
            self.preset_reminders_listbox.insert(tk.END, p)
        self.preset_allday_reminders_listbox.delete(0, tk.END)
        for p in ["日程发生时", "1天前", "2天前", "7天前"]:
            self.preset_allday_reminders_listbox.insert(tk.END, p)
        self.default_reminders_listbox.selection_clear(0, tk.END)
        self.default_allday_reminders_listbox.selection_clear(0, tk.END)
        self._custom_reminders_data.clear()
        self._custom_allday_reminders_data.clear()
        self.custom_default_reminders_listbox.delete(0, tk.END)
        self.custom_default_allday_reminders_listbox.delete(0, tk.END)

        self.enable_log_file_var.set(False)
        self.log_path_var.set("dav_server.log")
        self.log_level_var.set("INFO")
        self.tz_fmt_var.set("{offset} - {city} ({tz_id}) {localized}{local_tag}")
        TimezoneHelper.set_format(self.tz_fmt_var.get())

        self._dur_h_var.set("1")
        self._dur_m_var.set("0")

        self.ssl_enabled_var.set(False)
        self.ssl_cert_var.set("")
        self.ssl_key_var.set("")

        self._ip_whitelist_text.delete("1.0", tk.END)
        self._ip_blacklist_text.delete("1.0", tk.END)
        self._ip_bypass_text.delete("1.0", tk.END)

        messagebox.showinfo("重置完成", "所有设置已恢复默认值，点击「保存」生效。", parent=self)

    def _load_text_widget_lines(self, widget: tk.Text, raw: str):
        widget.delete("1.0", tk.END)
        for line in raw.replace('\r', '').split('\n'):
            widget.insert(tk.END, line + '\n')

    # ── 保存 ────────────────────────────────────────────────────

    def save_settings(self):
        s = self.db
        self._save_simple()

        s.set_setting('preset_reminders', ';'.join([self.preset_reminders_listbox.get(i) for i in range(self.preset_reminders_listbox.size())]))
        s.set_setting('preset_allday_reminders', ';'.join([self.preset_allday_reminders_listbox.get(i) for i in range(self.preset_allday_reminders_listbox.size())]))
        s.set_setting('default_reminders', ';'.join([self.default_reminders_listbox.get(i) for i in self.default_reminders_listbox.curselection()]))
        s.set_setting('default_allday_reminders', ';'.join([self.default_allday_reminders_listbox.get(i) for i in self.default_allday_reminders_listbox.curselection()]))
        s.set_setting('custom_default_reminders', ';'.join([json.dumps(item, ensure_ascii=False) for item in self._custom_reminders_data]))
        s.set_setting('custom_default_allday_reminders', ';'.join([json.dumps(item, ensure_ascii=False) for item in self._custom_allday_reminders_data]))

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

        s.set_setting("ip_whitelist", self._ip_whitelist_text.get("1.0", tk.END).strip())
        s.set_setting("ip_blacklist", self._ip_blacklist_text.get("1.0", tk.END).strip())
        s.set_setting("ip_bypass_auth", self._ip_bypass_text.get("1.0", tk.END).strip())

        event_bus.publish(EVENT_SETTINGS_CHANGED)
        if self.on_save_callback:
            self.on_save_callback(ssl_toggled)
        self.destroy()
