import tkinter as tk
from tkinter import ttk, messagebox
from ui.widgets.enhanced_tooltip import EnhancedTooltip
from services.auth_service import AuthService


class SecuritySettingsSection:
    """安全设置 — 从 SettingsDialog 提取"""
    def __init__(self, dialog):
        self.dialog = dialog
        self._parent_frame = None

    def create_ui(self, parent):
        self._parent_frame = parent
        sub = ttk.Notebook(parent)
        sub.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        pw_frame = ttk.Frame(sub); sub.add(pw_frame, text="密码验证")
        ip_frame = ttk.Frame(sub); sub.add(ip_frame, text="IP 控制")
        rate_frame = ttk.Frame(sub); sub.add(rate_frame, text="频率限制")

        self._create_password_ui(pw_frame)
        self._create_ip_ui(ip_frame)
        self._create_rate_ui(rate_frame)
        self._refresh()

    def _create_password_ui(self, parent):
        pw_f = ttk.LabelFrame(parent, text="访问密码")
        pw_f.pack(fill=tk.X, padx=5, pady=5)
        self._auth_status_label = ttk.Label(pw_f, text="", font=('', 10))
        self._auth_status_label.grid(row=0, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        self._set_pw_btn = ttk.Button(pw_f, text="设置密码", command=self._set_password)
        self._set_pw_btn.grid(row=1, column=0, padx=5, pady=5)
        self._change_pw_btn = ttk.Button(pw_f, text="更改密码", command=self._change_password)
        self._change_pw_btn.grid(row=1, column=1, padx=5, pady=5)
        self._clear_pw_btn = ttk.Button(pw_f, text="清除密码", command=self._clear_password)
        self._clear_pw_btn.grid(row=1, column=2, padx=5, pady=5)
        ttk.Label(pw_f, text="设置后 WebDAV、MCP 等所有服务均需密码验证。",
                  foreground="gray", wraplength=500).grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=2)

        self.dialog.force_password_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="强制要求密码（未设密码时拒绝访问）",
                        variable=self.dialog.force_password_var).pack(anchor="w", padx=10, pady=5)

        token_f = ttk.LabelFrame(parent, text="MCP 令牌（AI 连接用）")
        token_f.pack(fill=tk.X, padx=5, pady=5)
        self._mcp_token_var = tk.StringVar()
        token_entry = ttk.Entry(token_f, textvariable=self._mcp_token_var, state="readonly", width=70)
        token_entry.pack(fill=tk.X, padx=5, pady=5)
        self._mcp_token_time_var = tk.StringVar()
        ttk.Label(token_f, textvariable=self._mcp_token_time_var, foreground="gray", font=('', 8)).pack(anchor="w", padx=5)
        btn_f = ttk.Frame(token_f)
        btn_f.pack(fill=tk.X, padx=5, pady=5)
        copy_btn = ttk.Button(btn_f, text="复制令牌", command=self._copy_mcp_token)
        copy_btn.pack(side=tk.LEFT, padx=2)
        self._mcp_tip = EnhancedTooltip(copy_btn, "请先设置密码以生成令牌")
        self._rotate_token_btn = ttk.Button(btn_f, text="轮换令牌", command=self._rotate_mcp_token)
        self._rotate_token_btn.pack(side=tk.LEFT, padx=2)
        ttk.Label(btn_f, text="  更改密码或轮换后旧令牌立即失效。",
                  foreground="gray").pack(side=tk.LEFT)

    def _create_ip_ui(self, parent):
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

        self.dialog._bypass_localhost_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="本机访问免密码",
                        variable=self.dialog._bypass_localhost_var).pack(anchor="w", padx=10, pady=(5, 0))

        bypass_f = ttk.LabelFrame(parent, text="免密码 IP（以下 IP 访问时不需密码验证）")
        bypass_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(bypass_f, text="每行一个 IP / CIDR / 通配符:",
                  foreground="gray").grid(row=0, column=0, sticky="w", padx=5, pady=(5, 0))
        self._ip_bypass_text = tk.Text(bypass_f, height=3, width=60)
        self._ip_bypass_text.grid(row=1, column=0, padx=5, pady=2, sticky="ew")

    def _create_rate_ui(self, parent):
        rate_f = ttk.LabelFrame(parent, text="访问频率限制")
        rate_f.pack(fill=tk.X, padx=5, pady=5)
        self.dialog.rate_limit_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(rate_f, text="启用访问频率限制",
                        variable=self.dialog.rate_limit_enabled_var).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Label(rate_f, text="每分钟最大请求数:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dialog.rate_limit_max_var = tk.StringVar(value="60")
        ttk.Entry(rate_f, textvariable=self.dialog.rate_limit_max_var, width=10).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(rate_f, text="超过限制的请求将被返回 429 Too Many Requests",
                  foreground="gray", font=('', 8)).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=(0, 5))

    def _refresh(self):
        svc = AuthService()
        enabled = svc.is_enabled()
        self._auth_status_label.config(
            text=f"访问密码: {'已设置' if enabled else '未设置'}",
            foreground="green" if enabled else "orange")
        state = tk.NORMAL if enabled else tk.DISABLED
        self._change_pw_btn.config(state=state)
        self._clear_pw_btn.config(state=state)
        token = svc.get_mcp_token() if enabled else "(未设置密码)"
        self._mcp_token_var.set(token)
        rotated = svc.get_mcp_token_rotated_at()
        self._mcp_token_time_var.set(f"上次轮换: {rotated}" if rotated else "")
        self._rotate_token_btn.config(state=state)
        if self._mcp_tip:
            self._mcp_tip.text = "复制令牌到剪贴板" if enabled else "请先设置密码以生成令牌"

    def _set_password(self):
        self._password_dialog(change=False)

    def _change_password(self):
        if not AuthService().is_enabled():
            messagebox.showinfo("提示", "当前未设置密码，请使用「设置密码」", parent=self._parent_frame)
            return
        self._password_dialog(change=True)

    def _password_dialog(self, change=False):
        dialog = tk.Toplevel(self._parent_frame)
        dialog.title("更改密码" if change else "设置密码")
        dialog.transient(self._parent_frame)
        dialog.grab_set()
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
            self._refresh()
            dialog.destroy()
            messagebox.showinfo("成功", "密码已更新", parent=self._parent_frame)
        btn_f = ttk.Frame(dialog)
        btn_f.grid(row=row, column=0, columnspan=2, pady=15)
        ttk.Button(btn_f, text="确定", command=do_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def _clear_password(self):
        svc = AuthService()
        if not svc.is_enabled():
            return
        dialog = tk.Toplevel(self._parent_frame)
        dialog.title("清除密码")
        dialog.transient(self._parent_frame)
        dialog.grab_set()
        ttk.Label(dialog, text="请输入当前密码以确认清除:").pack(pady=(10, 5))
        pw_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=pw_var, show="*", width=25).pack(pady=2)
        def do_clear():
            if not svc.verify_password(pw_var.get()):
                messagebox.showerror("错误", "密码不正确", parent=dialog)
                return
            dialog.destroy()
            svc.clear_password()
            self._refresh()
            messagebox.showinfo("成功", "密码已清除", parent=self._parent_frame)
        btn_f = ttk.Frame(dialog)
        btn_f.pack(pady=10)
        ttk.Button(btn_f, text="确定清除", command=do_clear).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def _rotate_mcp_token(self):
        AuthService().rotate_mcp_token()
        self._refresh()
        from ui.widgets.toast import Toast
        Toast.show(self._parent_frame, "MCP 令牌已轮换，旧令牌立即失效")

    def _copy_mcp_token(self):
        token = AuthService().get_mcp_token()
        if not token:
            messagebox.showinfo("提示", "请先设置密码", parent=self._parent_frame)
            return
        self._parent_frame.clipboard_clear()
        self._parent_frame.clipboard_append(token)
        from ui.widgets.toast import Toast
        Toast.show(self._parent_frame, "MCP 令牌已复制到剪贴板")

    def load(self):
        s = self.dialog.db
        self.dialog._load_text_widget_lines(self._ip_whitelist_text, s.get_setting("ip_whitelist", ""))
        self.dialog._load_text_widget_lines(self._ip_blacklist_text, s.get_setting("ip_blacklist", ""))
        self.dialog._load_text_widget_lines(self._ip_bypass_text, s.get_setting("ip_bypass_auth", ""))
        self.dialog._bypass_localhost_var.set(s.get_setting("bypass_localhost", "True") == "True")
        self.dialog.force_password_var.set(s.get_setting("force_password", "True") == "True")

    def reset(self):
        self.dialog._bypass_localhost_var.set(True)
        self._ip_whitelist_text.delete("1.0", tk.END)
        self._ip_blacklist_text.delete("1.0", tk.END)
        self._ip_bypass_text.delete("1.0", tk.END)

    def save(self):
        s = self.dialog.db
        s.set_setting("ip_whitelist", self._ip_whitelist_text.get("1.0", tk.END).strip())
        s.set_setting("ip_blacklist", self._ip_blacklist_text.get("1.0", tk.END).strip())
        s.set_setting("ip_bypass_auth", self._ip_bypass_text.get("1.0", tk.END).strip())
        s.set_setting("bypass_localhost", str(self.dialog._bypass_localhost_var.get()))
        s.set_setting("force_password", str(self.dialog.force_password_var.get()))
