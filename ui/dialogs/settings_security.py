import tkinter as tk
from tkinter import ttk, messagebox
from ui.widgets.enhanced_tooltip import EnhancedTooltip
from services.auth_service import AuthService
from utils.validators import validate_port, validate_ip_list, validate_password_strength


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
        url_frame = ttk.Frame(sub); sub.add(url_frame, text="URL/Referer/远程")

        self._create_password_ui(pw_frame)
        self._create_ip_ui(ip_frame)
        self._create_rate_ui(rate_frame)
        self._create_url_auth_ui(url_frame)
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
        self._ip_wl_hint = ttk.Label(ip_f, text="", font=("", 8))
        self._ip_wl_hint.grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(ip_f, text="黑名单（每行一个 IP / CIDR / 通配符）:",
                  foreground="gray").grid(row=2, column=0, sticky="w", padx=5, pady=(5, 0))
        self._ip_blacklist_text = tk.Text(ip_f, height=3, width=60)
        self._ip_blacklist_text.grid(row=3, column=0, padx=5, pady=2, sticky="ew")
        self._ip_bl_hint = ttk.Label(ip_f, text="", font=("", 8))
        self._ip_bl_hint.grid(row=3, column=1, sticky="w", padx=5)
        ttk.Label(ip_f, text="示例: 127.0.0.1 | 192.168.1.0/24 | 10.0.* | 白名单非空时只允许白名单 IP 访问",
                  foreground="gray", font=('', 8)).grid(row=4, column=0, sticky="w", padx=5, pady=(0, 5))

        def _ip_check(text_widget, hint_label, *_, name="IP"):
            val = text_widget.get("1.0", tk.END).strip()
            errors = validate_ip_list(val)
            if errors:
                hint_label.config(text=f"{len(errors)} 个无效格式", foreground="red")
            else:
                hint_label.config(text="", foreground="")
        self._ip_whitelist_text.bind("<KeyRelease>", lambda *a: _ip_check(self._ip_whitelist_text, self._ip_wl_hint, name="白名单"))
        self._ip_blacklist_text.bind("<KeyRelease>", lambda *a: _ip_check(self._ip_blacklist_text, self._ip_bl_hint, name="黑名单"))

        self.dialog._bypass_localhost_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="本机访问免密码",
                        variable=self.dialog._bypass_localhost_var).pack(anchor="w", padx=10, pady=(5, 0))

        bypass_f = ttk.LabelFrame(parent, text="免密码 IP（以下 IP 访问时不需密码验证）")
        bypass_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(bypass_f, text="每行一个 IP / CIDR / 通配符:",
                  foreground="gray").grid(row=0, column=0, sticky="w", padx=5, pady=(5, 0))
        self._ip_bypass_text = tk.Text(bypass_f, height=3, width=60)
        self._ip_bypass_text.grid(row=1, column=0, padx=5, pady=2, sticky="ew")
        self._ip_bypass_hint = ttk.Label(bypass_f, text="", font=("", 8))
        self._ip_bypass_hint.grid(row=1, column=1, sticky="w", padx=5)
        def _bypass_check(*_):
            val = self._ip_bypass_text.get("1.0", tk.END).strip()
            errors = validate_ip_list(val)
            self._ip_bypass_hint.config(text=f"{len(errors)} 个无效格式" if errors else "", foreground="red" if errors else "")
        self._ip_bypass_text.bind("<KeyRelease>", _bypass_check)

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

    def _create_url_auth_ui(self, parent):
        # ── URL 鉴权 ──
        url_f = ttk.LabelFrame(parent, text="URL 鉴权（附件下载链接 时间戳+随机数+MD5）")
        url_f.pack(fill=tk.X, padx=5, pady=5)
        self.dialog.url_auth_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(url_f, text="启用 URL 鉴权",
                        variable=self.dialog.url_auth_enabled_var).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Label(url_f, text="令牌有效期（秒）:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dialog.url_auth_expiry_var = tk.StringVar(value="300")
        ttk.Entry(url_f, textvariable=self.dialog.url_auth_expiry_var, width=10).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(url_f, text="开启后附件下载链接需携带 ?token=&ts=&nonce= 参数，",
                  foreground="gray", font=('', 8)).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=(0, 2))
        ttk.Label(url_f, text="令牌由服务端密钥 + 时间戳 + 随机数 + 路径 MD5 生成。",
                  foreground="gray", font=('', 8)).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=(0, 5))

        # ── Referer 鉴权 ──
        ref_f = ttk.LabelFrame(parent, text="Referer 鉴权（防盗链）")
        ref_f.pack(fill=tk.X, padx=5, pady=5)
        self.dialog.referer_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ref_f, text="启用 Referer 鉴权",
                        variable=self.dialog.referer_enabled_var).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Label(ref_f, text="允许的 Referer 前缀（每行一个，匹配开头）:",
                  foreground="gray").grid(row=1, column=0, sticky="w", padx=5, pady=(0, 2))
        self._referer_text = tk.Text(ref_f, height=4, width=60)
        self._referer_text.grid(row=2, column=0, padx=5, pady=2, sticky="ew")
        ttk.Label(ref_f, text="示例: http://localhost:8080 | https://example.com",
                  foreground="gray", font=('', 8)).grid(row=3, column=0, sticky="w", padx=5, pady=(0, 5))

        # ── 远程鉴权 ──
        remote_f = ttk.LabelFrame(parent, text="远程鉴权（转发请求到外部服务验证）")
        remote_f.pack(fill=tk.X, padx=5, pady=5)
        self.dialog.remote_auth_enabled_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(remote_f, text="启用远程鉴权（开启后将转发所有请求到远程地址验证，通过后可跳过密码校验）",
                        variable=self.dialog.remote_auth_enabled_var).grid(row=0, column=0, columnspan=2, sticky="w", padx=5, pady=5)
        ttk.Label(remote_f, text="远程鉴权 URL:").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.dialog.remote_auth_url_var = tk.StringVar(value="")
        ttk.Entry(remote_f, textvariable=self.dialog.remote_auth_url_var, width=50).grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(remote_f, text="超时（秒）:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.dialog.remote_auth_timeout_var = tk.StringVar(value="10")
        ttk.Entry(remote_f, textvariable=self.dialog.remote_auth_timeout_var, width=10).grid(row=2, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(remote_f, text="POST JSON 到远程地址，返回 allow/ok/true/1/yes 表示允许，其余拒绝。",
                  foreground="gray", font=('', 8)).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=(0, 2))
        ttk.Label(remote_f, text='请求体: {"path","method","headers","client_ip","timestamp"}',
                  foreground="gray", font=('', 8)).grid(row=4, column=0, columnspan=2, sticky="w", padx=5, pady=(0, 5))

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
        from utils.window_utils import center_window; center_window(dialog, self._parent_frame)
        row = 0
        old_entry = None
        if change:
            ttk.Label(dialog, text="当前密码:").grid(row=row, column=0, sticky="w", padx=10, pady=5)
            old_var = tk.StringVar()
            old_entry = ttk.Entry(dialog, textvariable=old_var, show="*", width=30)
            old_entry.grid(row=row, column=1, padx=5)
            row += 1
        ttk.Label(dialog, text="新密码:").grid(row=row, column=0, sticky="w", padx=10, pady=5)
        new_var = tk.StringVar()
        new_entry = ttk.Entry(dialog, textvariable=new_var, show="*", width=30)
        new_entry.grid(row=row, column=1, padx=5)
        row += 1
        ttk.Label(dialog, text="确认密码:").grid(row=row, column=0, sticky="w", padx=10, pady=5)
        confirm_var = tk.StringVar()
        confirm_entry = ttk.Entry(dialog, textvariable=confirm_var, show="*", width=30)
        confirm_entry.grid(row=row, column=1, padx=5)
        row += 1
        hint = ttk.Label(dialog, text="", foreground="red")
        hint.grid(row=row, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 5))
        row += 1

        def _pw_keyup(*_):
            pw = new_var.get()
            pw2 = confirm_var.get()
            if not pw and not pw2:
                hint.config(text="", foreground="red"); return
            if pw and pw2 and pw != pw2:
                hint.config(text="两次密码不一致", foreground="red"); return
            ok, msg = validate_password_strength(pw) if pw else (True, "")
            if ok:
                hint.config(text=("" if not pw2 else "✓ 密码一致") if pw else "", foreground="green")
            else:
                hint.config(text=msg, foreground="red")
        new_entry.bind("<KeyRelease>", _pw_keyup)
        confirm_entry.bind("<KeyRelease>", _pw_keyup)

        def do_save(*_):
            if change and not AuthService().verify_password(old_var.get()):
                messagebox.showerror("错误", "当前密码不正确", parent=dialog)
                return
            pw = new_var.get()
            if not pw:
                hint.config(text="密码不能为空", foreground="red"); return
            ok, msg = validate_password_strength(pw)
            if not ok:
                hint.config(text=msg, foreground="red"); return
            if pw != confirm_var.get():
                hint.config(text="两次密码不一致", foreground="red"); return
            AuthService().set_password(pw)
            self._refresh()
            dialog.destroy()
            messagebox.showinfo("成功", "密码已更新", parent=self._parent_frame)
        btn_f = ttk.Frame(dialog)
        btn_f.grid(row=row, column=0, columnspan=2, pady=15)
        ttk.Button(btn_f, text="确定", command=do_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        for w in ([old_entry, new_entry, confirm_entry] if change else [new_entry, confirm_entry]):
            if w: w.bind("<Return>", do_save)

    def _clear_password(self):
        svc = AuthService()
        if not svc.is_enabled():
            return
        dialog = tk.Toplevel(self._parent_frame)
        dialog.title("清除密码")
        dialog.transient(self._parent_frame)
        dialog.grab_set()
        from utils.window_utils import center_window; center_window(dialog, self._parent_frame)
        ttk.Label(dialog, text="请输入当前密码以确认清除:").pack(pady=(10, 5))
        pw_var = tk.StringVar()
        pw_entry = ttk.Entry(dialog, textvariable=pw_var, show="*", width=25)
        pw_entry.pack(pady=2)
        def do_clear(*_):
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
        pw_entry.bind("<Return>", do_clear)
        pw_entry.focus()

    def _rotate_mcp_token(self):
        AuthService().rotate_mcp_token()
        self._refresh()
        from ui.widgets.toast import Toast
        Toast.success(self._parent_frame, "MCP 令牌已轮换，旧令牌立即失效")

    def _copy_mcp_token(self):
        token = AuthService().get_mcp_token()
        if not token:
            messagebox.showinfo("提示", "请先设置密码", parent=self._parent_frame)
            return
        self._parent_frame.clipboard_clear()
        self._parent_frame.clipboard_append(token)
        from ui.widgets.toast import Toast
        Toast.success(self._parent_frame, "MCP 令牌已复制到剪贴板")

    def load(self):
        s = self.dialog.db
        self.dialog._load_text_widget_lines(self._ip_whitelist_text, s.get_setting("ip_whitelist", ""))
        self.dialog._load_text_widget_lines(self._ip_blacklist_text, s.get_setting("ip_blacklist", ""))
        self.dialog._load_text_widget_lines(self._ip_bypass_text, s.get_setting("ip_bypass_auth", ""))
        self.dialog._bypass_localhost_var.set(s.get_setting("bypass_localhost", "True") == "True")
        self.dialog.force_password_var.set(s.get_setting("force_password", "True") == "True")
        self.dialog.url_auth_enabled_var.set(s.get_setting("url_auth_enabled", "False") == "True")
        self.dialog.url_auth_expiry_var.set(s.get_setting("url_auth_expiry", "300"))
        self.dialog.referer_enabled_var.set(s.get_setting("referer_enabled", "False") == "True")
        self.dialog._load_text_widget_lines(self._referer_text, s.get_setting("referer_whitelist", ""))
        self.dialog.remote_auth_enabled_var.set(s.get_setting("remote_auth_enabled", "False") == "True")
        self.dialog.remote_auth_url_var.set(s.get_setting("remote_auth_url", ""))
        self.dialog.remote_auth_timeout_var.set(s.get_setting("remote_auth_timeout", "10"))

    def reset(self):
        self.dialog._bypass_localhost_var.set(True)
        self._ip_whitelist_text.delete("1.0", tk.END)
        self._ip_blacklist_text.delete("1.0", tk.END)
        self._ip_bypass_text.delete("1.0", tk.END)
        self.dialog.url_auth_enabled_var.set(False)
        self.dialog.url_auth_expiry_var.set("300")
        self.dialog.referer_enabled_var.set(False)
        self._referer_text.delete("1.0", tk.END)
        self.dialog.remote_auth_enabled_var.set(False)
        self.dialog.remote_auth_url_var.set("")
        self.dialog.remote_auth_timeout_var.set("10")

    def save(self):
        s = self.dialog.db
        whitelist = self._ip_whitelist_text.get("1.0", tk.END).strip()
        blacklist = self._ip_blacklist_text.get("1.0", tk.END).strip()
        bypass = self._ip_bypass_text.get("1.0", tk.END).strip()
        for name, val in [("白名单", whitelist), ("黑名单", blacklist), ("免密码 IP", bypass)]:
            errors = validate_ip_list(val)
            if errors:
                lines = "\n".join(f"  {p}: {m}" for p, m in errors)
                messagebox.showerror("IP 格式错误", f"{name} 中存在无效条目:\n{lines}", parent=self._parent_frame)
                return
        s.set_setting("ip_whitelist", whitelist)
        s.set_setting("ip_blacklist", blacklist)
        s.set_setting("ip_bypass_auth", bypass)
        s.set_setting("bypass_localhost", str(self.dialog._bypass_localhost_var.get()))
        s.set_setting("force_password", str(self.dialog.force_password_var.get()))
        s.set_setting("url_auth_enabled", str(self.dialog.url_auth_enabled_var.get()))
        s.set_setting("url_auth_expiry", self.dialog.url_auth_expiry_var.get())
        s.set_setting("referer_enabled", str(self.dialog.referer_enabled_var.get()))
        s.set_setting("referer_whitelist", self._referer_text.get("1.0", tk.END).strip())
        s.set_setting("remote_auth_enabled", str(self.dialog.remote_auth_enabled_var.get()))
        s.set_setting("remote_auth_url", self.dialog.remote_auth_url_var.get())
        s.set_setting("remote_auth_timeout", self.dialog.remote_auth_timeout_var.get())
