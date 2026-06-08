import tkinter as tk
from tkinter import ttk, messagebox
from services.auth_service import AuthService
from services.settings_service import SettingsService
from config import SOFTWARE_NAME, SOFTWARE_VERSION
from utils.validators import validate_port, validate_password_strength


class SetupWizard(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.title(f"欢迎使用 {SOFTWARE_NAME}")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.settings_svc = SettingsService()
        self._step = 0
        self._result = None

        self._build()
        self._show_step(0)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build(self):
        self.step_frame = ttk.Frame(self, padding=20)
        self.step_frame.pack(fill=tk.BOTH, expand=True)

        self.btn_frame = ttk.Frame(self, padding=(20, 0, 20, 10))
        self.btn_frame.pack(fill=tk.X)

        self.prev_btn = ttk.Button(self.btn_frame, text="上一步", command=self._prev_step)
        self.prev_btn.pack(side=tk.LEFT)

        self.next_btn = ttk.Button(self.btn_frame, text="下一步", command=self._next_step)
        self.next_btn.pack(side=tk.RIGHT)

        self.finish_btn = ttk.Button(self.btn_frame, text="完成", command=self._finish)
        self.skip_btn = ttk.Button(self.btn_frame, text="跳过", command=self._on_close)

    def _clear(self):
        for w in self.step_frame.winfo_children():
            w.destroy()

    def _show_step(self, idx):
        self._step = idx
        self._clear()
        steps = [self._step_welcome, self._step_password, self._step_port]
        if 0 <= idx < len(steps):
            steps[idx]()

    def _step_welcome(self):
        ttk.Label(self.step_frame, text=f"欢迎使用 {SOFTWARE_NAME} v{SOFTWARE_VERSION}",
                  font=("", 16, "bold")).pack(pady=(0, 10))
        ttk.Label(self.step_frame, text="全能 DAV 服务 (CardDAV + CalDAV + WebDAV)",
                  font=("", 10)).pack(pady=(0, 15))
        msg = ("PersonalDAV 让您的设备联系人、日历与文件保持同步。\n\n"
               "接下来我们将帮助您完成基础设置：\n"
               "  1. 设置访问密码（可选）\n"
               "  2. 配置服务端口\n\n"
               "您也可以随时在「设置」中修改这些选项。")
        ttk.Label(self.step_frame, text=msg, justify=tk.LEFT).pack(pady=(0, 20))
        self.prev_btn.pack_forget()
        self.skip_btn.pack(side=tk.RIGHT, before=self.next_btn)
        self.next_btn.pack(side=tk.RIGHT)

    def _step_password(self):
        ttk.Label(self.step_frame, text="设置访问密码", font=("", 14, "bold")).pack(pady=(0, 15))
        ttk.Label(self.step_frame, text="设置密码可保护您的数据安全。\n如不需要可点击「跳过」留空。",
                  justify=tk.LEFT).pack(pady=(0, 10))

        ttk.Label(self.step_frame, text="密码:").pack(anchor=tk.W)
        self.pw_var = tk.StringVar()
        pw_entry = ttk.Entry(self.step_frame, textvariable=self.pw_var, show="*", width=30)
        pw_entry.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(self.step_frame, text="确认密码:").pack(anchor=tk.W)
        self.pw2_var = tk.StringVar()
        pw2_entry = ttk.Entry(self.step_frame, textvariable=self.pw2_var, show="*", width=30)
        pw2_entry.pack(fill=tk.X, pady=(0, 5))

        self.pw_hint = ttk.Label(self.step_frame, text="", foreground="red")
        self.pw_hint.pack(anchor=tk.W)

        self.skip_btn.pack(side=tk.RIGHT, before=self.next_btn)
        self.prev_btn.pack(side=tk.LEFT)
        self.next_btn.pack(side=tk.RIGHT)
        pw_entry.focus()

    def _step_port(self):
        ttk.Label(self.step_frame, text="配置服务端口", font=("", 14, "bold")).pack(pady=(0, 15))
        ttk.Label(self.step_frame, text="设置 DAV 服务监听的端口号（1024-65535）。\n默认值 8000 通常无需修改。",
                  justify=tk.LEFT).pack(pady=(0, 10))

        f = ttk.Frame(self.step_frame)
        f.pack(fill=tk.X)
        ttk.Label(f, text="端口:").pack(side=tk.LEFT)
        current_port = self.settings_svc.get_setting("default_port", "8000")
        self.port_var = tk.StringVar(value=current_port)
        port_entry = ttk.Entry(f, textvariable=self.port_var, width=10)
        port_entry.pack(side=tk.LEFT, padx=(5, 0))

        self.port_hint = ttk.Label(self.step_frame, text="", foreground="red")
        self.port_hint.pack(anchor=tk.W, pady=(5, 0))

        self.prev_btn.pack(side=tk.LEFT)
        self.finish_btn.pack(side=tk.RIGHT)
        self.skip_btn.pack_forget()
        self.next_btn.pack_forget()
        port_entry.focus()

    def _prev_step(self):
        self._show_step(self._step - 1)

    def _next_step(self):
        if self._step == 0:
            self._show_step(self._step + 1)
        elif self._step == 1:
            pw = self.pw_var.get()
            pw2 = self.pw2_var.get()
            if pw or pw2:
                if pw != pw2:
                    self.pw_hint.config(text="两次密码不一致")
                    return
                ok, msg = validate_password_strength(pw)
                if not ok:
                    self.pw_hint.config(text=msg)
                    return
                AuthService().set_password(pw)
            self._show_step(self._step + 1)

    def _finish(self):
        port = self.port_var.get().strip()
        if port:
            ok, msg = validate_port(port)
            if not ok:
                self.port_hint.config(text=msg)
                return
            self.settings_svc.set_setting("default_port", port)
        self._result = True
        self.destroy()

    def _on_close(self):
        self._result = False
        self.destroy()
