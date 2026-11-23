import tkinter as tk
from tkinter import ttk, messagebox, filedialog


class MountDialog(tk.Toplevel):
    def __init__(self, parent, initial_name="", initial_path="", initial_quota=None):
        super().__init__(parent)
        self.title("挂载点设置")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.result = None

        ttk.Label(self, text="挂载名称:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 2))
        self.name_var = tk.StringVar(value=initial_name)
        ttk.Entry(self, textvariable=self.name_var, width=40).grid(row=0, column=1, padx=10, pady=(10, 2))

        ttk.Label(self, text="文件系统路径:").grid(row=1, column=0, sticky="w", padx=10, pady=2)
        self.path_var = tk.StringVar(value=initial_path)
        ttk.Entry(self, textvariable=self.path_var, width=40).grid(row=1, column=1, padx=10, pady=2)
        ttk.Button(self, text="浏览...", command=lambda: self.path_var.set(filedialog.askdirectory(parent=self))).grid(row=1, column=2, padx=5, pady=2)

        ttk.Label(self, text="空间上限 (MB):").grid(row=2, column=0, sticky="w", padx=10, pady=2)
        self.quota_var = tk.StringVar(value="" if initial_quota in (None, "") else str(initial_quota))
        ttk.Entry(self, textvariable=self.quota_var, width=40).grid(row=2, column=1, columnspan=2, sticky="w", padx=10, pady=2)
        ttk.Label(self, text="留空表示使用设备真实容量；可设置大于实际容量的上限。",
                  foreground="gray").grid(row=3, column=0, columnspan=3, sticky="w", padx=10)

        btn_f = ttk.Frame(self)
        btn_f.grid(row=4, column=0, columnspan=3, pady=10)
        ttk.Button(btn_f, text="确定", command=self.confirm).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=5)

        from utils.window_utils import center_window
        center_window(self, parent)

    def confirm(self):
        name = self.name_var.get().strip()
        path = self.path_var.get().strip()
        if not name or not path:
            messagebox.showwarning("提示", "请填写完整信息", parent=self)
            return
        quota_text = self.quota_var.get().strip()
        quota = None
        if quota_text:
            try:
                quota = float(quota_text)
            except ValueError:
                messagebox.showwarning("提示", "空间上限必须是数字（MB）", parent=self)
                return
            if quota <= 0:
                messagebox.showwarning("提示", "空间上限必须大于 0", parent=self)
                return
        self.result = {"name": name, "path": path, "quota_mb": quota}
        self.destroy()
