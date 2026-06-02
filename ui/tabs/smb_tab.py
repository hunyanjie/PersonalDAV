import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
from typing import Any
from services.smb_service import SMBService
from services.settings_service import SettingsService
from utils.logger import logger


class SMBTab(ttk.Frame):
    settings_service: SettingsService
    smb_service: SMBService
    _current_server: str
    _current_share: str
    _current_path: str
    server_var: tk.StringVar
    username_var: tk.StringVar
    password_var: tk.StringVar
    connect_btn: ttk.Button
    up_btn: ttk.Button
    mount_btn: ttk.Button
    path_label: ttk.Label
    tree: ttk.Treeview
    mounts_tree: ttk.Treeview

    def __init__(self, parent: ttk.Notebook, settings_service: SettingsService) -> None:
        super().__init__(parent)
        self.settings_service = settings_service
        self.smb_service = SMBService()
        self._current_server = ""
        self._current_share = ""
        self._current_path = "/"

        self.server_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()

        self.create_widgets()
        self.refresh_mounts()

    def create_widgets(self) -> None:
        conn_frame = ttk.LabelFrame(self, text="连接信息")
        conn_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(conn_frame, text="服务器:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.server_var, width=30).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(conn_frame, text="用户名:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.username_var, width=15).grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        ttk.Label(conn_frame, text="密码:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.password_var, width=15, show="*").grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)

        self.connect_btn = ttk.Button(conn_frame, text="连接", command=self.connect)
        self.connect_btn.grid(row=0, column=6, padx=10, pady=5)

        browse_frame = ttk.LabelFrame(self, text="文件浏览")
        browse_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 5))

        toolbar = ttk.Frame(browse_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        self.up_btn = ttk.Button(toolbar, text="返回上级", command=self.go_up, state=tk.DISABLED)
        self.up_btn.pack(side=tk.LEFT, padx=2)

        self.path_label = ttk.Label(toolbar, text="/")
        self.path_label.pack(side=tk.LEFT, padx=10)

        tree_frame = ttk.Frame(browse_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        columns = ("name", "type", "size", "modified")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        self.tree.heading("name", text="名称")
        self.tree.heading("type", text="类型")
        self.tree.heading("size", text="大小")
        self.tree.heading("modified", text="修改时间")
        self.tree.column("name", width=300)
        self.tree.column("type", width=80)
        self.tree.column("size", width=100)
        self.tree.column("modified", width=160)

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self.on_double_click)

        mounts_frame = ttk.LabelFrame(self, text="已挂载的共享")
        mounts_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        mounts_columns = ("server", "share", "mount_point")
        self.mounts_tree = ttk.Treeview(mounts_frame, columns=mounts_columns, show="headings", height=5)
        self.mounts_tree.heading("server", text="服务器")
        self.mounts_tree.heading("share", text="共享")
        self.mounts_tree.heading("mount_point", text="挂载点")
        self.mounts_tree.column("server", width=150)
        self.mounts_tree.column("share", width=150)
        self.mounts_tree.column("mount_point", width=250)
        self.mounts_tree.pack(fill=tk.X, padx=5, pady=5)

        mounts_btn_frame = ttk.Frame(mounts_frame)
        mounts_btn_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        self.mount_btn = ttk.Button(mounts_btn_frame, text="挂载当前目录", command=self.mount_current, state=tk.DISABLED)
        self.mount_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(mounts_btn_frame, text="刷新挂载列表", command=self.refresh_mounts).pack(side=tk.LEFT, padx=2)

    def connect(self) -> None:
        server = self.server_var.get().strip()
        if not server:
            messagebox.showwarning("提示", "请输入服务器地址", parent=self)
            return

        self.connect_btn.config(state=tk.DISABLED, text="连接中...")
        username = self.username_var.get().strip() or "guest"
        password = self.password_var.get()

        threading.Thread(target=self._connect_thread, args=(server, username, password), daemon=True).start()

    def _connect_thread(self, server: str, username: str, password: str) -> None:
        result = self.smb_service.list_shares(server, username, password)
        self.after(0, lambda: self._connect_done(result))

    def _connect_done(self, result: dict[str, Any]) -> None:
        self.connect_btn.config(state=tk.NORMAL, text="连接")
        if not result["success"]:
            messagebox.showerror("连接失败", result.get("error", "未知错误"), parent=self)
            return

        self.list_shares(result["data"])

    def list_shares(self, shares: list[dict[str, Any]]) -> None:
        self.tree.delete(*self.tree.get_children())
        for share in shares:
            name = share["name"]
            self.tree.insert("", tk.END, values=(name, "共享", "", ""))
        self.path_label.config(text="/")
        self._current_share = ""
        self._current_path = "/"
        self.up_btn.config(state=tk.DISABLED)
        self.mount_btn.config(state=tk.DISABLED)

    def browse_share(self, share: str, path: str = "/") -> None:
        self._current_share = share
        self._current_path = path
        self.path_label.config(text=f"{share}{path}")

        username = self.username_var.get().strip() or "guest"
        password = self.password_var.get()

        self.tree.delete(*self.tree.get_children())
        self.tree.insert("", tk.END, values=("(加载中...)", "", "", ""))
        self.up_btn.config(state=tk.DISABLED)
        self.mount_btn.config(state=tk.DISABLED)

        threading.Thread(
            target=self._browse_thread,
            args=(self._current_server, share, path, username, password),
            daemon=True
        ).start()

    def _browse_thread(self, server: str, share: str, path: str, username: str, password: str) -> None:
        result = self.smb_service.list_files(server, share, path, username, password)
        self.after(0, lambda: self._browse_done(result))

    def _browse_done(self, result: dict[str, Any]) -> None:
        self.tree.delete(*self.tree.get_children())
        if not result["success"]:
            messagebox.showerror("读取失败", result.get("error", "未知错误"), parent=self)
            return

        files = result["data"]
        for f in files:
            name = f["name"]
            if name == "." or name == "..":
                continue
            is_dir = f["is_directory"]
            ftype = "文件夹" if is_dir else "文件"
            size = "" if is_dir else self._format_size(f.get("size", 0))
            modified = f.get("last_modified", "") or ""
            self.tree.insert("", tk.END, values=(name, ftype, size, modified))

        self.up_btn.config(state=tk.NORMAL if self._current_path != "/" else tk.DISABLED)
        self.mount_btn.config(state=tk.NORMAL)

    def on_double_click(self, event: tk.Event) -> None:
        item = self.tree.selection()
        if not item:
            return
        values = self.tree.item(item[0], "values")
        name = values[0]
        ftype = values[1]

        if ftype != "文件夹":
            return

        if self._current_share:
            path = self._current_path.rstrip("/") + "/" + name
            self.browse_share(self._current_share, path)

    def go_up(self) -> None:
        if not self._current_share or self._current_path == "/":
            return
        parent = "/".join(self._current_path.rstrip("/").split("/")[:-1]) or "/"
        if not parent.startswith("/"):
            parent = "/" + parent
        self.browse_share(self._current_share, parent)

    def mount_current(self) -> None:
        if not self._current_server or not self._current_share:
            return

        mount_point = f"/mnt/smb/{self._current_share}"
        username = self.username_var.get().strip() or "guest"
        password = self.password_var.get()

        def run() -> None:
            result = self.smb_service.mount(
                self._current_server, self._current_share,
                mount_point, username, password
            )
            self.after(0, lambda: self._mount_done(result))

        threading.Thread(target=run, daemon=True).start()

    def _mount_done(self, result: dict[str, Any]) -> None:
        if not result["success"]:
            messagebox.showerror("挂载失败", result.get("error", "未知错误"), parent=self)
            return
        messagebox.showinfo("挂载成功", f"已挂载到 {result['data']['mount_point']}", parent=self)
        self.refresh_mounts()

    def refresh_mounts(self) -> None:
        self.mounts_tree.delete(*self.mounts_tree.get_children())
        result = self.smb_service.get_mounted_shares()
        if result["success"]:
            for m in result["data"]:
                self.mounts_tree.insert("", tk.END, values=(m["server"], m["share"], m["mount_point"]))

    @staticmethod
    def _format_size(size: float | int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
