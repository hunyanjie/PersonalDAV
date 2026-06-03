import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
import os
from typing import Any
from services.smb_service import SMBService
from services.ftp_client_service import FTPClientService
from services.settings_service import SettingsService
from utils.logger import logger


class SMBTab(ttk.Frame):
    settings_service: SettingsService
    smb_service: SMBService
    ftp_client: FTPClientService
    _current_protocol: str
    _current_server: str
    _current_share: str
    _current_path: str
    protocol_var: tk.StringVar
    server_var: tk.StringVar
    port_var: tk.StringVar
    username_var: tk.StringVar
    password_var: tk.StringVar
    connect_btn: ttk.Button
    up_btn: ttk.Button
    mount_btn: ttk.Button
    path_label: ttk.Label
    tree: ttk.Treeview
    mounts_tree: ttk.Treeview

    PROTOCOLS = {"SMB": 445, "FTP": 21, "FTPS": 990, "SFTP": 22}
    ENCODINGS = [
        "utf-8", "utf-16be", "utf-16le", "utf-32be", "utf-32le",
        "gb2312", "gb18030", "gbk", "big5", "big5-hkscs",
        "cesu-8", "euc-jp", "euc-kr",
        "ibm866", "ibm850",
        "iso-2022-jp", "iso-2022-kr", "iso-8859-1", "iso-8859-2",
        "iso-8859-3", "iso-8859-4", "iso-8859-5", "iso-8859-6",
        "iso-8859-7", "iso-8859-8", "iso-8859-9", "iso-8859-10",
        "iso-8859-13", "iso-8859-14", "iso-8859-15",
        "koi8-r", "koi8-u",
        "shift-jis",
        "cp1250", "cp1251", "cp1252", "cp1253", "cp1254",
        "cp1255", "cp1256", "cp1257", "cp1258",
    ]

    def __init__(self, parent: ttk.Notebook, settings_service: SettingsService) -> None:
        super().__init__(parent)
        self.settings_service = settings_service
        self.smb_service = SMBService()
        self.ftp_client = FTPClientService()
        self._current_protocol = "SMB"
        self._current_server = ""
        self._current_share = ""
        self._current_path = "/"

        self.protocol_var = tk.StringVar(value="SMB")
        self.server_var = tk.StringVar()
        self.port_var = tk.StringVar(value="445")
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.encoding_var = tk.StringVar(value="utf-8")

        self.create_widgets()
        self.refresh_mounts()

    def create_widgets(self) -> None:
        conn_frame = ttk.LabelFrame(self, text="连接信息")
        conn_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        ttk.Label(conn_frame, text="协议:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        proto_combo = ttk.Combobox(conn_frame, textvariable=self.protocol_var,
                                   values=list(self.PROTOCOLS.keys()), state="readonly", width=6)
        proto_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        proto_combo.bind("<<ComboboxSelected>>", self._on_protocol_change)

        ttk.Label(conn_frame, text="服务器:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.server_var, width=25).grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        ttk.Label(conn_frame, text="端口:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.port_var, width=6).grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)

        ttk.Label(conn_frame, text="用户名:").grid(row=0, column=6, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.username_var, width=12).grid(row=0, column=7, padx=5, pady=5, sticky=tk.W)

        ttk.Label(conn_frame, text="密码:").grid(row=0, column=8, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(conn_frame, textvariable=self.password_var, width=12, show="*").grid(row=0, column=9, padx=5, pady=5, sticky=tk.W)

        ttk.Label(conn_frame, text="编码:").grid(row=0, column=10, padx=5, pady=5, sticky=tk.W)
        encoding_combo = ttk.Combobox(conn_frame, textvariable=self.encoding_var,
                                       values=list(self.ENCODINGS), state="readonly", width=8)
        encoding_combo.grid(row=0, column=11, padx=5, pady=5, sticky=tk.W)

        self.connect_btn = ttk.Button(conn_frame, text="连接", command=self.connect)
        self.connect_btn.grid(row=0, column=12, padx=10, pady=5)

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

        mounts_frame = ttk.LabelFrame(self, text="已挂载的共享 / 连接记录")
        mounts_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        mounts_columns = ("protocol", "server", "share", "mount_point")
        self.mounts_tree = ttk.Treeview(mounts_frame, columns=mounts_columns, show="headings", height=4)
        self.mounts_tree.heading("protocol", text="协议")
        self.mounts_tree.heading("server", text="服务器")
        self.mounts_tree.heading("share", text="路径")
        self.mounts_tree.heading("mount_point", text="挂载点")
        self.mounts_tree.column("protocol", width=60)
        self.mounts_tree.column("server", width=150)
        self.mounts_tree.column("share", width=150)
        self.mounts_tree.column("mount_point", width=200)
        self.mounts_tree.pack(fill=tk.X, padx=5, pady=5)

        mounts_btn_frame = ttk.Frame(mounts_frame)
        mounts_btn_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        self.mount_btn = ttk.Button(mounts_btn_frame, text="挂载 / 保存连接", command=self.mount_current, state=tk.DISABLED)
        self.mount_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(mounts_btn_frame, text="刷新列表", command=self.refresh_mounts).pack(side=tk.LEFT, padx=2)

    def _on_protocol_change(self, event=None) -> None:
        proto = self.protocol_var.get()
        self.port_var.set(str(self.PROTOCOLS.get(proto, "21")))
        if proto == "SMB":
            self.mount_btn.config(text="挂载 / 保存连接")
        else:
            self.mount_btn.config(text="保存连接")

    def connect(self) -> None:
        self._current_protocol = self.protocol_var.get()
        server = self.server_var.get().strip()
        if not server:
            messagebox.showwarning("提示", "请输入服务器地址", parent=self)
            return

        self.connect_btn.config(state=tk.DISABLED, text="连接中...")
        username = self.username_var.get().strip() or "anonymous"
        password = self.password_var.get()
        port = self.port_var.get().strip() or str(self.PROTOCOLS.get(self._current_protocol, "21"))

        threading.Thread(
            target=self._connect_thread,
            args=(self._current_protocol, server, port, username, password),
            daemon=True
        ).start()

    def _connect_thread(self, protocol: str, server: str, port: str, username: str, password: str) -> None:
        proto_lower = protocol.lower()
        if protocol == "SMB":
            result = self.smb_service.list_shares(server, username, password)
        else:
            result = self.ftp_client.list_dir(proto_lower, server, int(port), username, password, "/", encoding=self.encoding_var.get())
        self.after(0, lambda: self._connect_done(protocol, server, port, username, password, result))

    def _connect_done(self, protocol: str, server: str, port: str, username: str, password: str, result: dict[str, Any]) -> None:
        self.connect_btn.config(state=tk.NORMAL, text="连接")
        if not result["success"]:
            messagebox.showerror("连接失败", result.get("error", "未知错误"), parent=self)
            return

        account = f"{username}@" if username and username != "anonymous" else ""
        self._current_server = f"{protocol}://{account}{server}:{port}"
        self._current_share = ""
        self._current_path = "/"

        if protocol == "SMB":
            self.list_shares(result["data"])
        else:
            self._display_files(result["data"])

    def list_shares(self, shares: list[dict[str, Any]]) -> None:
        self.tree.delete(*self.tree.get_children())
        for share in shares:
            name = share["name"]
            self.tree.insert("", tk.END, values=(name, "共享", "", ""))
        self.path_label.config(text="/")
        self.up_btn.config(state=tk.DISABLED)
        self.mount_btn.config(state=tk.DISABLED)

    def _display_files(self, files: list[dict[str, Any]]) -> None:
        self.tree.delete(*self.tree.get_children())
        for f in files:
            name = f["name"]
            if name in (".", ".."):
                continue
            is_dir = f["is_directory"]
            ftype = "文件夹" if is_dir else "文件"
            size = "" if is_dir else self._format_size(f.get("size", 0))
            modified = f.get("modified", "") or ""
            self.tree.insert("", tk.END, values=(name, ftype, size, modified))
        self.up_btn.config(state=tk.NORMAL if self._current_path != "/" else tk.DISABLED)
        self.mount_btn.config(state=tk.NORMAL)

    def browse_share(self, share: str, path: str = "/") -> None:
        self._current_share = share
        self._current_path = path
        self.path_label.config(text=f"{share}{path}")

        username = self.username_var.get().strip() or "anonymous"
        password = self.password_var.get()

        self.tree.delete(*self.tree.get_children())
        self.tree.insert("", tk.END, values=("(加载中...)", "", "", ""))
        self.up_btn.config(state=tk.DISABLED)
        self.mount_btn.config(state=tk.DISABLED)

        if self._current_protocol == "SMB":
            threading.Thread(
                target=self._browse_smb_thread,
                args=(self._current_server, share, path, username, password),
                daemon=True
            ).start()
        else:
            threading.Thread(
                target=self._browse_ftp_thread,
                args=(path, username, password),
                daemon=True
            ).start()

    def _browse_smb_thread(self, server: str, share: str, path: str, username: str, password: str) -> None:
        clean_server = server.split("://")[-1].rsplit(":", 1)[0]
        result = self.smb_service.list_files(clean_server, share, path, username, password)
        self.after(0, lambda: self._display_files(result["data"] if result["success"] else []))

    def _browse_ftp_thread(self, path: str, username: str, password: str) -> None:
        parts = self._current_server.split("://")[-1].rsplit(":", 1)
        server = parts[0]
        port = int(parts[1]) if len(parts) > 1 else 21
        result = self.ftp_client.list_dir(
            self._current_protocol.lower(), server, port, username, password, path, encoding=self.encoding_var.get()
        )
        self.after(0, lambda: self._display_files(result["data"] if result["success"] else []))

    def on_double_click(self, event: tk.Event) -> None:
        item = self.tree.selection()
        if not item:
            return
        values = self.tree.item(item[0], "values")
        name = values[0]
        ftype = values[1]

        if ftype != "文件夹" and ftype != "共享":
            return

        if ftype == "共享":
            self.browse_share(name, "/")
        elif self._current_share:
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
        if not self._current_server:
            return

        mount_point = f"/mnt/{self._current_protocol.lower()}/{self._current_share or 'root'}"
        username = self.username_var.get().strip() or "anonymous"
        password = self.password_var.get()

        if self._current_protocol == "SMB":
            parts = self._current_server.split("://")[-1].rsplit(":", 1)
            server = parts[0]
            result = self.smb_service.mount(server, self._current_share, mount_point, username, password)
        else:
            proto_lower = self._current_protocol.lower()
            result = self.ftp_client.list_dir(proto_lower,
                self._current_server.split("://")[-1].rsplit(":", 1)[0],
                int(self._current_server.split(":")[-1]),
                username, password, "/",
                encoding=self.encoding_var.get())
            result = {"success": True, "data": {"mount_point": mount_point}}

        if not result["success"]:
            messagebox.showerror("失败", result.get("error", "未知错误"), parent=self)
            return
        messagebox.showinfo("成功", f"已保存连接: {mount_point}", parent=self)
        self.refresh_mounts()

    def refresh_mounts(self) -> None:
        self.mounts_tree.delete(*self.mounts_tree.get_children())
        result = self.smb_service.get_mounted_shares()
        if result["success"]:
            for m in result["data"]:
                self.mounts_tree.insert("", tk.END, values=("SMB", m["server"], m["share"], m["mount_point"]))

    @staticmethod
    def _format_size(size: float | int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"