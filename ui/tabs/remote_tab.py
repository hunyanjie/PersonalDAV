import tkinter as tk
from tkinter import ttk, messagebox
import threading
import os
from typing import Any
from services.smb_service import SMBService
from services.ftp_client_service import FTPClientService
from services.dav_client_service import DAVClientService
from services.settings_service import SettingsService
from services.auth_service import AuthService
from utils.logger import logger
from ui.tabs.remote_mount_manager import RemoteMountManager
from ui.tabs.remote_file_ops import RemoteFileOps


class RemoteTab(ttk.Frame):
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

    PROTOCOLS = {"SMB": 445, "FTP": 21, "FTPS": 21, "SFTP": 22, "WebDAV": 80}
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
        self.dav_client = DAVClientService()
        self._current_protocol = "SMB"
        self._current_server = ""
        self._current_share = ""
        self._current_path = "/"
        self._is_connected = False
        self._sort_state: dict[str, Any] = {"column": "name", "ascending": True}
        self._heading_text = {"name": "名称", "type": "类型", "size": "大小", "modified": "修改时间"}

        self.protocol_var = tk.StringVar(value="SMB")
        self.server_var = tk.StringVar()
        self.port_var = tk.StringVar(value="445")
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.encoding_var = tk.StringVar(value="utf-8")

        self.mount_mgr = RemoteMountManager(self)
        self.file_ops = RemoteFileOps(self)

        self.create_widgets()
        self.mount_mgr.refresh()

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

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=2)

        self.upload_btn = ttk.Button(toolbar, text="上传", command=self.file_ops.upload_file, state=tk.DISABLED)
        self.upload_btn.pack(side=tk.LEFT, padx=2)
        self.download_btn = ttk.Button(toolbar, text="下载", command=self.file_ops.download_selected, state=tk.DISABLED)
        self.download_btn.pack(side=tk.LEFT, padx=2)
        self.delete_btn = ttk.Button(toolbar, text="删除", command=self.file_ops.delete_selected, state=tk.DISABLED)
        self.delete_btn.pack(side=tk.LEFT, padx=2)
        self.rename_btn = ttk.Button(toolbar, text="重命名", command=self.file_ops.rename_file, state=tk.DISABLED)
        self.rename_btn.pack(side=tk.LEFT, padx=2)
        self.newdir_btn = ttk.Button(toolbar, text="新建文件夹", command=self.file_ops.new_folder, state=tk.DISABLED)
        self.newdir_btn.pack(side=tk.LEFT, padx=2)

        self.path_label = ttk.Label(toolbar, text="/")
        self.path_label.pack(side=tk.LEFT, padx=10)

        tree_frame = ttk.Frame(browse_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        columns = ("name", "type", "size", "modified")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=self._heading_text[col],
                              command=lambda c=col: self._on_column_click(c))
        self.tree.column("name", width=300)
        self.tree.column("type", width=80)
        self.tree.column("size", width=100)
        self.tree.column("modified", width=160)

        tree_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.file_ops.show_tree_context_menu)

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

        self.mount_btn = ttk.Button(mounts_btn_frame, text="挂载 / 保存连接",
                                    command=self.mount_mgr.mount_current, state=tk.DISABLED)
        self.mount_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(mounts_btn_frame, text="刷新列表", command=self.mount_mgr.refresh).pack(side=tk.LEFT, padx=2)
        self.mounts_tree.bind("<Double-1>", lambda e: self.mount_mgr.on_double_click())
        self.mounts_tree.bind("<Button-3>", self.mount_mgr.show_context_menu)

    def _on_protocol_change(self, event=None) -> None:
        proto = self.protocol_var.get()
        if proto == "WebDAV":
            from services.settings_service import SettingsService
            server_port = SettingsService().get_setting("default_port", "8000")
            self.port_var.set(server_port)
        else:
            self.port_var.set(str(self.PROTOCOLS.get(proto, 21)))
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
        if server == "0.0.0.0":
            server = "127.0.0.1"

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
        if protocol == "SMB":
            result = self.smb_service.list_shares(server, username, password)
        elif protocol == "WebDAV":
            result = self.dav_client.list_dir("webdav", server, int(port), username, password, "/", encoding=self.encoding_var.get())
        else:
            result = self.ftp_client.list_dir(protocol.lower(), server, int(port), username, password, "/", encoding=self.encoding_var.get())
        self.after(0, lambda: self._connect_done(protocol, server, port, username, password, result))

    def _connect_done(self, protocol: str, server: str, port: str, username: str, password: str, result: dict[str, Any]) -> None:
        self.connect_btn.config(state=tk.NORMAL, text="连接")
        AuthService().log_auth(result["success"], server, f"远程文件/{protocol}",
                               f"用户={username},端口={port}")
        if not result["success"]:
            messagebox.showerror("连接失败", result.get("error", "未知错误"), parent=self)
            return

        account = f"{username}@" if username and username != "anonymous" else ""
        if protocol == "WebDAV" and port in ("80", "443"):
            self._current_server = f"{protocol}://{account}{server}"
        else:
            self._current_server = f"{protocol}://{account}{server}:{port}"
        self._current_share = ""
        self._current_path = "/"
        self._is_connected = True

        if protocol == "SMB":
            self.list_shares(result["data"])
        else:
            self._display_files(result["data"])

    def list_shares(self, shares: list[dict[str, Any]]) -> None:
        self.tree.delete(*self.tree.get_children())
        for share in shares:
            self.tree.insert("", tk.END, values=(share["name"], "共享", "", ""))
        self.path_label.config(text="/")
        self.up_btn.config(state=tk.DISABLED)
        self.mount_btn.config(state=tk.DISABLED)
        for btn in (self.upload_btn, self.download_btn, self.delete_btn, self.rename_btn, self.newdir_btn):
            btn.config(state=tk.DISABLED)

    @staticmethod
    def _format_date(raw: str) -> str:
        if not raw:
            return ""
        import datetime
        if isinstance(raw, (int, float)):
            return datetime.datetime.fromtimestamp(raw).strftime("%Y-%m-%d %H:%M")
        if raw.isdigit() or (raw.replace(".", "").isdigit() and len(raw) >= 8):
            raw_clean = raw.split(".")[0]
            if len(raw_clean) >= 14:
                try:
                    return datetime.datetime.strptime(raw_clean[:14], "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M")
                except ValueError:
                    pass
            elif len(raw_clean) == 8:
                try:
                    return datetime.datetime.strptime(raw_clean, "%Y%m%d").strftime("%Y-%m-%d")
                except ValueError:
                    pass
        return raw

    def _display_files(self, files: list[dict[str, Any]]) -> None:
        self.tree.delete(*self.tree.get_children())
        sorted_files = sorted(
            (f for f in files if f.get("name", "") not in (".", "..")),
            key=lambda f: (0 if f.get("is_directory") else 1, (f.get("name") or "").lower())
        )
        for f in sorted_files:
            name = f["name"]
            ftype = "文件夹" if f.get("is_directory") else (os.path.splitext(name)[1].lstrip(".").upper() or "文件")
            size = "" if f.get("is_directory") else self._format_size(f.get("size", 0))
            modified = self._format_date(f.get("modified", ""))
            self.tree.insert("", tk.END, values=(name, ftype, size, modified))
        self._re_sort()
        self.up_btn.config(state=tk.NORMAL if self._current_path != "/" else tk.DISABLED)
        self.mount_btn.config(state=tk.NORMAL)
        self.upload_btn.config(state=tk.NORMAL)
        self.download_btn.config(state=tk.NORMAL)
        self.delete_btn.config(state=tk.NORMAL)
        self.rename_btn.config(state=tk.NORMAL)
        self.newdir_btn.config(state=tk.NORMAL)

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
        self.file_ops.set_ops_state(True)

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
        clean_server = self._parse_server(server, 445)[0]
        result = self.smb_service.list_files(clean_server, share, path, username, password)
        self.after(0, lambda: self._display_files(result["data"] if result["success"] else []))

    @staticmethod
    def _parse_server(server_str: str, default_port: int = 21) -> tuple[str, int]:
        host_part = server_str.split("://")[-1]
        host_part = host_part.rsplit("@", 1)[-1]
        parts = host_part.rsplit(":", 1)
        host = parts[0]
        port = int(parts[1]) if len(parts) > 1 else default_port
        return host, port

    def _browse_ftp_thread(self, path: str, username: str, password: str) -> None:
        default_port = 80 if self._current_protocol == "WebDAV" else 21
        server, port = self._parse_server(self._current_server, default_port)
        if self._current_protocol == "WebDAV":
            result = self.dav_client.list_dir(
                "webdav", server, port, username, password, path, encoding=self.encoding_var.get()
            )
        else:
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

        if ftype == "共享":
            self.browse_share(name, "/")
        elif ftype == "文件夹":
            if self._current_share or self._current_server:
                path = self._current_path.rstrip("/") + "/" + name
                self.browse_share(self._current_share, path)
        else:
            self._open_remote_file(name)

    @staticmethod
    def _tmp_dir() -> str:
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "tmp")
        os.makedirs(d, exist_ok=True)
        return d

    def _open_remote_file(self, name: str) -> None:
        proto = self._current_protocol
        if proto == "SMB":
            messagebox.showinfo("提示", "SMB 暂不支持双击打开文件", parent=self)
            return
        remote = self._current_path.rstrip("/") + "/" + name
        import random
        stem, ext = os.path.splitext(name)
        suffix = f"_{random.randint(1000,9999)}{ext}"
        local = os.path.join(self._tmp_dir(), f"{stem}{suffix}")

        server, port = self._parse_server(self._current_server, 80 if proto == "WebDAV" else 21)
        username = self.username_var.get().strip() or "anonymous"
        password = self.password_var.get()
        client = self.dav_client if proto == "WebDAV" else self.ftp_client
        encoding = self.encoding_var.get()
        threading.Thread(
            target=self._open_remote_thread,
            args=(proto, server, port, username, password, remote, local, encoding),
            daemon=True
        ).start()

    def _open_remote_thread(self, proto: str, server: str, port: int,
                            username: str, password: str, remote: str, local: str,
                            encoding: str) -> None:
        client = self.dav_client if proto == "WebDAV" else self.ftp_client
        result = client.download(proto.lower(), server, port, username, password, remote, local, encoding)
        if result["success"]:
            try:
                os.startfile(local)
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("打开失败", str(e), parent=self))
                try: os.remove(local)
                except OSError: pass
                return
            threading.Thread(target=self._cleanup_tmp_file, args=(local,), daemon=True).start()
        else:
            self.after(0, lambda: messagebox.showerror("下载失败", result.get("error", "未知错误"), parent=self))

    @staticmethod
    def _cleanup_tmp_file(tmp: str) -> None:
        import time
        for _ in range(10):
            time.sleep(10)
            try:
                os.remove(tmp)
                return
            except OSError:
                continue

    def go_up(self) -> None:
        if (not self._current_share and not self._current_server) or self._current_path == "/":
            return
        parent = "/".join(self._current_path.rstrip("/").split("/")[:-1]) or "/"
        if not parent.startswith("/"):
            parent = "/" + parent
        self.browse_share(self._current_share, parent)

    # ── 表头排序 ─────────────────────────────────────────────────

    def _on_column_click(self, col: str) -> None:
        if self._sort_state["column"] == col:
            self._sort_state["ascending"] = not self._sort_state["ascending"]
        else:
            self._sort_state["column"] = col
            self._sort_state["ascending"] = True
        self._re_sort()

    def _update_heading_arrows(self) -> None:
        col = self._sort_state["column"]
        asc = self._sort_state["ascending"]
        for c in self._heading_text:
            text = self._heading_text[c]
            if c == col:
                arrow = "↑" if asc else "↓"
                label = "升序" if asc else "降序"
                text = f"{text} ({arrow}{label})"
            self.tree.heading(c, text=text)

    def _re_sort(self) -> None:
        self._update_heading_arrows()
        items = self.tree.get_children()
        if not items:
            return
        col = self._sort_state["column"]
        asc = self._sort_state["ascending"]
        col_index = {"name": 0, "type": 1, "size": 2, "modified": 3}.get(col, 0)

        def sort_key(item):
            values = self.tree.item(item, "values")
            val = values[col_index] if col_index < len(values) else ""
            ftype = values[1] if len(values) > 1 else ""
            is_dir = ftype == "文件夹"
            if col == "type":
                return (0 if is_dir else 1, (values[0] or "").lower())
            if col == "size":
                num = self._parse_size(val) if val else -1
                return (0 if is_dir else 1, num if asc else -num)
            comp = (val or "").lower()
            return (0 if is_dir else 1, comp)

        sorted_items = sorted(items, key=sort_key, reverse=not asc)
        for i, item in enumerate(sorted_items):
            self.tree.move(item, "", i)

    @staticmethod
    def _parse_size(size_str: str) -> float:
        units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4, "PB": 1024**5}
        parts = size_str.split()
        if len(parts) == 2:
            try:
                return float(parts[0]) * units.get(parts[1], 1)
            except (ValueError, KeyError):
                return 0
        try:
            return float(size_str)
        except ValueError:
            return 0

    @staticmethod
    def _format_size(size: float | int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"
