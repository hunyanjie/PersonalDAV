import tkinter as tk
from tkinter import ttk, messagebox
from services.smb_service import SMBService
from database.db_manager import Database
from utils.crypto import encrypt, decrypt
from utils.window_utils import center_window


class RemoteMountManager:
    """远程连接/挂载管理器 — 从 RemoteTab 提取"""

    def __init__(self, tab):
        self.tab = tab
        self.smb_service = SMBService()

    def mount_current(self):
        if not self.tab._current_server:
            return
        server_raw = self.tab.server_var.get().strip()
        port_raw = int(self.tab.port_var.get().strip() or "21")
        username = self.tab.username_var.get().strip() or "anonymous"
        password = self.tab.password_var.get()
        encoding = self.tab.encoding_var.get()

        if self.tab._current_protocol == "SMB":
            mount_point = f"/mnt/smb/{self.tab._current_share or 'root'}"
            server = self.tab._parse_server(self.tab._current_server, 445)[0]
            result = self.smb_service.mount(server, self.tab._current_share, mount_point, username, password)
            if not result["success"]:
                messagebox.showerror("失败", result.get("error", "未知错误"), parent=self.tab)
                return
        else:
            import datetime
            label = f"{self.tab._current_protocol}://{server_raw}:{port_raw}"
            conn_info = (self.tab._current_protocol, server_raw, port_raw, username, encrypt(password), encoding, label, datetime.datetime.now().isoformat())
            Database().execute(
                "INSERT INTO remote_connections (protocol, server, port, username, password, encoding, label, created_at) VALUES (?,?,?,?,?,?,?,?)",
                conn_info)

        messagebox.showinfo("成功", "已保存连接", parent=self.tab)
        self.refresh()

    def refresh(self):
        tree = self.tab.mounts_tree
        tree.delete(*tree.get_children())
        result = self.smb_service.get_mounted_shares()
        if result["success"]:
            for m in result["data"]:
                tree.insert("", tk.END, values=("SMB", m["server"], m["share"], m["mount_point"]))
        for row in Database().query(
                "SELECT protocol, server, port, username, label FROM remote_connections ORDER BY id DESC"):
            proto, srv, port, user, label = row
            tree.insert("", tk.END, values=(proto, f"{srv}:{port}", user, label))

    def on_double_click(self):
        tree = self.tab.mounts_tree
        item = tree.selection()
        if not item:
            return
        values = tree.item(item[0], "values")
        proto = values[0]
        if proto == "SMB":
            return
        server_port = values[1]
        username = values[2]
        if ":" in server_port:
            server, port_str = server_port.rsplit(":", 1)
        else:
            server, port_str = server_port, "21"
        self.tab.protocol_var.set(proto)
        self.tab.server_var.set(server)
        self.tab.port_var.set(port_str)
        self.tab.username_var.set(username if username != "anonymous" else "")
        self.tab.password_var.set("")
        self.tab.connect()

    def show_context_menu(self, event):
        tree = self.tab.mounts_tree
        item = tree.identify_row(event.y)
        sel = tree.selection()
        if item and item not in sel:
            tree.selection_set(item)
        sel = tree.selection()
        has_sel = bool(sel)
        is_single = len(sel) == 1

        menu = tk.Menu(tree, tearoff=0)
        has_ftp_entry = False
        if is_single and has_sel:
            values = tree.item(sel[0], "values")
            if values and values[0] != "SMB":
                has_ftp_entry = True
                menu.add_command(label="连接", command=lambda: self._connect_entry(sel[0]))
                menu.add_command(label="编辑", command=lambda: self._edit_entry(sel[0]))
            elif values and values[0] == "SMB":
                menu.add_command(label="连接", state=tk.DISABLED)
                menu.add_command(label="编辑", state=tk.DISABLED)
        else:
            menu.add_command(label="连接", state=tk.DISABLED)
            menu.add_command(label="编辑", state=tk.DISABLED)
        if has_sel:
            menu.add_command(label="删除" + (f" ({len(sel)})" if len(sel) > 1 else ""),
                             command=self._delete_selected)
        else:
            menu.add_command(label="删除", state=tk.DISABLED)
        menu.tk_popup(event.x_root, event.y_root)
        menu.grab_release()

    def _connect_entry(self, item):
        tree = self.tab.mounts_tree
        values = tree.item(item, "values")
        if not values or values[0] == "SMB":
            return
        proto, server_port, username = values[0], values[1], values[2]
        if ":" in server_port:
            server, port_str = server_port.rsplit(":", 1)
        else:
            server, port_str = server_port, "21"
        self.tab.protocol_var.set(proto)
        self.tab.server_var.set(server)
        self.tab.port_var.set(port_str)
        self.tab.username_var.set(username if username != "anonymous" else "")
        self.tab.password_var.set("")
        self.tab.connect()

    def _edit_entry(self, item):
        tree = self.tab.mounts_tree
        values = tree.item(item, "values")
        if not values or values[0] == "SMB":
            return
        proto, server_port, username = values[0], values[1], values[2]
        server = server_port.rsplit(":", 1)[0] if ":" in server_port else server_port
        rows = Database().query(
            "SELECT id, protocol, server, port, username, password, encoding, label "
            "FROM remote_connections WHERE protocol=? AND server=? AND username=? ORDER BY id DESC LIMIT 1",
            (proto, server, username))
        if not rows:
            messagebox.showerror("错误", "未找到连接记录", parent=self.tab)
            return
        row = rows[0]
        self._show_editor(row[0], row[1], row[2], row[3], row[4], decrypt(row[5]), row[6])

    def _show_editor(self, conn_id, protocol, server, port, username, password, encoding):
        dialog = tk.Toplevel(self.tab)
        dialog.title(f"编辑连接 - {protocol}://{server}")
        dialog.transient(self.tab)
        dialog.grab_set()
        dialog.resizable(False, False)
        center_window(dialog, self.tab)

        f = ttk.Frame(dialog, padding=15)
        f.pack(fill=tk.BOTH, expand=True)

        ttk.Label(f, text="协议:").grid(row=0, column=0, sticky="w", pady=3)
        proto_var = tk.StringVar(value=protocol)
        ttk.Combobox(f, textvariable=proto_var, values=["FTP", "FTPS", "SFTP"],
                     state="readonly", width=8).grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(f, text="服务器:").grid(row=1, column=0, sticky="w", pady=3)
        srv_var = tk.StringVar(value=server)
        ttk.Entry(f, textvariable=srv_var, width=25).grid(row=1, column=1, padx=5)

        ttk.Label(f, text="端口:").grid(row=2, column=0, sticky="w", pady=3)
        port_var = tk.StringVar(value=str(port))
        ttk.Entry(f, textvariable=port_var, width=8).grid(row=2, column=1, sticky="w", padx=5)

        ttk.Label(f, text="用户名:").grid(row=3, column=0, sticky="w", pady=3)
        user_var = tk.StringVar(value=username if username != "anonymous" else "")
        ttk.Entry(f, textvariable=user_var, width=20).grid(row=3, column=1, padx=5)

        ttk.Label(f, text="密码:").grid(row=4, column=0, sticky="w", pady=3)
        pw_var = tk.StringVar(value=password)
        ttk.Entry(f, textvariable=pw_var, width=20, show="*").grid(row=4, column=1, padx=5)

        ttk.Label(f, text="编码:").grid(row=5, column=0, sticky="w", pady=3)
        enc_var = tk.StringVar(value=encoding)
        ttk.Combobox(f, textvariable=enc_var, values=self.tab.ENCODINGS,
                     state="readonly", width=10).grid(row=5, column=1, sticky="w", padx=5)

        def save_edit():
            Database().execute(
                "UPDATE remote_connections SET protocol=?, server=?, port=?, username=?, password=?, encoding=? WHERE id=?",
                (proto_var.get(), srv_var.get(), int(port_var.get()),
                 user_var.get().strip() or "anonymous",
                 encrypt(pw_var.get()), enc_var.get(), conn_id))
            self.refresh()
            dialog.destroy()

        btn_f = ttk.Frame(f)
        btn_f.grid(row=6, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(btn_f, text="保存", command=save_edit).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def _delete_selected(self):
        tree = self.tab.mounts_tree
        sel = tree.selection()
        if not sel:
            return
        if not messagebox.askyesno("确认删除", f"确定要删除 {len(sel)} 条记录吗？", parent=self.tab):
            return
        for item in sel:
            values = tree.item(item, "values")
            if not values:
                continue
            if values[0] == "SMB":
                mount_point = values[3] if len(values) > 3 else ""
                if mount_point:
                    self.smb_service.unmount(mount_point)
            else:
                proto, server_port, username = values[0], values[1], values[2]
                server = server_port.rsplit(":", 1)[0] if ":" in server_port else server_port
                Database().execute(
                    "DELETE FROM remote_connections WHERE protocol=? AND server=? AND username=?",
                    (proto, server, username))
        self.refresh()
