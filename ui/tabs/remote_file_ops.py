import tkinter as tk
from tkinter import ttk, messagebox
from ui.widgets.toast import Toast, filedialog, simpledialog
import threading
import os
from typing import Any
from utils.logger import logger


class RemoteFileOps:
    """远程文件操作管理器 — 从 RemoteTab 提取"""

    def __init__(self, tab):
        self.tab = tab

    # ── 辅助方法 ──

    def is_ftp_connected(self):
        return self.tab._is_connected and self.tab._current_protocol != "SMB"

    def get_selected_name(self):
        sel = self.tab.tree.selection()
        if not sel:
            return None
        return self.tab.tree.item(sel[0], "values")[0]

    def get_selected_path(self):
        name = self.get_selected_name()
        if not name:
            return None
        return self.tab._current_path.rstrip("/") + "/" + name

    def set_ops_state(self, disabled):
        state = tk.DISABLED if disabled else tk.NORMAL
        for btn in (self.tab.upload_btn, self.tab.download_btn,
                     self.tab.delete_btn, self.tab.rename_btn, self.tab.newdir_btn):
            btn.config(state=state)

    # ── 右键菜单 ──

    def show_tree_context_menu(self, event):
        tree = self.tab.tree
        item = tree.identify_row(event.y)
        sel = tree.selection()
        if item and item not in sel:
            tree.selection_set(item)
        sel = tree.selection()
        has_sel = bool(sel)
        sel_names = [tree.item(i, "values")[0] for i in sel if tree.item(i, "values")]
        sel_types = [tree.item(i, "values")[1] for i in sel if len(tree.item(i, "values")) > 1]
        has_file = any(t == "文件" for t in sel_types)
        single_mode = len(sel) == 1

        menu = tk.Menu(tree, tearoff=0)
        if self.is_ftp_connected():
            if has_file:
                menu.add_command(label="下载" + (f" ({len(sel)})" if len(sel) > 1 else ""),
                                 command=self.download_selected)
            elif has_sel:
                menu.add_command(label="下载所选", state=tk.DISABLED)
            menu.add_separator()
            menu.add_command(label="删除所选" + (f" ({len(sel)})" if len(sel) > 1 else ""),
                             state=tk.NORMAL if has_sel else tk.DISABLED,
                             command=self.delete_selected)
            if single_mode and has_sel:
                menu.add_command(label="重命名", command=self.rename_file)
            else:
                menu.add_command(label="重命名", state=tk.DISABLED)
            menu.add_separator()
            if single_mode and has_sel:
                menu.add_command(label="复制路径",
                                 command=lambda n=sel_names[0]: self._copy_path(n))
        menu.add_command(label="上传到此目录", command=self.upload_file)
        menu.tk_popup(event.x_root, event.y_root)
        menu.grab_release()

    def _copy_path(self, name):
        path = self.tab._current_path.rstrip("/") + "/" + name
        self.tab.clipboard_clear()
        self.tab.clipboard_append(path)

    # ── 上传 ──

    def upload_file(self):
        if not self.is_ftp_connected():
            Toast.warning(self.tab, "仅 FTP/FTPS/SFTP 协议支持上传")
            return
        file_path = filedialog.askopenfilename(title="选择要上传的文件")
        if not file_path:
            return
        remote_name = os.path.basename(file_path)
        remote_path = self.tab._current_path.rstrip("/") + "/" + remote_name
        self.set_ops_state(True)
        threading.Thread(target=self._upload_thread, args=(file_path, remote_path), daemon=True).start()

    def _upload_thread(self, local, remote):
        server, port = self.tab._parse_server(self.tab._current_server)
        username = self.tab.username_var.get().strip() or "anonymous"
        password = self.tab.password_var.get()
        result = self.tab.ftp_client.upload(
            self.tab._current_protocol.lower(), server, port, username, password, local, remote,
            encoding=self.tab.encoding_var.get())
        self.tab.after(0, lambda: self._op_done(result, "上传"))

    # ── 下载 ──

    def download_selected(self):
        if not self.is_ftp_connected():
            Toast.warning(self.tab, "仅 FTP/FTPS/SFTP 协议支持下载")
            return
        sel = self.tab.tree.selection()
        if not sel:
            return
        targets = []
        for item in sel:
            values = self.tab.tree.item(item, "values")
            if len(values) >= 2 and values[1] == "文件":
                remote = self.tab._current_path.rstrip("/") + "/" + values[0]
                targets.append((values[0], remote))
        if not targets:
            Toast.warning(self.tab, "没有选中可下载的文件")
            return
        if len(targets) == 1:
            name, remote = targets[0]
            save = filedialog.asksaveasfilename(title="保存到", initialfile=name, parent=self.tab)
            if not save:
                return
            files_to_dl = [(save, remote)]
        else:
            save_dir = filedialog.askdirectory(title="选择保存目录", parent=self.tab)
            if not save_dir:
                return
            files_to_dl = [(os.path.join(save_dir, name), remote) for name, remote in targets]
        self.set_ops_state(True)
        threading.Thread(target=self._download_all_thread, args=(files_to_dl,), daemon=True).start()

    def _download_all_thread(self, files):
        server, port = self.tab._parse_server(self.tab._current_server)
        username = self.tab.username_var.get().strip() or "anonymous"
        password = self.tab.password_var.get()
        encoding = self.tab.encoding_var.get()
        proto = self.tab._current_protocol.lower()
        ok = 0
        for local, remote in files:
            r = self.tab.ftp_client.download(proto, server, port, username, password, remote, local, encoding)
            if r["success"]:
                ok += 1
        self.tab.after(0, lambda: self._multi_op_done(ok, len(files), "下载"))

    # ── 删除 ──

    def delete_selected(self):
        if not self.is_ftp_connected():
            Toast.warning(self.tab, "仅 FTP/FTPS/SFTP 协议支持删除")
            return
        sel = self.tab.tree.selection()
        if not sel:
            return
        paths = []
        for item in sel:
            values = self.tab.tree.item(item, "values")
            if not values:
                continue
            paths.append(self.tab._current_path.rstrip("/") + "/" + values[0])
        label = "\n".join(paths[:5])
        if len(paths) > 5:
            label += f"\n... 等 {len(paths)} 项"
        if not messagebox.askyesno("确认删除", f"确定要删除以下 {len(paths)} 项吗？\n{label}", parent=self.tab):
            return
        self.set_ops_state(True)
        threading.Thread(target=self._delete_all_thread, args=(paths,), daemon=True).start()

    def _delete_all_thread(self, paths):
        server, port = self.tab._parse_server(self.tab._current_server)
        username = self.tab.username_var.get().strip() or "anonymous"
        password = self.tab.password_var.get()
        encoding = self.tab.encoding_var.get()
        proto = self.tab._current_protocol.lower()
        ok = sum(1 for p in paths
                 if self.tab.ftp_client.delete(proto, server, port, username, password, p, encoding)["success"])
        self.tab.after(0, lambda: self._multi_op_done(ok, len(paths), "删除"))

    # ── 重命名 ──

    def rename_file(self):
        old_path = self.get_selected_path()
        if not old_path:
            return
        if not self.is_ftp_connected():
            Toast.warning(self.tab, "仅 FTP/FTPS/SFTP 协议支持重命名")
            return
        name = self.get_selected_name()
        new_name = simpledialog.askstring("重命名", "新名称:", initialvalue=name, parent=self.tab)
        if not new_name:
            return
        new_path = self.tab._current_path.rstrip("/") + "/" + new_name
        self.set_ops_state(True)
        threading.Thread(target=self._rename_thread, args=(old_path, new_path), daemon=True).start()

    def _rename_thread(self, old, new):
        server, port = self.tab._parse_server(self.tab._current_server)
        username = self.tab.username_var.get().strip() or "anonymous"
        password = self.tab.password_var.get()
        result = self.tab.ftp_client.rename(
            self.tab._current_protocol.lower(), server, port, username, password, old, new,
            encoding=self.tab.encoding_var.get())
        self.tab.after(0, lambda: self._op_done(result, "重命名"))

    # ── 新建文件夹 ──

    def new_folder(self):
        if not self.is_ftp_connected():
            Toast.warning(self.tab, "仅 FTP/FTPS/SFTP 协议支持新建文件夹")
            return
        dir_name = simpledialog.askstring("新建文件夹", "文件夹名称:", parent=self.tab)
        if not dir_name:
            return
        new_path = self.tab._current_path.rstrip("/") + "/" + dir_name
        self.set_ops_state(True)
        threading.Thread(target=self._mkdir_thread, args=(new_path,), daemon=True).start()

    def _mkdir_thread(self, path):
        server, port = self.tab._parse_server(self.tab._current_server)
        username = self.tab.username_var.get().strip() or "anonymous"
        password = self.tab.password_var.get()
        result = self.tab.ftp_client.mkdir(
            self.tab._current_protocol.lower(), server, port, username, password, path,
            encoding=self.tab.encoding_var.get())
        self.tab.after(0, lambda: self._op_done(result, "新建文件夹"))

    # ── 操作结果 ──

    def _op_done(self, result, op_name):
        if result["success"]:
            logger.info(f"远程文件 {op_name} 成功")
            self.tab.browse_share(self.tab._current_share, self.tab._current_path)
        else:
            self.set_ops_state(False)
            messagebox.showerror(f"{op_name}失败", result.get("error", "未知错误"), parent=self.tab)

    def _multi_op_done(self, ok, total, op_name):
        logger.info(f"远程文件 {op_name}: {ok}/{total} 成功")
        if ok == total:
            self.tab.browse_share(self.tab._current_share, self.tab._current_path)
        else:
            self.set_ops_state(False)
            Toast.warning(self.tab, f"{ok}/{total} 项{op_name}成功")
