import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os
import shutil
import threading
from datetime import datetime
from services.settings_service import SettingsService
from services.file_mount_service import FileMountService
from utils.logger import logger


class FilesTab(ttk.Frame):
    settings_service: SettingsService

    def __init__(self, parent: ttk.Notebook, settings_service: SettingsService) -> None:
        super().__init__(parent)
        self.settings_service = settings_service
        self._virtual_path = ""       # ""=root, "mount", "mount/subdir"
        self._current_fs_path = ""    # resolved filesystem path
        self._sort_state: dict[str, bool | str] = {"column": "name", "ascending": True}
        self._heading_text = {"name": "名称", "type": "类型", "size": "大小", "modified": "修改时间"}
        self._mount_svc = None
        self.create_widgets()

    @staticmethod
    def _tmp_dir() -> str:
        d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "data", "tmp")
        os.makedirs(d, exist_ok=True)
        return d

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

    def _mount(self) -> FileMountService:
        if self._mount_svc is None:
            self._mount_svc = FileMountService()
        return self._mount_svc

    def create_widgets(self) -> None:
        top_frame = ttk.LabelFrame(self, text="本地 DAV 文件管理")
        top_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        path_f = ttk.Frame(top_frame)
        path_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(path_f, text="根目录:").pack(side=tk.LEFT, padx=2)
        self.root_path_label = ttk.Label(path_f, text="", foreground="gray")
        self.root_path_label.pack(side=tk.LEFT, padx=2)

        browse_frame = ttk.LabelFrame(self, text="文件浏览")
        browse_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 5))

        toolbar = ttk.Frame(browse_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        self.up_btn = ttk.Button(toolbar, text="返回上级", command=self.go_up, state=tk.DISABLED)
        self.up_btn.pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=2)

        self.upload_btn = ttk.Button(toolbar, text="上传", command=self.upload_file)
        self.upload_btn.pack(side=tk.LEFT, padx=2)
        self.download_btn = ttk.Button(toolbar, text="下载", command=self.download_selected)
        self.download_btn.pack(side=tk.LEFT, padx=2)
        self.delete_btn = ttk.Button(toolbar, text="删除", command=self.delete_selected)
        self.delete_btn.pack(side=tk.LEFT, padx=2)
        self.rename_btn = ttk.Button(toolbar, text="重命名", command=self.rename_file)
        self.rename_btn.pack(side=tk.LEFT, padx=2)
        self.newdir_btn = ttk.Button(toolbar, text="新建文件夹", command=self.new_folder)
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
        self.tree.bind("<Button-3>", self._show_context_menu)

    def refresh(self) -> None:
        mounts = self._mount().get_mounts()
        self.root_path_label.config(text=" | ".join(f"{m['name']}:{m['path']}" for m in mounts) or "无挂载点")
        if not self._virtual_path and self._mount().is_single_mount:
            self._enter_mount(self._mount().get_mounts()[0]["name"])
        else:
            self._browse(self._virtual_path)

    def _browse(self, virtual_path: str) -> None:
        self._virtual_path = virtual_path
        svc = self._mount()
        if not virtual_path:
            entries = svc.get_root_entries()
            self._current_fs_path = ""
            self._display_entries(entries, is_mount_root=True)
            self.path_label.config(text="/")
            self.up_btn.config(state=tk.DISABLED)
            return

        parts = virtual_path.split("/", 1)
        mount_name = parts[0]
        rel_path = parts[1] if len(parts) > 1 else ""

        m = svc.get_mount(mount_name)
        if not m:
            messagebox.showerror("错误", f"挂载点 '{mount_name}' 不存在", parent=self)
            return

        dir_path = os.path.normpath(os.path.join(m["path"], rel_path))
        if not dir_path.startswith(os.path.normpath(m["path"])):
            messagebox.showerror("错误", "路径越权", parent=self)
            return

        self._current_fs_path = dir_path
        try:
            entries = []
            for name in sorted(os.listdir(dir_path)):
                full = os.path.join(dir_path, name)
                try:
                    st = os.stat(full)
                    is_dir = os.path.isdir(full)
                    entries.append({
                        "name": name,
                        "is_dir": is_dir,
                        "size": st.st_size if not is_dir else 0,
                        "modified": datetime.fromtimestamp(st.st_mtime),
                    })
                except OSError:
                    entries.append({
                        "name": name,
                        "is_dir": False,
                        "size": 0,
                        "modified": datetime.now(),
                    })
            self._display_entries(entries, is_mount_root=False)
        except OSError as e:
            messagebox.showerror("错误", f"无法读取目录: {e}", parent=self)
            self._display_entries([], is_mount_root=False)

        display = "/" + virtual_path
        self.path_label.config(text=display)
        self.up_btn.config(state=tk.NORMAL)

    def _display_entries(self, entries: list[dict], is_mount_root: bool = False) -> None:
        self.tree.delete(*self.tree.get_children())
        for e in sorted(entries, key=lambda f: (0 if f.get("is_dir", False) else 1, f.get("name", "").lower())):
            if e.get("is_mount"):
                ftype = "文件夹"
                size_str = ""
                modified_str = ""
            else:
                ftype = "文件夹" if e.get("is_dir", False) else (os.path.splitext(e["name"])[1].lstrip(".").upper() or "文件")
                size_str = "" if e.get("is_dir", False) else self._format_size(e["size"])
                mod = e.get("modified")
                modified_str = mod.strftime("%Y-%m-%d %H:%M") if isinstance(mod, datetime) else str(mod or "")
            self.tree.insert("", tk.END, values=(e["name"], ftype, size_str, modified_str))
        self._re_sort()

    def _enter_mount(self, mount_name: str) -> None:
        self._browse(mount_name)

    def on_double_click(self, event: tk.Event) -> None:
        item = self.tree.selection()
        if not item:
            return
        values = self.tree.item(item[0], "values")
        name = values[0]
        ftype = values[1]

        if ftype != "文件夹":
            full = os.path.join(self._current_fs_path, name)
            self._open_local_file(full, name)
            return

        if not self._virtual_path:
            self._enter_mount(name)
        else:
            new_vp = self._virtual_path + "/" + name
            self._browse(new_vp)

    def _open_local_file(self, full_path: str, name: str) -> None:
        import random
        stem, ext = os.path.splitext(name)
        suffix = f"_{random.randint(1000,9999)}{ext}"
        tmp = os.path.join(self._tmp_dir(), f"{stem}{suffix}")
        try:
            shutil.copy2(full_path, tmp)
        except Exception as e:
            messagebox.showerror("错误", f"复制文件失败: {e}", parent=self)
            return
        try:
            os.startfile(tmp)
        except Exception as e:
            try: os.remove(tmp)
            except OSError: pass
            messagebox.showerror("错误", f"打开文件失败: {e}", parent=self)
            return
        threading.Thread(target=self._cleanup_tmp_file, args=(tmp,), daemon=True).start()

    def go_up(self) -> None:
        if not self._virtual_path:
            return
        parent = "/".join(self._virtual_path.rstrip("/").split("/")[:-1])
        self._browse(parent)

    def _fs_path_for(self, name: str) -> str:
        return os.path.join(self._current_fs_path, name)

    def upload_file(self) -> None:
        if not self._virtual_path:
            messagebox.showwarning("提示", "请先进入挂载点", parent=self)
            return
        paths = filedialog.askopenfilenames(parent=self, title="选择要上传的文件")
        if not paths:
            return
        def run():
            for src in paths:
                try:
                    dst = os.path.join(self._current_fs_path, os.path.basename(src))
                    shutil.copy2(src, dst)
                except Exception as e:
                    self.after(0, lambda s=src: messagebox.showerror("上传失败", f"{s}: {e}", parent=self))
                    return
            self.after(0, lambda: self._browse(self._virtual_path))
        threading.Thread(target=run, daemon=True).start()

    def download_selected(self) -> None:
        items = self.tree.selection()
        if not items:
            messagebox.showwarning("提示", "请先选择文件", parent=self)
            return
        target = filedialog.askdirectory(parent=self, title="选择下载目录")
        if not target:
            return
        def run():
            for item in items:
                values = self.tree.item(item, "values")
                name = values[0]
                ftype = values[1]
                src = self._fs_path_for(name)
                dst = os.path.join(target, name)
                try:
                    if ftype == "文件夹":
                        shutil.copytree(src, dst, dirs_exist_ok=True)
                    else:
                        shutil.copy2(src, dst)
                except Exception as e:
                    self.after(0, lambda n=name: messagebox.showerror("下载失败", f"{n}: {e}", parent=self))
                    return
            self.after(0, lambda: messagebox.showinfo("完成", "下载完成", parent=self))
        threading.Thread(target=run, daemon=True).start()

    def delete_selected(self) -> None:
        if not self._virtual_path:
            return
        items = self.tree.selection()
        if not items:
            messagebox.showwarning("提示", "请先选择要删除的文件", parent=self)
            return
        names = [self.tree.item(i, "values")[0] for i in items]
        if not messagebox.askyesno("确认删除", f"确定要删除选中的 {len(names)} 项吗？\n" + "\n".join(names[:10]), parent=self):
            return
        def run():
            for item in items:
                values = self.tree.item(item, "values")
                name = values[0]
                ftype = values[1]
                full = self._fs_path_for(name)
                try:
                    if ftype == "文件夹":
                        shutil.rmtree(full)
                    else:
                        os.remove(full)
                except Exception as e:
                    self.after(0, lambda n=name: messagebox.showerror("删除失败", f"{n}: {e}", parent=self))
                    return
            self.after(0, lambda: self._browse(self._virtual_path))
        threading.Thread(target=run, daemon=True).start()

    def rename_file(self) -> None:
        if not self._virtual_path:
            return
        items = self.tree.selection()
        if len(items) != 1:
            messagebox.showwarning("提示", "请选择单个文件或文件夹", parent=self)
            return
        old_name = self.tree.item(items[0], "values")[0]
        new_name = simpledialog.askstring("重命名", "新名称:", initialvalue=old_name, parent=self)
        if not new_name or new_name == old_name:
            return
        src = self._fs_path_for(old_name)
        dst = self._fs_path_for(new_name)
        try:
            os.rename(src, dst)
            self._browse(self._virtual_path)
        except Exception as e:
            messagebox.showerror("重命名失败", str(e), parent=self)

    def new_folder(self) -> None:
        if not self._virtual_path:
            return
        name = simpledialog.askstring("新建文件夹", "文件夹名称:", parent=self)
        if not name:
            return
        full = self._fs_path_for(name)
        try:
            os.makedirs(full, exist_ok=True)
            self._browse(self._virtual_path)
        except Exception as e:
            messagebox.showerror("错误", f"创建失败: {e}", parent=self)

    def _show_context_menu(self, event: tk.Event) -> None:
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="下载", command=self.download_selected)
        menu.add_command(label="重命名", command=self.rename_file)
        menu.add_command(label="删除", command=self.delete_selected)
        menu.add_separator()
        menu.add_command(label="上传到此目录", command=self.upload_file)
        menu.add_command(label="新建文件夹", command=self.new_folder)
        if self._virtual_path:
            menu.add_separator()
            menu.add_command(label="返回上级目录", command=self.go_up)
        menu.post(event.x_root, event.y_root)

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
                text = f"{text} ({arrow}{'升序' if asc else '降序'})"
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
    def _format_size(size: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} PB"

    @staticmethod
    def _parse_size(size_str: str) -> float:
        units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
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
