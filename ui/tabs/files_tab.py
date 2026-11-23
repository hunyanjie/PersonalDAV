import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os
import shutil
import threading
from datetime import datetime
from services.settings_service import SettingsService
from services.file_mount_service import FileMountService
from utils.logger import logger
from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED
from ui.tabs.trash_tab import TrashTab


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
        self._all_entries: list[dict] = []
        self._search_var = tk.StringVar()
        self._search_var.trace("w", self._on_search_change)
        self.create_widgets()
        event_bus.subscribe(EVENT_SETTINGS_CHANGED, self.refresh)

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

        # 创建子 Notebook
        self.sub_notebook = ttk.Notebook(self)
        self.sub_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        # 1. 文件浏览页面
        self.browse_frame = ttk.Frame(self.sub_notebook)
        self.sub_notebook.add(self.browse_frame, text="文件浏览")

        toolbar = ttk.Frame(self.browse_frame)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        self.up_btn = ttk.Button(toolbar, text="返回上级", command=self.go_up, state=tk.DISABLED)
        self.up_btn.pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=2)

        self.action_btn_frame = ttk.Frame(toolbar)
        self.action_btn_frame.pack(side=tk.LEFT, fill=tk.Y)

        self.upload_btn = ttk.Button(self.action_btn_frame, text="上传", command=self.upload_file)
        self.upload_btn.pack(side=tk.LEFT, padx=2)
        self.download_btn = ttk.Button(self.action_btn_frame, text="下载", command=self.download_selected)
        self.download_btn.pack(side=tk.LEFT, padx=2)
        
        self.main_action_btn = ttk.Button(toolbar, text="删除挂载点", command=self.delete_mount)
        self.main_action_btn.pack(side=tk.LEFT, padx=2)
        
        self.rename_btn = ttk.Button(toolbar, text="重命名挂载点", command=self.rename_mount)
        self.rename_btn.pack(side=tk.LEFT, padx=2)
        
        self.new_action_btn = ttk.Button(toolbar, text="新建挂载点", command=self.add_mount)
        self.new_action_btn.pack(side=tk.LEFT, padx=2)

        self.refresh_btn = ttk.Button(toolbar, text="刷新", command=self.refresh)
        self.refresh_btn.pack(side=tk.LEFT, padx=2)

        self.path_label = ttk.Label(toolbar, text="/")
        self.path_label.pack(side=tk.LEFT, padx=10)

        search_f = ttk.Frame(self.browse_frame)
        search_f.pack(fill=tk.X, padx=5, pady=(0, 5))
        ttk.Label(search_f, text="搜索:").pack(side=tk.LEFT, padx=2)
        self._search_entry = ttk.Entry(search_f, textvariable=self._search_var)
        self._search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(search_f, text="清空", width=5, command=lambda: self._search_var.set("")).pack(side=tk.LEFT, padx=2)

        tree_frame = ttk.Frame(self.browse_frame)
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
        
        # 2. 回收站页面
        self.trash_tab = TrashTab(self.sub_notebook)
        self.sub_notebook.add(self.trash_tab, text="回收站")
        
        self.update_ui_state()

    def update_ui_state(self):
        in_mount = bool(self._virtual_path)
        logger.info(f"UI State Update: in_mount={in_mount}, path='{self._virtual_path}'")
        
        if not in_mount:
            self.upload_btn.config(state=tk.DISABLED)
            self.download_btn.config(state=tk.DISABLED)
            
            self.main_action_btn.config(text="删除挂载点", state=tk.NORMAL)
            self.main_action_btn.configure(command=self.delete_mount)
            
            self.rename_btn.config(text="重命名挂载点", state=tk.NORMAL)
            self.rename_btn.configure(command=self.rename_mount)
            
            self.new_action_btn.config(text="新建挂载点", state=tk.NORMAL)
            self.new_action_btn.configure(command=self.add_mount)
        else:
            self.upload_btn.config(state=tk.NORMAL)
            self.download_btn.config(state=tk.NORMAL)
            
            self.main_action_btn.config(text="删除", state=tk.NORMAL)
            self.main_action_btn.configure(command=self.delete_selected)
            
            self.rename_btn.config(text="重命名", state=tk.NORMAL)
            self.rename_btn.configure(command=self.rename_file)
            
            self.new_action_btn.config(text="新建文件夹", state=tk.NORMAL)
            self.new_action_btn.configure(command=self.new_folder)
            
        # 只刷新布局，不处理其它待处理事件，避免在标签切换回调里重入事件循环。
        self.update_idletasks()

    def refresh(self) -> None:
        mounts = self._mount().get_mounts()
        self.root_path_label.config(text=" | ".join(f"{m['name']}:{m['path']}" for m in mounts) or "无挂载点")
        # 即使是单挂载点自动进入，也要确保 update_ui_state 被正确调用
        if not self._virtual_path and self._mount().is_single_mount and mounts:
            self._enter_mount(mounts[0]["name"])
        else:
            self._browse(self._virtual_path)
        self.update_ui_state()

    def _browse(self, virtual_path: str) -> None:
        self._virtual_path = virtual_path
        self.update_ui_state()
        svc = self._mount()
        if not virtual_path:
            entries = svc.get_root_entries()
            self._current_fs_path = ""
            self._all_entries = entries
            self._display_entries_from_cache()
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
            self._all_entries = entries
            self._display_entries_from_cache()
        except OSError as e:
            messagebox.showerror("错误", f"无法读取目录: {e}", parent=self)
            self._all_entries = []
            self._display_entries_from_cache()

        display = "/" + virtual_path
        self.path_label.config(text=display)
        self.up_btn.config(state=tk.NORMAL)

    def _on_search_change(self, *args) -> None:
        self._display_entries_from_cache()

    def _display_entries_from_cache(self) -> None:
        self._display_entries(self._all_entries, self._virtual_path == "")

    def _display_entries(self, entries: list[dict], is_mount_root: bool = False) -> None:
        self.tree.delete(*self.tree.get_children())
        query = self._search_var.get().lower().strip()
        if query:
            entries = [e for e in entries if query in e.get("name", "").lower()]
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

    def delete_mount(self):
        items = self.tree.selection()
        if not items:
            messagebox.showwarning("提示", "请选择要删除的挂载点", parent=self)
            return
        name = self.tree.item(items[0], "values")[0]
        if messagebox.askyesno("确认", f"确定要删除挂载点 '{name}' 吗？(仅删除挂载配置，不会删除实际磁盘文件)"):
            if self._mount().remove_mount(name):
                self.refresh()
                event_bus.publish(EVENT_SETTINGS_CHANGED)

    def add_mount(self):
        from ui.dialogs.mount_dialog import MountDialog
        dialog = MountDialog(self)
        self.wait_window(dialog)
        if dialog.result:
            try:
                self._mount().add_mount(dialog.result["name"], dialog.result["path"])
                self.refresh()
                event_bus.publish(EVENT_SETTINGS_CHANGED)
            except ValueError as e:
                messagebox.showerror("错误", str(e), parent=self)

    def rename_mount(self):
        items = self.tree.selection()
        if len(items) != 1:
            messagebox.showwarning("提示", "请选择单个挂载点", parent=self)
            return
        old_name = self.tree.item(items[0], "values")[0]
        new_name = simpledialog.askstring("重命名", "新挂载点名称:", initialvalue=old_name, parent=self)
        if not new_name or new_name == old_name: return
        
        m = self._mount().get_mount(old_name)
        try:
            self._mount().update_mount(old_name, new_name, m["path"])
            self.refresh()
            event_bus.publish(EVENT_SETTINGS_CHANGED)
        except Exception as e:
            messagebox.showerror("错误", str(e), parent=self)

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
            
        def get_unique_path(path):
            if not os.path.exists(path): return path
            base, ext = os.path.splitext(path)
            counter = 1
            while os.path.exists(f"{base}({counter}){ext}"):
                counter += 1
            return f"{base}({counter}){ext}"

        def run():
            for src in paths:
                try:
                    filename = os.path.basename(src)
                    dst = os.path.join(self._current_fs_path, filename)
                    
                    if os.path.exists(dst):
                        choice = messagebox.askyesnocancel("文件冲突", f"文件 '{filename}' 已存在。\n点击'是'覆盖，'否'自动重命名，'取消'跳过。")
                        if choice is None: continue # Cancel/Skip
                        elif choice: # Overwrite
                            pass 
                        else: # Rename
                            dst = get_unique_path(dst)
                            
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
            from services.trash_service import TrashService
            for item in items:
                values = self.tree.item(item, "values")
                name = values[0]
                full = self._fs_path_for(name)
                try:
                    # 构造包含挂载点的完整虚拟路径
                    full_virtual_path = "/" + self._virtual_path.rstrip("/") + "/" + name
                    TrashService.delete(full, full_virtual_path)
                except Exception as e:
                    self.after(0, lambda n=name: messagebox.showerror("删除失败", f"{n}: {e}", parent=self))
                    return
            self.after(0, lambda: [self._browse(self._virtual_path), self.trash_tab.refresh()])
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
        if not self._virtual_path:
            menu.add_command(label="重命名挂载点", command=self.rename_mount)
            menu.add_command(label="删除挂载点", command=self.delete_mount)
        else:
            menu.add_command(label="下载", command=self.download_selected)
            menu.add_command(label="重命名", command=self.rename_file)
            menu.add_command(label="删除", command=self.delete_selected)
            menu.add_separator()
            menu.add_command(label="上传到此目录", command=self.upload_file)
            menu.add_command(label="新建文件夹", command=self.new_folder)
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
