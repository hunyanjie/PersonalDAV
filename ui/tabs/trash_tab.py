import tkinter as tk
from tkinter import ttk, messagebox
from ui.tabs.base_tab import BaseTreeTab
from services.trash_service import TrashService

class TrashTab(BaseTreeTab):
    COLUMNS = ("uuid", "name", "original", "size", "deleted_at")
    HEADINGS = {"uuid": "UUID", "name": "文件名", "original": "原路径", "size": "大小", "deleted_at": "删除时间"}

    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()
        self.refresh()

    def create_widgets(self):
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(toolbar, text="还原选中", command=self.restore_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="永久删除", command=self.delete_permanent).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="清空回收站", command=self.purge_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="刷新", command=self.refresh).pack(side=tk.LEFT, padx=2)

        self.setup_treeview(self, self.restore_selected)

    def refresh(self):
        items = TrashService.list_items()
        def format_size(size_val):
            try:
                size = float(size_val)
                for unit in ["B", "KB", "MB", "GB", "TB"]:
                    if size < 1024:
                        return f"{size:.1f} {unit}"
                    size /= 1024
                return f"{size:.1f} PB"
            except:
                return str(size_val)

        self._all_data = [
            (" ", item["uuid"], item.get("name", ""), item.get("original_path", ""), format_size(item.get("size", 0)), item.get("deleted_at", ""))
            for item in items
        ]
        self._rerender()

    def restore_selected(self):
        sel = self.tree.selection()
        if not sel: return
        for iid in sel:
            uid = self.tree.item(iid, "values")[1]
            TrashService.restore(uid)
        self.refresh()

    def delete_selected(self):
        """Delete key handler —永久删除选中文件。"""
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("提示", "未选中文件", parent=self)
            return
        if not messagebox.askyesno("确认", "永久删除？", parent=self): return
        for iid in sel:
            uid = self.tree.item(iid, "values")[1]
            TrashService.permanent_delete(uid)
        self.refresh()

    def delete_permanent(self):
        sel = self.tree.selection()
        if not sel: return
        if not messagebox.askyesno("确认", "永久删除？", parent=self): return
        for iid in sel:
            uid = self.tree.item(iid, "values")[1]
            TrashService.permanent_delete(uid)
        self.refresh()
        
    def purge_all(self):
        if not messagebox.askyesno("确认", "清空？"): return
        TrashService.clear_all()
        self.refresh()
