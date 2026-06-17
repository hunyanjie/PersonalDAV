import tkinter as tk
from tkinter import ttk, messagebox
from ui.tabs.base_tab import BaseTreeTab
from services.trash_service import TrashService

class TrashTab(BaseTreeTab):
    COLUMNS = ("name", "original", "deleted_at")
    HEADINGS = {"name": "文件名", "original": "原路径", "deleted_at": "删除时间"}
    
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
        self._all_data = [
            (" ", item["uuid"], item.get("name", ""), item.get("original_path", ""), item.get("deleted_at", ""))
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

    def delete_permanent(self):
        sel = self.tree.selection()
        if not sel: return
        if not messagebox.askyesno("确认", "永久删除？"): return
        for iid in sel:
            uid = self.tree.item(iid, "values")[1]
            TrashService.permanent_delete(uid)
        self.refresh()
        
    def purge_all(self):
        if not messagebox.askyesno("确认", "清空？"): return
        TrashService.clear_all()
        self.refresh()
