import tkinter as tk
from tkinter import ttk
from utils.logger import logger

class RightClickMenu:
    """通用的右键菜单封装 - 支持上下文感知"""
    def __init__(self, widget, widget_type="normal"):
        self.widget = widget
        self.widget_type = widget_type
        self.menu = tk.Menu(widget, tearoff=0)
        self.create_base_menu()

        # 绑定右键事件
        if isinstance(widget, (tk.Entry, tk.Text, ttk.Treeview)):
            widget.bind('<Button-3>', self.show_menu)
        else:
            logger.error(f"右键菜单注册失败: 类型 {type(widget)} 暂不支持")

    def create_base_menu(self):
        """创建基础菜单项"""
        self.menu.delete(0, tk.END)
        if isinstance(self.widget, ttk.Treeview):
            # Treeview 上下文菜单
            self.menu.add_command(label="编辑选中", command=self._handle_edit)
            self.menu.add_command(label="删除选中", command=self._handle_delete)
            self.menu.add_separator()
            self.menu.add_command(label="导出选中", command=self._handle_export)
            self.menu.add_separator()
            self.menu.add_command(label="查看原始数据", command=self._handle_show_raw)
            self.menu.add_separator()
            self.menu.add_command(label="全选 (Ctrl+A)", command=self.select_all)
        else:
            # 标准编辑菜单
            self.menu.add_command(label="撤销 (Ctrl+Z)", command=self.undo)
            self.menu.add_command(label="重做 (Ctrl+Y)", command=self.redo)
            self.menu.add_separator()
            self.menu.add_command(label="剪切 (Ctrl+X)", command=self.cut)
            self.menu.add_command(label="复制 (Ctrl+C)", command=self.copy)
            self.menu.add_command(label="粘贴 (Ctrl+V)", command=self.paste)
            self.menu.add_separator()
            self.menu.add_command(label="删除 (Del)", command=self.delete)
            self.menu.add_command(label="全选 (Ctrl+A)", command=self.select_all)

    def _handle_edit(self):
        """处理 Treeview 编辑选中"""
        self.widget.event_generate("<<TreeviewEdit>>")

    def _handle_delete(self):
        """处理 Treeview 删除选中"""
        self.widget.event_generate("<<TreeviewDelete>>")

    def _handle_export(self):
        """处理 Treeview 导出选中"""
        self.widget.event_generate("<<TreeviewExport>>")

    def _handle_show_raw(self):
        """处理 Treeview 查看原始数据"""
        self.widget.event_generate("<<TreeviewShowRaw>>")

    def show_menu(self, event):
        """显示右键菜单"""
        if isinstance(self.widget, ttk.Treeview):
            # 如果右键点击时没有选中项，自动选中当前行
            item = self.widget.identify_row(event.y)
            if item and item not in self.widget.selection():
                self.widget.selection_set(item)
        
        self.update_menu_state()
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def update_menu_state(self):
        """更新菜单项状态"""
        if isinstance(self.widget, ttk.Treeview):
            has_sel = bool(self.widget.selection())
            state = tk.NORMAL if has_sel else tk.DISABLED
            try:
                self.menu.entryconfigure("编辑选中", state=state)
                self.menu.entryconfigure("删除选中", state=state)
                self.menu.entryconfigure("导出选中", state=state)
                self.menu.entryconfigure("查看原始数据", state=state)
            except: pass
            return

        # 标准控件状态逻辑
        if isinstance(self.widget, tk.Text) and self.widget_type == "text":
            # 由于 Tkinter 无法在不改变内容的情况下探测是否可撤销，
            # 默认保持开启，由 undo() 方法内部处理具体逻辑。
            self.menu.entryconfigure("撤销 (Ctrl+Z)", state=tk.NORMAL)
            self.menu.entryconfigure("重做 (Ctrl+Y)", state=tk.NORMAL)
        else:
            self.menu.entryconfigure("撤销 (Ctrl+Z)", state=tk.DISABLED)
            self.menu.entryconfigure("重做 (Ctrl+Y)", state=tk.DISABLED)

        # 剪切/复制/删除状态（需要选中文本）
        try:
            has_selection = bool(self.widget.selection_get())
        except tk.TclError:
            has_selection = False

        self.menu.entryconfigure("剪切 (Ctrl+X)", state=tk.NORMAL if (
                has_selection and (self.widget_type == "normal" or self.widget_type == "text")) else tk.DISABLED)
        self.menu.entryconfigure("复制 (Ctrl+C)", state=tk.NORMAL if has_selection else tk.DISABLED)
        self.menu.entryconfigure("删除 (Del)", state=tk.NORMAL if (
                has_selection and (self.widget_type == "normal" or self.widget_type == "text")) else tk.DISABLED)

        # 粘贴状态（需要剪贴板有内容）
        try:
            clipboard_content = self.widget.clipboard_get()
            self.menu.entryconfigure("粘贴 (Ctrl+V)", state=tk.NORMAL if (clipboard_content and (
                    self.widget_type == "normal" or self.widget_type == 'text')) else tk.DISABLED)
        except tk.TclError:
            self.menu.entryconfigure("粘贴 (Ctrl+V)", state=tk.DISABLED)

    def undo(self):
        try: self.widget.edit_undo()
        except: self.widget.event_generate("<<Undo>>")

    def redo(self):
        try: self.widget.edit_redo()
        except: self.widget.event_generate("<<Redo>>")
    def cut(self): self.widget.event_generate("<<Cut>>")
    def copy(self): self.widget.event_generate("<<Copy>>")
    def paste(self): self.widget.event_generate("<<Paste>>")
    def delete(self): self.widget.event_generate("<Delete>")
    def select_all(self): self.widget.event_generate("<<SelectAll>>")
