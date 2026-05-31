import tkinter as tk
from tkinter import ttk
from utils.logger import logger


class RightClickMenu:
    """通用的右键菜单封装 - 支持上下文感知
    通过 actions 参数自定义菜单项，actions 列表中的 None 表示分隔线。
    """

    ACTION_MAP = {
        "undo": ("撤销 (Ctrl+Z)", "undo"),
        "redo": ("重做 (Ctrl+Y)", "redo"),
        "cut": ("剪切 (Ctrl+X)", "cut"),
        "copy": ("复制 (Ctrl+C)", "copy"),
        "paste": ("粘贴 (Ctrl+V)", "paste"),
        "delete": ("删除 (Del)", "delete"),
        "select_all": ("全选 (Ctrl+A)", "select_all"),
        "edit": ("编辑选中", "_handle_edit"),
        "delete_sel": ("删除选中", "_handle_delete"),
        "export": ("导出选中", "_handle_export"),
        "show_raw": ("查看原始数据", "_handle_show_raw"),
    }

    DEFAULT_ACTIONS = {
        "treeview": ["edit", "delete_sel", None, "export", None, "show_raw", None, "select_all"],
        "text": ["undo", "redo", None, "cut", "copy", "paste", None, "delete", "select_all"],
        "entry": ["cut", "copy", "paste", None, "delete", "select_all"],
    }

    def __init__(self, widget, widget_type="normal", actions=None):
        self.widget = widget
        self.widget_type = widget_type
        self.menu = tk.Menu(widget, tearoff=0)

        if actions is not None:
            self.actions = list(actions)
        elif isinstance(widget, ttk.Treeview):
            self.actions = list(self.DEFAULT_ACTIONS["treeview"])
        elif widget_type in ("text", "log"):
            self.actions = list(self.DEFAULT_ACTIONS["text"])
        else:
            self.actions = list(self.DEFAULT_ACTIONS["entry"])

        self._build_menu()
        self._bind_events()

    def _bind_events(self):
        if isinstance(self.widget, (tk.Entry, tk.Text, ttk.Treeview)):
            self.widget.bind('<Button-3>', self.show_menu)
        else:
            logger.error(f"右键菜单注册失败: 类型 {type(self.widget)} 暂不支持")

    def _build_menu(self):
        self.menu.delete(0, tk.END)
        for action_id in self.actions:
            if action_id is None:
                self.menu.add_separator()
                continue
            label, method_name = self.ACTION_MAP.get(action_id, (action_id, None))
            if method_name is None:
                self.menu.add_command(label=label, command=lambda: None)
            else:
                method = getattr(self, method_name)
                self.menu.add_command(label=label, command=method)

    def _handle_edit(self):
        self.widget.event_generate("<<TreeviewEdit>>")

    def _handle_delete(self):
        self.widget.event_generate("<<TreeviewDelete>>")

    def _handle_export(self):
        self.widget.event_generate("<<TreeviewExport>>")

    def _handle_show_raw(self):
        self.widget.event_generate("<<TreeviewShowRaw>>")

    def show_menu(self, event):
        if isinstance(self.widget, ttk.Treeview):
            item = self.widget.identify_row(event.y)
            if item and item not in self.widget.selection():
                self.widget.selection_set(item)

        self.update_menu_state()
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def update_menu_state(self):
        for action_id in self.actions:
            if action_id is None:
                continue
            label, _ = self.ACTION_MAP.get(action_id, (action_id, None))

            if action_id in ("edit", "delete_sel", "export", "show_raw"):
                has_sel = bool(self.widget.selection())
                try:
                    self.menu.entryconfigure(label, state=tk.NORMAL if has_sel else tk.DISABLED)
                except tk.TclError:
                    pass
            elif action_id == "select_all":
                pass
            elif action_id in ("cut", "copy", "delete"):
                try:
                    has_selection = bool(self.widget.selection_get())
                except tk.TclError:
                    has_selection = False
                try:
                    self.menu.entryconfigure(label, state=tk.NORMAL if has_selection else tk.DISABLED)
                except tk.TclError:
                    pass
            elif action_id == "paste":
                try:
                    has_clip = bool(self.widget.clipboard_get())
                except tk.TclError:
                    has_clip = False
                try:
                    self.menu.entryconfigure(label, state=tk.NORMAL if has_clip else tk.DISABLED)
                except tk.TclError:
                    pass
            elif action_id in ("undo", "redo"):
                try:
                    self.menu.entryconfigure(label, state=tk.NORMAL if self.widget_type == "text" else tk.DISABLED)
                except tk.TclError:
                    pass

    def undo(self):
        try:
            self.widget.edit_undo()
        except:
            self.widget.event_generate("<<Undo>>")

    def redo(self):
        try:
            self.widget.edit_redo()
        except:
            self.widget.event_generate("<<Redo>>")

    def cut(self): self.widget.event_generate("<<Cut>>")
    def copy(self): self.widget.event_generate("<<Copy>>")
    def paste(self): self.widget.event_generate("<<Paste>>")
    def delete(self): self.widget.event_generate("<Delete>")
    def select_all(self): self.widget.event_generate("<<SelectAll>>")
