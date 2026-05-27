import tkinter as tk
from tkinter import ttk
from ui.widgets.right_click_menu import RightClickMenu

class TextImportDialog(tk.Toplevel):
    """文本粘贴导入对话框 - 1:1 还原带撤销功能的编辑器"""
    def __init__(self, parent, title, on_import_callback):
        super().__init__(parent)
        self.title(title)
        self.geometry("600x500")
        self.transient(parent)
        self.grab_set()
        self.on_import_callback = on_import_callback
        self.result = None

        self.create_widgets()

    def create_widgets(self):
        f = ttk.Frame(self); f.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(f, text="请在下方粘贴 vCard (VCF) 或 iCalendar (ICS) 纯文本数据:", foreground="blue").pack(anchor="w", pady=5)

        self.text_area = tk.Text(f, undo=True, wrap=tk.NONE)
        self.text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        RightClickMenu(self.text_area, "text")

        sb_y = ttk.Scrollbar(f, orient=tk.VERTICAL, command=self.text_area.yview)
        sb_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.text_area.config(yscrollcommand=sb_y.set)

        sb_x = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.text_area.xview)
        self.text_area.config(xscrollcommand=sb_x.set)

        btn_f = ttk.Frame(self); btn_f.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_f, text="开始导入", command=self.ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_f, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_f, text="清空", command=lambda: self.text_area.delete("1.0", tk.END)).pack(side=tk.LEFT)

    def ok(self):
        data = self.text_area.get("1.0", "end-1c").strip()
        if data:
            self.on_import_callback(data)
        self.destroy()

def show_about(parent):
    """关于对话框"""
    from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_AUTHOR, SOFTWARE_DESCRIPTION
    about_text = f"""{SOFTWARE_NAME} v{SOFTWARE_VERSION}

{SOFTWARE_DESCRIPTION}

作者: {SOFTWARE_AUTHOR}

这是一个私人 CardDAV/CalDAV 服务程序，可以管理联系人和日历事件。

功能特点:
- 本地数据库存储
- 支持 WebDAV 协议
- 支持导入/导出 vCard 和 iCalendar 格式
- 提供图形用户界面
- 支持拖拽导入

(c) hunyanjie 2024-2025"""
    from tkinter import messagebox
    messagebox.showinfo("关于", about_text, parent=parent)
