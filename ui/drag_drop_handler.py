import os
from tkinter import messagebox
from tkinterdnd2 import DND_FILES
from utils.logger import logger


class DragDropHandler:
    """全局文件拖拽处理器 — 从 DAVServerApp 提取"""

    def __init__(self, root, notebook, contacts_tab, calendar_tab):
        self.root = root
        self.notebook = notebook
        self.contacts_tab = contacts_tab
        self.calendar_tab = calendar_tab

    def setup(self):
        try:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self._handle_drop)
        except Exception as e:
            logger.warning(f"无法注册全局拖拽: {e}")

    def _handle_drop(self, event):
        files = self._parse_drop_data(event.data)
        if not files:
            return

        tab_text = self.notebook.tab(self.notebook.select(), "text")
        if tab_text not in ("联系人", "日历"):
            messagebox.showinfo("提示", "请切换到联系人或日历标签页进行导入")
            return

        tab = self.contacts_tab if tab_text == "联系人" else self.calendar_tab
        all_data = []
        for f in files:
            try:
                with open(f, 'r', encoding='utf-8') as fh:
                    all_data.append(fh.read())
            except Exception as e:
                messagebox.showerror("错误", f"读取文件失败 {f}: {e}")
                return

        data = "\n".join(all_data)
        items = tab._parse_data_to_items(data)
        if not items:
            label = "vCard" if tab_text == "联系人" else "iCalendar"
            messagebox.showinfo("提示", f"未识别到有效 {label} 数据", parent=tab)
            return

        from ui.dialogs.import_preview_dialog import ImportPreviewDialog
        dialog = ImportPreviewDialog(tab, tab._import_type,
            on_import_callback=lambda sel: tab._import_selected(sel, "拖拽文件"),
            items=items)
        self.root.wait_window(dialog)

    def _parse_drop_data(self, raw):
        files = []
        if isinstance(raw, (list, tuple)):
            files = [f for f in raw if os.path.exists(f)]
        else:
            if raw.startswith('{') and raw.endswith('}'):
                for path in raw[1:-1].split('} {'):
                    if os.path.exists(path):
                        files.append(path)
            elif os.path.exists(raw):
                files.append(raw)
            else:
                for path in raw.split():
                    if os.path.exists(path):
                        files.append(path)
        return files
