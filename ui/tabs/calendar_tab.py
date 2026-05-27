import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ui.dialogs.event_dialog import EventDialog
from ui.dialogs.webdav_import_dialog import WebDAVImportDialog
from ui.widgets.right_click_menu import RightClickMenu
from ui.tabs.base_tab import BaseTreeTab
from tkinterdnd2 import DND_FILES
from datetime import datetime

from utils.event_bus import event_bus, EVENT_EVENTS_CHANGED
from services.import_service import TextImportManager, FileSource, UrlSource, ClipboardSource


class CalendarTab(BaseTreeTab):
    """日历管理标签页"""
    COLUMNS = ("selected", "uid", "summary", "start", "end")
    HEADINGS = {
        "selected": "✓",
        "uid": "ID",
        "summary": "事件",
        "start": "开始时间",
        "end": "结束时间"
    }

    def __init__(self, parent, event_service, settings_service, app_root):
        self.db = event_service
        self.settings = settings_service
        self.app_root = app_root
        self.import_manager = TextImportManager(event_service)

        super().__init__(parent)

        self.create_widgets()
        self.setup_dnd()
        self.refresh_events()

        # 订阅数据变更事件
        event_bus.subscribe(EVENT_EVENTS_CHANGED, self.refresh_events)

    def get_column_width(self, col):
        widths = {"selected": 30, "uid": 150, "summary": 300, "start": 200, "end": 200}
        return widths.get(col, 100)

    def create_widgets(self):
        # 列表框架
        list_frame = ttk.LabelFrame(self, text="日历事件列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 操作提示
        hint_label = ttk.Label(list_frame, text="操作提示: 1) 点击复选框选择/取消 2) 表头复选框全选 3) 鼠标拖拽多选 4) 双击行编辑", foreground="blue")
        hint_label.pack(fill=tk.X, padx=5, pady=5)

        # 初始化 Treeview
        self.setup_treeview(list_frame, self.edit_event)

        # 右键菜单
        RightClickMenu(self.tree)

        # 按钮栏
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="添加事件", command=self.add_event).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="编辑事件", command=self.edit_event).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除事件", command=self.delete_event).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="查看原始数据", command=self.show_raw).pack(side=tk.LEFT, padx=2)

        # 导入菜单
        import_btn = ttk.Menubutton(btn_frame, text="导入数据")
        import_menu = tk.Menu(import_btn, tearoff=0)
        import_menu.add_command(label="从文件导入...", command=lambda: self.import_manager.perform_import(FileSource([("iCalendar", "*.ics")])))
        import_menu.add_command(label="从 URL 导入...", command=lambda: self.import_manager.perform_import(UrlSource()))
        import_menu.add_command(label="从剪切板导入", command=lambda: self.import_manager.perform_import(ClipboardSource(self.app_root)))
        import_menu.add_command(label="粘贴文本导入...", command=self.show_text_import)
        import_menu.add_command(label="WebDAV 导入...", command=self.import_webdav)
        import_btn.config(menu=import_menu)
        import_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(btn_frame, text="导出选中", command=self.export_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="刷新列表", command=self.refresh_events).pack(side=tk.RIGHT, padx=10)

    def setup_dnd(self):
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        files = self.tk.splitlist(event.data)
        for f in files:
            if f.lower().endswith('.ics'):
                with open(f, 'r', encoding='utf-8') as file:
                    self.db.add_event(file.read())
        self.refresh_events()

    def refresh_events(self):
        selected_uids = {self.tree.item(i)['values'][1] for i in self.tree.selection() if self.tree.exists(i)}
        for item in self.tree.get_children(): self.tree.delete(item)
        for event in self.db.get_events_list():
            uid = event[0]
            sel = "✓" if uid in selected_uids else " "
            # 解码事件名称
            summary = event[1]
            if summary:
                from utils.encoding_helper import decode_ical_value
                summary = decode_ical_value(summary)
            item_id = self.tree.insert("", tk.END, values=(sel, uid, summary, event[2], event[3]))
            if sel == "✓": self.tree.selection_add(item_id)

    def sort_tree(self, col):
        """排序树形列表 - 时间列特殊处理"""
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = False

        data = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]

        # 对时间列做特殊处理
        if col in ('start', 'end'):
            def try_parse(dt_str):
                try:
                    return datetime.fromisoformat(dt_str)
                except Exception:
                    return datetime.min
            data.sort(key=lambda x: try_parse(x[0]), reverse=self._sort_rev)
        else:
            data.sort(reverse=self._sort_rev)

        for idx, (_, k) in enumerate(data):
            self.tree.move(k, '', idx)

    def add_event(self):
        dialog = EventDialog(self.app_root, db=self.settings)
        if dialog.result:
            self.db.add_event(dialog.get_raw_ical())
            self.refresh_events()

    def edit_event(self):
        sel = self.tree.selection()
        if not sel: return
        uid = self.tree.item(sel[0])['values'][1]
        data = self.db.get_event(uid)
        if data:
            init = {'uid': uid, 'ical': data}
            dialog = EventDialog(self.app_root, initial=init, db=self.settings)
            if dialog.result:
                self.db.add_event(dialog.get_raw_ical())
                self.refresh_events()

    def delete_event(self):
        sel = self.tree.selection()
        if not sel: return
        if messagebox.askyesno("确认", f"确定删除选中的 {len(sel)} 个事件吗？"):
            for i in sel: self.db.delete_event(self.tree.item(i)['values'][1])
            self.refresh_events()
    
    def _on_delete(self):
        """处理删除事件（来自右键菜单或Delete键）"""
        self.delete_event()

    def show_raw(self):
        sel = self.tree.selection()
        if not sel: return
        uid = self.tree.item(sel[0])['values'][1]
        data = self.db.get_event(uid)
        if data:
            win = tk.Toplevel(self); win.title("原始数据")
            txt = tk.Text(win); txt.pack(fill=tk.BOTH, expand=True)
            txt.insert(tk.END, data); txt.config(state=tk.DISABLED)

    def import_webdav(self):
        dialog = WebDAVImportDialog(self, "从 WebDAV 导入日历", self.db.add_event)
        self.wait_window(dialog)

    def show_text_import(self):
        from ui.dialogs.text_import_dialog import TextImportDialog
        dialog = TextImportDialog(self.app_root, "粘贴 iCalendar 文本导入", self.db.add_event)
        self.wait_window(dialog)

    def export_selected(self):
        sel = self.tree.selection()
        if not sel: return
        uids = [self.tree.item(i)['values'][1] for i in sel]
        events = self.db.get_selected_ical_events(uids)

        # 单选时预填文件名
        initial = ""
        if len(sel) == 1:
            summary = self.tree.item(sel[0])['values'][2]  # 事件标题列
            if summary:
                summary = str(summary)
                import re
                summary = re.sub(r'[<>:"/\\|?*]', '_', summary)
                initial = summary

        path = filedialog.asksaveasfilename(
            defaultextension=".ics",
            filetypes=[("iCalendar", "*.ics"), ("所有文件", "*.*")],
            initialfile=initial
        )
        if path:
            if not path.endswith('.ics'):
                path += '.ics'
            data = self.db.generate_calendar_wrapper(events)
            with open(path, 'w', encoding='utf-8') as f: f.write(data)
            messagebox.showinfo("成功", f"成功导出 {len(events)} 个事件")
