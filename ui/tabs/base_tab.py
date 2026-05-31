"""Treeview 通用操作基类 - 遵循 DRY 原则"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import os
import threading
import uuid
import re
from ui.widgets.treeview_scroller import TreeviewScroller


class BaseTreeTab(ttk.Frame):
    """Treeview 标签页基类 - 封装通用操作逻辑"""

    COLUMNS = []  # 子类覆盖
    HEADINGS = {}  # 子类覆盖: {'col1': '标题1', ...}
    DEFAULT_SORT_COL = ''    # 默认排序列（子类可覆盖）
    DEFAULT_SORT_REV = False  # 默认排序方向

    def __init__(self, parent):
        super().__init__(parent)
        self.tree = None
        self._drag_start = None
        self._drag_item = None
        self._dragging = False
        self._last_selected = None
        self._sort_col = ''
        self._sort_rev = False
        self._user_sort = False   # True = 用户主动排序, False = 使用默认排序
        self._all_data = []       # 存储完整数据用于过滤
        self.app_root = None      # 子类应设为 Tk 根窗口
        self._import_type = ''    # 'contacts' 或 'events'，子类设置

    def setup_search_ui(self, parent):
        """创建统一的搜索栏"""
        search_f = ttk.Frame(parent)
        search_f.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_f, text="搜索:").pack(side=tk.LEFT, padx=2)
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_f, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        self.search_var.trace("w", self._on_search_change)
        
        ttk.Button(search_f, text="清空", width=5, 
                   command=lambda: self.search_var.set("")).pack(side=tk.LEFT, padx=2)
        return search_f

    def _on_search_change(self, *args):
        """搜索框内容变更回调"""
        query = self.search_var.get().lower().strip()
        self.apply_filter(query)

    def apply_filter(self, query):
        """执行过滤显示"""
        # 子类需覆盖此方法以实现具体的过滤逻辑
        pass

    def setup_treeview(self, list_frame, on_edit_callback):
        """初始化 Treeview"""
        self.tree = ttk.Treeview(list_frame, columns=self.COLUMNS, show="headings", selectmode="extended")

        for col in self.COLUMNS:
            self.tree.heading(col, text=self.HEADINGS.get(col, col),
                            command=lambda c=col: self.sort_tree(c))
            self.tree.column(col, width=self.get_column_width(col))

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # 事件绑定
        self.tree.bind('<ButtonPress-1>', self._on_click)
        self.tree.bind('<B1-Motion>', self._on_drag)
        self.tree.bind('<ButtonRelease-1>', self._on_release)
        self.tree.bind('<Double-1>', lambda e: on_edit_callback())
        self.tree.bind("<<TreeviewEdit>>", lambda e: on_edit_callback())
        self.tree.bind("<<TreeviewExport>>", lambda e: self.export_selected())
        self.tree.bind("<<TreeviewShowRaw>>", lambda e: self.show_raw())
        self.tree.bind("<<TreeviewDelete>>", lambda e: self._on_delete())
        self.tree.bind("<Control-a>", self.select_all)
        self.tree.bind("<Delete>", lambda e: self.delete_selected())
        
        # 保存编辑和删除回调
        self._edit_callback = on_edit_callback

    def get_column_width(self, col):
        """获取列宽 - 子类可覆盖"""
        widths = {'selected': 30}
        return widths.get(col, 100)

    def _on_click(self, event):
        """处理点击事件"""
        region = self.tree.identify("region", event.x, event.y)
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        self._drag_start = (event.x, event.y)
        self._drag_item = item
        self._dragging = False

        if region == "heading" and column == "#1":
            self.toggle_all_selection()
            return "break"
        if region == "heading":
            return

        # Shift 多选
        if event.state & 0x0001:
            if not item:
                return "break"
            all_items = list(self.tree.get_children())
            start_idx = all_items.index(self._last_selected or all_items[0])
            end_idx = all_items.index(item)
            selected = all_items[min(start_idx, end_idx):max(start_idx, end_idx)+1]
            self.tree.selection_set(selected)
            self._update_checkboxes(selected)
            return "break"

        ctrl = bool(event.state & 0x0004)

        # 复选框列点击
        if column == "#1" and item:
            if ctrl:
                if item in self.tree.selection():
                    self.tree.selection_remove(item)
                    self._set_item_checkbox(item, " ")
                else:
                    self.tree.selection_add(item)
                    self._set_item_checkbox(item, "✓")
            else:
                self.tree.selection_set([item])
                self._set_item_checkbox(item, "✓")
            self._last_selected = item
            return "break"

        # 普通列点击
        if item:
            if ctrl:
                if item in self.tree.selection():
                    self.tree.selection_remove(item)
                    self._set_item_checkbox(item, " ")
                else:
                    self.tree.selection_add(item)
                    self._set_item_checkbox(item, "✓")
            else:
                self.tree.selection_set([item])
                self._update_checkboxes([item])
            self._last_selected = item
            return "break"

    def _on_drag(self, event):
        """处理拖拽事件"""
        self._dragging = True
        TreeviewScroller.handle_drag_scroll(self.tree, event)

        if not self._drag_item:
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return

        all_items = list(self.tree.get_children())
        start_idx = self.tree.index(self._drag_item)
        curr_idx = self.tree.index(item)
        selected = all_items[min(start_idx, curr_idx):max(start_idx, curr_idx)+1]
        self.tree.selection_set(selected)
        self._update_checkboxes(selected)

    def _on_release(self, event):
        """处理释放事件"""
        self._drag_start = None
        self._drag_item = None
        self._dragging = False

    # def _on_motion(self, event):
    #     """处理鼠标移动事件（备用）"""
    #     TreeviewScroller.handle_drag_scroll(self.tree, event)

    def select_all(self, event=None):
        """全选"""
        items = self.tree.get_children()
        self.tree.selection_set(items)
        self._update_checkboxes(items)
        return "break"

    def delete_selected(self):
        """执行删除逻辑的外部入口"""
        self._on_delete()

    def toggle_all_selection(self):
        """切换全选状态"""
        all_items = self.tree.get_children()
        if not all_items:
            return

        all_sel = all(i in self.tree.selection() for i in all_items)
        new_sel = [] if all_sel else all_items
        self.tree.selection_set(new_sel)
        self._update_checkboxes([] if all_sel else all_items)

    def _update_checkboxes(self, selected):
        """更新复选框状态 - 子类可覆盖"""
        for i in self.tree.get_children():
            state = "✓" if i in selected else " "
            self._set_item_checkbox(i, state)

    def _set_item_checkbox(self, item, state):
        """设置单行复选框"""
        vals = list(self.tree.item(item, 'values'))
        vals[0] = state
        self.tree.item(item, values=vals)

    def sort_tree(self, col):
        """三态排序: asc -> desc -> 取消(默认排序)"""
        if col in ('selected', '#0', ''):
            return

        if self._user_sort and self._sort_col == col:
            if self._sort_rev:
                self._restore_default()
            else:
                self._sort_rev = True
                self._sort_tree_exec()
        else:
            self._sort_col = col
            self._sort_rev = False
            self._user_sort = True
            self._sort_tree_exec()

    def _sort_tree_exec(self):
        """执行当前排序"""
        rev = self._sort_rev
        col = self._sort_col
        items = self.tree.get_children('')
        if not items:
            return
        data = [(self._sort_key(col, self.tree.set(k, col)), k) for k in items]
        data.sort(key=lambda x: x[0], reverse=rev)
        for idx, (_, k) in enumerate(data):
            self.tree.move(k, '', idx)
        self._update_sort_arrows()

    def _sort_key(self, col, value):
        """排序键 - 时间列用 datetime 解析，其他列用字符串"""
        if col in ('start', 'end', 'created_at', 'updated_at'):
            try: return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
            except: return datetime.min
        return (value or '').lower()

    def _restore_default(self):
        """取消用户排序，恢复默认排序"""
        self._user_sort = False
        query = getattr(self, 'search_var', None) and self.search_var.get().lower().strip() or ""
        self.apply_filter(query)
        if self.DEFAULT_SORT_COL:
            self._sort_col = self.DEFAULT_SORT_COL
            self._sort_rev = self.DEFAULT_SORT_REV
            self._sort_tree_exec()
        else:
            self._sort_col = ''
            self._update_sort_arrows()

    def _after_refresh(self):
        """数据刷新后恢复排序状态 - 子类 refresh_* 末尾调用"""
        if self._user_sort and self._sort_col:
            self._sort_tree_exec()
        elif self.DEFAULT_SORT_COL:
            self._sort_col = self.DEFAULT_SORT_COL
            self._sort_rev = self.DEFAULT_SORT_REV
            self._sort_tree_exec()
        else:
            self._sort_col = ''
            self._update_sort_arrows()

    def _update_sort_arrows(self):
        """更新表头排序指示"""
        for col in self.COLUMNS:
            text = self.HEADINGS.get(col, col)
            if col == self._sort_col:
                arrow = '↑' if not self._sort_rev else '↓'
                label = '升序' if not self._sort_rev else '降序'
                text = f"{text} ({arrow}{label})"
            self.tree.heading(col, text=text)

    def refresh_selection(self):
        """刷新选择状态 - 子类可覆盖"""
        pass

    # ── 导入框架（子类只需实现 _import_add_item / _import_refresh_list / _parse_data_to_items） ──

    def _import_add_item(self, raw, force=False, publish=True):
        """子类覆盖：调用服务添加单项"""
        raise NotImplementedError

    def _import_refresh_list(self):
        """子类覆盖：刷新列表"""
        raise NotImplementedError

    def _parse_data_to_items(self, data):
        """子类覆盖：解析原始数据为 item 列表"""
        raise NotImplementedError

    def _import_selected(self, items, source):
        """将预览对话框中选择的 items 导入（带进度窗口）"""
        from ui.widgets.progress_window import ProgressWindow
        win = ProgressWindow(self, f"正在从 {source} 导入...")
        def run():
            total = len(items)
            stats = {'new': 0, 'updated': 0, 'unchanged': 0, 'failed': 0}
            for idx, it in enumerate(items):
                action = it.get('_action', 'new')
                if action == 'new_uid':
                    new_uid = str(uuid.uuid4())
                    raw = re.sub(r'^UID:.*$', f'UID:{new_uid}', it['raw'], count=1, flags=re.MULTILINE | re.IGNORECASE)
                    _, op = self._import_add_item(raw, publish=False)
                    if op == "inserted":
                        stats['new'] += 1
                        msg = f"新增(重置UID): {it['title']}"
                    else:
                        stats['failed'] += 1
                        msg = f"失败(重置UID): {it['title']}"
                else:
                    _, op = self._import_add_item(it['raw'], force=True, publish=False)
                    if op == "inserted":
                        stats['new'] += 1
                        msg = f"新增: {it['title']}"
                    elif op == "updated":
                        stats['updated'] += 1
                        msg = f"更新: {it['title']}"
                    elif op == "unchanged":
                        stats['unchanged'] += 1
                        msg = None
                    else:
                        stats['failed'] += 1
                        msg = f"失败: {it['title']}"
                pct = (idx + 1) / total * 100
                s = dict(stats)
                win.after(0, lambda m=msg, p=pct, st=s: (
                    win.log(m) if m else None,
                    win.update_progress(p),
                    win.stat_vars['new'].set(st['new']),
                    win.stat_vars['updated'].set(st['updated']),
                    win.stat_vars['unchanged'].set(st['unchanged']),
                    win.stat_vars['failed'].set(st['failed'])))
            win.after(0, lambda: (
                win.update_status("导入完成"),
                win.set_finished(),
                self._import_refresh_list()))
        threading.Thread(target=run, daemon=True).start()

    def _import_file(self):
        is_contact = self._import_type == 'contacts'
        path = filedialog.askopenfilename(
            filetypes=[("联系人文件", "*.vcf *.vcs"), ("日历文件", "*.ics *.vcs"), ("所有文件", "*.*")] if is_contact
                      else [("日历文件", "*.ics *.vcs"), ("联系人文件", "*.vcf *.vcs"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()
            items = self._parse_data_to_items(data)
            if not items:
                label = "vCard" if is_contact else "iCalendar"
                messagebox.showinfo("提示", f"未识别到有效 {label} 数据", parent=self)
                return
            from ui.dialogs.import_preview_dialog import ImportPreviewDialog
            dialog = ImportPreviewDialog(self, self._import_type,
                on_import_callback=lambda sel: self._import_selected(sel, os.path.basename(path)),
                items=items)
            self.wait_window(dialog)
        except Exception as e:
            messagebox.showerror("错误", f"读取文件失败: {e}", parent=self)

    def _import_url(self):
        is_contact = self._import_type == 'contacts'
        label = "VCF" if is_contact else "ICS"
        from tkinter import simpledialog
        url = simpledialog.askstring("URL 导入", f"请输入 {label} 文件的 URL:", parent=self)
        if not url:
            return
        from ui.widgets.progress_window import ProgressWindow
        import requests
        win = ProgressWindow(self, "正在从 URL 下载...")
        def run():
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                data = resp.text
                win.after(0, win.destroy)
                items = self._parse_data_to_items(data)
                if not items:
                    wn = win
                    win.after(0, lambda: messagebox.showinfo("提示", f"未识别到有效 {label} 数据", parent=self))
                    return
                win.after(0, lambda: self._open_import_preview(items, "URL"))
            except Exception as e:
                win.after(0, lambda: [win.destroy(), messagebox.showerror("错误", f"下载失败: {e}", parent=self)])
        threading.Thread(target=run, daemon=True).start()

    def _import_clipboard(self):
        try:
            data = self.app_root.clipboard_get()
            if not data.strip():
                messagebox.showinfo("提示", "剪切板为空", parent=self); return
            items = self._parse_data_to_items(data)
            if not items:
                label = "vCard" if self._import_type == 'contacts' else "iCalendar"
                messagebox.showinfo("提示", f"未识别到有效 {label} 数据", parent=self)
                return
            self._open_import_preview(items, "剪切板")
        except:
            messagebox.showinfo("提示", "无法读取剪切板内容", parent=self)

    def show_text_import(self):
        is_contact = self._import_type == 'contacts'
        label = "vCard" if is_contact else "iCalendar"
        from ui.dialogs.text_import_dialog import TextImportDialog
        dialog = TextImportDialog(self.app_root, f"粘贴 {label} 文本导入")
        self.wait_window(dialog)
        data = dialog.result
        if not data:
            return
        items = self._parse_data_to_items(data)
        if not items:
            messagebox.showinfo("提示", f"未识别到有效 {label} 数据", parent=self)
            return
        self._open_import_preview(items, "文本粘贴")

    def show_import_preview(self):
        from ui.dialogs.import_preview_dialog import ImportPreviewDialog
        dialog = ImportPreviewDialog(self, self._import_type)
        self.wait_window(dialog)

    def _open_import_preview(self, items, source):
        from ui.dialogs.import_preview_dialog import ImportPreviewDialog
        dialog = ImportPreviewDialog(self, self._import_type,
            on_import_callback=lambda sel: self._import_selected(sel, source),
            items=items)
        self.wait_window(dialog)

    def show_raw(self):
        """查看原始数据 - 子类可覆盖"""
        pass
    
    def _on_delete(self):
        """处理删除事件 - 子类应覆盖此方法"""
        pass
    
    def export_selected(self):
        """导出选中项 - 子类应覆盖此方法"""
        pass
