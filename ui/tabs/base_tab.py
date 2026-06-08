"""Treeview 通用操作基类 — 原生 Treeview + 滚动。"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import os
import threading
import uuid
import re
from ui.widgets.treeview_scroller import TreeviewScroller


class BaseTreeTab(ttk.Frame):
    """Treeview 标签页基类 — 封装通用操作逻辑。"""

    COLUMNS = []          # 子类覆盖
    HEADINGS = {}         # 子类覆盖: {'col1': '标题1', ...}
    DEFAULT_SORT_COL = ''     # 默认排序列（子类可覆盖）
    DEFAULT_SORT_REV = False  # 默认排序方向
    BATCH_SIZE = 200      # 批量插入每批条数

    def __init__(self, parent):
        super().__init__(parent)
        self.tree = None
        self.vscroll = None
        self.hscroll = None
        self._drag_start = None
        self._drag_item = None
        self._dragging = False
        self._last_selected = None
        self._sort_col = ''
        self._sort_rev = False
        self._user_sort = False
        self._all_data = []       # 全量数据列表（已过滤）
        self._selected_uids = set()  # 跨页记住选中状态
        self._insert_pending = False  # 批量插入进行中
        self._uid_to_item = {}    # uid -> tree item id
        self._drag_lo = None      # 拖拽最小行索引
        self._drag_hi = None      # 拖拽最大行索引
        self.app_root = None
        self._import_type = ''

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
        """初始化标准 Treeview。"""
        self.tree = ttk.Treeview(list_frame, columns=['selected'] + list(self.COLUMNS),
                                 show='headings', selectmode='extended')
        self.tree.heading('selected', text='✓')
        self.tree.column('selected', width=30, anchor=tk.CENTER)

        for col in self.COLUMNS:
            width = self.get_column_width(col)
            self.tree.heading(col, text=self.HEADINGS.get(col, col),
                            command=lambda c=col: self.sort_tree(c))
            self.tree.column(col, width=width)

        # 滚动条 — 原生连接
        self.vscroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.vscroll.set)
        self.hscroll = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(xscrollcommand=self.hscroll.set)

        self.vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

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
        self.tree.bind("<MouseWheel>", self._on_mousewheel)

        self._edit_callback = on_edit_callback

    def get_column_width(self, col):
        """获取列宽 - 子类可覆盖"""
        widths = {'selected': 30}
        return widths.get(col, 100)

    def _on_mousewheel(self, event):
        """鼠标滚轮滚动。"""
        self.tree.yview_scroll(-int(event.delta / 120), 'units')

    # ── 大批量数据分批插入 ──

    def _batch_insert(self, start=0):
        """分批插入 _all_data 到 Treeview，避免 UI 卡顿。"""
        self._insert_pending = True
        end = min(start + self.BATCH_SIZE, len(self._all_data))
        for i in range(start, end):
            uid = self._all_data[i][1]
            vals = list(self._all_data[i])
            vals[0] = "✓" if uid in self._selected_uids else " "
            item_id = self.tree.insert("", tk.END, values=vals)
            self._uid_to_item[uid] = item_id
        if end < len(self._all_data):
            self.after(1, lambda: self._batch_insert(end))
        else:
            self._insert_pending = False
            self._sync_checkboxes()

    def _rerender(self):
        """用当前 _all_data 重建视图。"""
        if self._insert_pending:
            return
        self._uid_to_item.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        if self._all_data:
            self._batch_insert(0)
        else:
            self._sync_checkboxes()

    def _after_refresh(self):
        """数据刷新后恢复排序状态 — 子类 refresh_* 末尾调用。"""
        if self._user_sort and self._sort_col:
            self._sort_tree_exec()
        elif self.DEFAULT_SORT_COL:
            self._sort_col = self.DEFAULT_SORT_COL
            self._sort_rev = self.DEFAULT_SORT_REV
            self._sort_tree_exec()
        else:
            self._sort_col = ''
            self._rerender()
            self._update_sort_arrows()

    def _on_click(self, event):
        """处理点击事件。"""
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
            visible = self.tree.get_children()
            if not visible:
                return "break"
            old_sel = self._selected_uids.copy()
            start_idx = visible.index(self._last_selected or visible[0])
            end_idx = visible.index(item)
            selected = visible[min(start_idx, end_idx):max(start_idx, end_idx)+1]
            self._selected_uids = {self._uid_of(i) for i in selected}
            self.tree.selection_set(selected)
            self._sync_checkboxes(old_sel ^ self._selected_uids)
            return "break"

        ctrl = bool(event.state & 0x0004)
        uid = self._uid_of(item) if item else None
        old_sel = self._selected_uids.copy()

        # 复选框列点击
        if column == "#1" and item:
            if ctrl:
                if item in self.tree.selection():
                    self.tree.selection_remove(item)
                    self._selected_uids.discard(uid)
                else:
                    self.tree.selection_add(item)
                    self._selected_uids.add(uid)
            else:
                self.tree.selection_set([item])
                self._selected_uids = {uid} if uid else set()
            self._last_selected = item
            self._sync_checkboxes(old_sel ^ self._selected_uids)
            return "break"

        # 普通列点击
        if item:
            if ctrl:
                if item in self.tree.selection():
                    self.tree.selection_remove(item)
                    self._selected_uids.discard(uid)
                else:
                    self.tree.selection_add(item)
                    self._selected_uids.add(uid)
            else:
                self.tree.selection_set([item])
                self._selected_uids = {uid} if uid else set()
            self._last_selected = item
            self._sync_checkboxes(old_sel ^ self._selected_uids)
            return "break"

    def _uid_of(self, item):
        """从 tree item 中提取 UID（第2列）。"""
        vals = self.tree.item(item, 'values')
        return vals[1] if len(vals) > 1 else None

    def _on_drag(self, event):
        """处理拖拽选多行。"""
        self._dragging = True
        TreeviewScroller.handle_drag_scroll(self.tree, event)
        if not self._drag_item:
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        visible = self.tree.get_children()
        if not visible:
            return
        try:
            start_idx = self.tree.index(self._drag_item)
            curr_idx = self.tree.index(item)
        except tk.TclError:
            return
        lo = min(start_idx, curr_idx)
        hi = max(start_idx, curr_idx)
        upd_lo = lo if self._drag_lo is None else min(lo, self._drag_lo)
        upd_hi = hi if self._drag_hi is None else max(hi, self._drag_hi)
        self._drag_lo, self._drag_hi = lo, hi
        selected = visible[lo:hi+1]
        self._selected_uids = {self._uid_of(i) for i in selected}
        self.tree.selection_set(selected)
        for i in range(upd_lo, upd_hi + 1):
            item_id = visible[i]
            vals = list(self.tree.item(item_id, 'values'))
            vals[0] = "✓" if lo <= i <= hi else " "
            self.tree.item(item_id, values=vals)

    def _on_release(self, event):
        """处理释放事件"""
        self._drag_start = None
        self._drag_item = None
        self._drag_lo = None
        self._drag_hi = None
        if self._dragging:
            self._sync_checkboxes()
        self._dragging = False

    def select_all(self, event=None):
        """全选。"""
        visible = self.tree.get_children()
        self._selected_uids.update(self._uid_of(i) for i in visible)
        self.tree.selection_set(visible)
        self._sync_checkboxes()
        return "break"

    def delete_selected(self):
        """外部删除入口。"""
        self._on_delete()

    def toggle_all_selection(self):
        """切换全选状态。"""
        visible = self.tree.get_children()
        if not visible:
            return
        all_sel = all(i in self.tree.selection() for i in visible)
        if all_sel:
            self._selected_uids.difference_update(self._uid_of(i) for i in visible)
            self.tree.selection_set([])
        else:
            self._selected_uids.update(self._uid_of(i) for i in visible)
            self.tree.selection_set(visible)
        self._sync_checkboxes()

    def get_selected_uids(self):
        """返回所有已选 UID（跨页）。"""
        return self._selected_uids

    def _sync_checkboxes(self, uids=None):
        """同步复选框和选中状态。
        
        Args:
            uids: 若提供，只更新这些 UID 对应行的复选框（不更新 selection）。
                  若为 None，全量同步（遍历所有行 + 重建 selection）。
        """
        if uids is not None:
            for uid in uids:
                item = self._uid_to_item.get(uid)
                if item is None:
                    continue
                vals = list(self.tree.item(item, 'values'))
                vals[0] = "✓" if uid in self._selected_uids else " "
                self.tree.item(item, values=vals)
            return
        sel = []
        for i in self.tree.get_children():
            uid = self._uid_of(i)
            selected = uid in self._selected_uids
            vals = list(self.tree.item(i, 'values'))
            vals[0] = "✓" if selected else " "
            self.tree.item(i, values=vals)
            if selected:
                sel.append(i)
        self.tree.selection_set(sel)

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
        """排序全量数据后重新渲染。"""
        if not self._all_data:
            return
        col = self._sort_col
        rev = self._sort_rev
        data = [(self._sort_key(col, row[self._col_index(col)]), row) for row in self._all_data]
        data.sort(key=lambda x: x[0], reverse=rev)
        self._all_data = [row for _, row in data]
        self._rerender()
        self._update_sort_arrows()

    def _col_index(self, col):
        """返回列名在 COLUMNS 中的索引。"""
        try:
            return self.COLUMNS.index(col)
        except ValueError:
            return 1  # 回退到 UID 列

    def _sort_key(self, col, value):
        """排序键 - 时间列用 datetime 解析，其他列用字符串"""
        if col in ('start', 'end', 'created_at', 'updated_at'):
            try: return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=None)
            except Exception: return datetime.min
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
        except Exception:
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
