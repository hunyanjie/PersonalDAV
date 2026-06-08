"""Treeview 通用操作基类 — 原生 Treeview + yview 滚动。"""
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
    PAGE_SIZE = 500       # 虚拟滚动窗口大小

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
        self._scroll_offset = 0   # 虚拟滚动偏移量
        self._vsb_busy = False    # 防 vscroll.set 回环
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
        # 创建 Treeview
        self.tree = ttk.Treeview(list_frame, columns=['selected'] + list(self.COLUMNS),
                                 show='headings', selectmode='extended')
        self.tree.heading('selected', text='✓')
        self.tree.column('selected', width=30, anchor=tk.CENTER)

        for col in self.COLUMNS:
            width = self.get_column_width(col)
            self.tree.heading(col, text=self.HEADINGS.get(col, col),
                            command=lambda c=col: self.sort_tree(c))
            self.tree.column(col, width=width)

        # 滚动条
        self.vscroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.vscroll.set)
        self.hscroll = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(xscrollcommand=self.hscroll.set)

        self.vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 虚拟滚动 — 替换滚动条命令 + Treeview 的 yscrollcommand
        self.vscroll.config(command=self._vsb_handler)
        self.tree.configure(yscrollcommand=self._on_tree_scroll)

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
        self.tree.bind("<Up>", self._on_virtual_up)
        self.tree.bind("<Down>", self._on_virtual_down)
        self.tree.bind("<Prior>", self._on_virtual_pageup)
        self.tree.bind("<Next>", self._on_virtual_pagedown)
        self.tree.bind("<Home>", self._on_virtual_home)
        self.tree.bind("<End>", self._on_virtual_end)

        self._edit_callback = on_edit_callback

    def get_column_width(self, col):
        """获取列宽 - 子类可覆盖"""
        widths = {'selected': 30}
        return widths.get(col, 100)

    def _on_mousewheel(self, event):
        """鼠标滚轮滚动（支持虚拟滚动）。"""
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            self.tree.yview_scroll(-int(event.delta / 120), 'units')
            return
        step = -int(event.delta / 120)
        new_offset = self._scroll_offset + step
        new_offset = max(0, min(n - self.PAGE_SIZE, new_offset))
        if new_offset != self._scroll_offset:
            self._scroll_offset = new_offset
            self._render_window()

    # ── 虚拟滚动核心 ──

    def _vsb_handler(self, *args):
        """拦截滚动条操作，转发到虚拟滚动逻辑。"""
        if self._vsb_busy:
            return
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            self.tree.yview(*args)
            return
        cmd = args[0]
        if cmd == 'moveto':
            frac = float(args[1])
            self._scroll_offset = max(0, min(n - self.PAGE_SIZE, round(frac * n)))
            self._render_window()
        elif cmd == 'scroll':
            amount = int(args[1])
            what = args[2]
            step = amount * self.PAGE_SIZE if what == 'pages' else amount
            self._scroll_offset = max(0, min(n - self.PAGE_SIZE, self._scroll_offset + step))
            self._render_window()

    def _on_tree_scroll(self, first, last):
        """忽略 Treeview 内部滚动（虚拟滚动下由 _sync_scrollbar 管理）。"""
        if len(self._all_data) <= self.PAGE_SIZE:
            self.vscroll.set(first, last)

    def _render_window(self):
        """用当前 _scroll_offset 渲染 Treeview 窗口。"""
        n = len(self._all_data)
        if n == 0:
            for item in self.tree.get_children():
                self.tree.delete(item)
            self._sync_scrollbar()
            self._update_checkboxes()
            return
        end = min(self._scroll_offset + self.PAGE_SIZE, n)
        window_data = self._all_data[self._scroll_offset:end]
        existing = self.tree.get_children()
        for i, item_id in enumerate(existing):
            if i < len(window_data):
                self.tree.item(item_id, values=window_data[i])
        for i in range(len(existing), len(window_data)):
            self.tree.insert("", tk.END, values=window_data[i])
        for item_id in existing[len(window_data):]:
            self.tree.delete(item_id)
        self._sync_scrollbar()
        self._update_checkboxes()
        self.tree.yview_moveto(0)

    def _sync_scrollbar(self):
        """更新滚动条位置以反映虚拟数据集的大小。"""
        self._vsb_busy = True
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            self.vscroll.set(0, 1)
        else:
            off = self._scroll_offset
            vis = min(self.PAGE_SIZE, n)
            start = off / max(1, n)
            end = (off + vis) / max(1, n)
            self.vscroll.set(start, end)
        self._vsb_busy = False

    def _handle_drag_scroll_virtual(self, event):
        """拖拽时的边缘自动滚动（虚拟滚动版本）。"""
        h = self.tree.winfo_height()
        if h <= 0:
            return
        rel_y = event.y / h
        n = len(self._all_data)
        if rel_y < 0.1:
            new_off = max(0, self._scroll_offset - 1)
            if new_off != self._scroll_offset:
                self._scroll_offset = new_off
                self._render_window()
        elif rel_y > 0.9:
            new_off = min(n - self.PAGE_SIZE, self._scroll_offset + 1)
            if new_off != self._scroll_offset:
                self._scroll_offset = new_off
                self._render_window()

    # ── 键盘导航（虚拟滚动） ──

    def _on_virtual_up(self, event):
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            return
        sel = self.tree.selection()
        if not sel:
            return
        visible = self.tree.get_children()
        if not visible:
            return
        if sel[0] == visible[0] and self._scroll_offset > 0:
            self._scroll_offset -= 1
            self._render_window()
            self.tree.selection_set(self.tree.get_children()[0])
            self._update_checkboxes()
            return "break"

    def _on_virtual_down(self, event):
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            return
        sel = self.tree.selection()
        if not sel:
            return
        visible = self.tree.get_children()
        if not visible:
            return
        if sel[0] == visible[-1] and self._scroll_offset < n - self.PAGE_SIZE:
            self._scroll_offset += 1
            self._render_window()
            self.tree.selection_set(self.tree.get_children()[-1])
            self._update_checkboxes()
            return "break"

    def _on_virtual_pageup(self, event):
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            return
        self._scroll_offset = max(0, self._scroll_offset - self.PAGE_SIZE)
        self._render_window()
        return "break"

    def _on_virtual_pagedown(self, event):
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            return
        self._scroll_offset = min(n - self.PAGE_SIZE, self._scroll_offset + self.PAGE_SIZE)
        self._render_window()
        return "break"

    def _on_virtual_home(self, event):
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            return
        self._scroll_offset = 0
        self._render_window()
        self.tree.selection_set(self.tree.get_children()[0] if self.tree.get_children() else ())
        self._update_checkboxes()
        return "break"

    def _on_virtual_end(self, event):
        n = len(self._all_data)
        if n <= self.PAGE_SIZE:
            return
        self._scroll_offset = n - self.PAGE_SIZE
        self._render_window()
        items = self.tree.get_children()
        if items:
            self.tree.selection_set(items[-1])
            self._update_checkboxes()
        return "break"

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
            start_idx = visible.index(self._last_selected or visible[0])
            end_idx = visible.index(item)
            selected = visible[min(start_idx, end_idx):max(start_idx, end_idx)+1]
            selected_uids = {self._uid_of(i) for i in selected}
            self._selected_uids = selected_uids
            self.tree.selection_set(selected)
            self._update_checkboxes()
            return "break"

        ctrl = bool(event.state & 0x0004)
        uid = self._uid_of(item) if item else None

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
            self._update_checkboxes()
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
            self._update_checkboxes()
            return "break"

    def _uid_of(self, item):
        """从 tree item 中提取 UID（第2列）。"""
        vals = self.tree.item(item, 'values')
        return vals[1] if len(vals) > 1 else None

    def _on_drag(self, event):
        """处理拖拽选多行（支持虚拟滚动）。"""
        self._dragging = True
        n = len(self._all_data)
        if n > self.PAGE_SIZE:
            self._handle_drag_scroll_virtual(event)
        else:
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
            start_idx = visible.index(self._drag_item)
            curr_idx = visible.index(item)
        except ValueError:
            return
        selected = visible[min(start_idx, curr_idx):max(start_idx, curr_idx)+1]
        self._selected_uids = {self._uid_of(i) for i in selected}
        self.tree.selection_set(selected)
        self._update_checkboxes()

    def _on_release(self, event):
        """处理释放事件"""
        self._drag_start = None
        self._drag_item = None
        self._dragging = False

    def select_all(self, event=None):
        """全选当前页。"""
        visible = self.tree.get_children()
        self._selected_uids.update(self._uid_of(i) for i in visible)
        self.tree.selection_set(visible)
        self._update_checkboxes()
        return "break"

    def delete_selected(self):
        """外部删除入口。"""
        self._on_delete()

    def toggle_all_selection(self):
        """切换当前页全选状态。"""
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
        self._update_checkboxes()

    def get_selected_uids(self):
        """返回所有已选 UID（跨页）。"""
        return self._selected_uids

    def _update_checkboxes(self):
        """根据 _selected_uids 刷新当前页复选框和选中高亮。"""
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

    def _rerender(self):
        """用当前 _all_data 重建虚拟滚动视图。"""
        self._scroll_offset = 0
        self._render_window()

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
