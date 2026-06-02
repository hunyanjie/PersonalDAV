"""虚拟滚动 Treeview — 只渲染可视区域内行，万条数据无卡顿。"""
import tkinter as tk
from tkinter import ttk


class VirtualTreeview:
    """用滑动窗口包装 ttk.Treeview，总数据量不限。

    用法:
        vtree = VirtualTreeview(parent, columns, headings, column_width_fn)
        vtree.set_data(data)         # data 是 (值, ...) 元组列表
        vtree.tree                    # 原始 Treeview（用于事件绑定）
        vtree.frame                   # 容器 Frame（用于 pack）
        vtree.scrollbar               # 滚动条
    """
    PAGE_SIZE = 200  # 每页行数

    def __init__(self, parent, columns, headings, column_width_fn):
        self._data = []            # 全量数据
        self._offset = 0           # 当前窗口起始索引
        self._idx_to_iid = {}      # 数据索引 → tree item id
        self._iid_to_idx = {}      # tree item id → 数据索引
        self._col_width_fn = column_width_fn
        self.post_render_hook = None  # _render 完成后回调，由 BaseTreeTab 设为 _update_checkboxes

        self.frame = ttk.Frame(parent)
        self.tree = ttk.Treeview(self.frame, columns=columns, show="headings",
                                 selectmode="extended")
        for col in columns:
            self.tree.heading(col, text=headings.get(col, col))
            self.tree.column(col, width=column_width_fn(col))

        self.scrollbar = ttk.Scrollbar(self.frame, orient=tk.VERTICAL,
                                       command=self._on_scrollbar)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.frame.pack(fill=tk.BOTH, expand=True)

    # ── 公共接口 ────────────────────────────────────────────

    def set_data(self, data):
        """设置全量数据并刷新显示。"""
        self._data = list(data)
        self._offset = 0
        self._render()

    def get_data(self):
        """返回全量数据列表。"""
        return self._data

    def get_count(self):
        """返回总数据条数。"""
        return len(self._data)

    def idx_of(self, iid):
        """tree item id → 数据索引"""
        return self._iid_to_idx.get(iid)

    def iid_of(self, idx):
        """数据索引 → tree item id（仅在可视窗口内有效）"""
        return self._idx_to_iid.get(idx)

    def get_visible_iids(self):
        """返回当前可视范围内所有 tree item ID（按行顺序）。"""
        total = self.get_count()
        if total == 0:
            return []
        end = min(self._offset + self.PAGE_SIZE, total)
        result = []
        for i in range(self._offset, end):
            iid = self._idx_to_iid.get(i)
            if iid:
                result.append(iid)
        return result

    def visible_indices(self):
        """当前可视范围内的数据索引列表（排序后）。"""
        return sorted(self._idx_to_iid.keys())

    def index_at(self, y):
        """根据 Y 坐标获取对应行的数据索引。"""
        iid = self.tree.identify_row(y)
        return self._iid_to_idx.get(iid) if iid else None

    def scroll_to_index(self, index):
        """滚动到指定数据索引处（使其进入可视窗口）。"""
        total = self.get_count()
        if total <= self.PAGE_SIZE:
            return
        max_off = total - self.PAGE_SIZE
        self._offset = max(0, min(max_off, index - self.PAGE_SIZE // 4))
        self._render()

    # ── 内部 ────────────────────────────────────────────────

    def _render(self):
        """销毁旧行，插入当前窗口范围内的行。"""
        for iid in list(self._idx_to_iid.values()):
            self.tree.delete(iid)
        self._idx_to_iid.clear()
        self._iid_to_idx.clear()

        total = self.get_count()
        if total == 0:
            self._sync_scrollbar()
            return

        end = min(self._offset + self.PAGE_SIZE, total)
        for i in range(self._offset, end):
            iid = self.tree.insert("", tk.END, values=self._data[i])
            self._idx_to_iid[i] = iid
            self._iid_to_idx[iid] = i

        self._sync_scrollbar()
        if self.post_render_hook:
            self.post_render_hook()

    def _on_scrollbar(self, *args):
        """滚动条拖动/滚轮回调。"""
        total = self.get_count()
        max_off = max(0, total - self.PAGE_SIZE)

        if args[0] == 'moveto':
            frac = float(args[1])
            self._offset = min(max_off, int(frac * max_off))
        elif args[0] == 'scroll':
            n = int(args[1])
            if args[2] == 'units':
                self._offset = max(0, min(max_off, self._offset + n))
            elif args[2] == 'pages':
                self._offset = max(0, min(max_off, self._offset + n * self.PAGE_SIZE // 2))

        self._render()

    def _sync_scrollbar(self):
        """根据当前偏移量和总数据量更新滚动条。"""
        total = self.get_count()
        if total <= self.PAGE_SIZE:
            self.scrollbar.set(0.0, 1.0)
            return
        frac = self._offset / (total - self.PAGE_SIZE)
        thumb = self.PAGE_SIZE / total
        self.scrollbar.set(frac, min(1.0, frac + thumb))
