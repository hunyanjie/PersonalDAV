"""虚拟滚动 Treeview — 只渲染可视区域内行，万条数据无卡顿。"""
import tkinter as tk
from tkinter import ttk


class VirtualTreeview:
    """用滑动窗口包装 ttk.Treeview，总数据量不限。

    不再使用固定 PAGE_SIZE，而是根据 Treeview 实际高度动态
    计算可视行数，Treeview 自身无需滚动，滚动条完全控制虚拟偏移。

    用法:
        vtree = VirtualTreeview(parent, columns, headings, column_width_fn)
        vtree.set_data(data)         # data 是 (值, ...) 元组列表
        vtree.tree                    # 原始 Treeview（用于事件绑定）
        vtree.frame                   # 容器 Frame（用于 pack）
        vtree.scrollbar               # 滚动条
    """
    def __init__(self, parent, columns, headings, column_width_fn):
        self._data = []            # 全量数据
        self._offset = 0           # 当前窗口起始索引
        self._idx_to_iid = {}      # 数据索引 → tree item id
        self._iid_to_idx = {}      # tree item id → 数据索引
        self._col_width_fn = column_width_fn
        self._visible = 20         # 当前窗口实际可渲染行数（初次精确填充后缓存）
        self._iid_seq = 0          # 双缓冲 IID 序列号
        self.post_render_hook = None

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

        self.tree.bind('<Configure>', self._on_configure, add='+')

    # ── 公共接口 ────────────────────────────────────────────

    def set_data(self, data):
        """设置全量数据并刷新显示。"""
        self._data = list(data)
        self._offset = 0
        self._render_precise()

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
        """返回当前已渲染的所有 tree item ID（按行顺序）。"""
        return [self._idx_to_iid[i] for i in sorted(self._idx_to_iid) if self._idx_to_iid[i]]

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
        page = max(1, len(self._idx_to_iid))
        if total <= page:
            return
        max_off = total - page
        self._offset = max(0, min(max_off, index - page // 4))
        self._render_fast()

    # ── 内部 ────────────────────────────────────────────────

    def _new_iid(self):
        """生成全局唯一 IID 用于双缓冲。"""
        self._iid_seq += 1
        return f"_vt{self._iid_seq}"

    def _swap_items(self, new_items):
        """用新 items 替换旧 items（先插后删，消除闪白）。"""
        old_iids = dict(self._idx_to_iid)
        self._idx_to_iid = new_items
        self._iid_to_idx = {v: k for k, v in new_items.items()}
        for iid in old_iids.values():
            self.tree.delete(iid)

    def _render_fast(self):
        """快速渲染：用缓存的 _visible 行数批量插入，适合滚动。"""
        total = self.get_count()
        page = self._visible
        end = min(self._offset + page, total)
        new_items = {}
        for i in range(self._offset, end):
            iid = self._new_iid()
            self.tree.insert("", tk.END, iid=iid, values=self._data[i])
            new_items[i] = iid
        # 有多余或不足时修正 _visible
        actual = end - self._offset
        if actual != self._visible:
            self._visible = actual
        self._swap_items(new_items)
        self._sync_scrollbar()
        if self.post_render_hook:
            self.post_render_hook()

    def _render_precise(self):
        """精确填充：用 bbox 逐行测试确保刚好填满，仅在加载/调窗口时执行。"""
        total = self.get_count()
        tree_h = self.tree.winfo_height()
        new_items = {}
        idx = self._offset
        while idx < total:
            iid = self._new_iid()
            self.tree.insert("", tk.END, iid=iid, values=self._data[idx])
            new_items[idx] = iid
            idx += 1
            self.tree.update_idletasks()
            b = self.tree.bbox(iid)
            if b:
                if b[1] + b[3] > tree_h:
                    self.tree.delete(iid)
                    del new_items[idx - 1]
                    idx -= 1
                    break
            elif idx - self._offset >= self._visible:
                break
        self._visible = max(5, idx - self._offset)
        self._swap_items(new_items)
        self._sync_scrollbar()
        if self.post_render_hook:
            self.post_render_hook()

    def _on_configure(self, event):
        """窗口尺寸变化时精确重填。"""
        if event.widget is not self.tree:
            return
        if self._data:
            self._render_precise()

    def _on_scrollbar(self, *args):
        """滚动条拖动/滚轮回调。"""
        total = self.get_count()
        page = self._visible
        max_off = max(0, total - page)

        if args[0] == 'moveto':
            frac = float(args[1])
            self._offset = max(0, min(max_off, int(frac * total)))
        elif args[0] == 'scroll':
            n = int(args[1])
            if args[2] == 'units':
                self._offset = max(0, min(max_off, self._offset + n))
            elif args[2] == 'pages':
                self._offset = max(0, min(max_off, self._offset + n * page // 2))

        self._render_fast()

    def _sync_scrollbar(self):
        """根据 _offset 和已缓存行数更新滚动条位置。"""
        total = self.get_count()
        page = self._visible
        if total <= page:
            self.scrollbar.set(0.0, 1.0)
            return
        first = self._offset / total
        last = (self._offset + page) / total
        self.scrollbar.set(first, last)
