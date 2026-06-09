from tkinter import ttk


class TreeviewScroller:
    """Treeview 滚动逻辑抽象"""

    EDGE_THRESHOLD = 0.1    # 边缘触发阈值 10%
    MAX_SCROLL_UNITS = 50   # 最大单次滚动行数

    @staticmethod
    def compute_scroll_units(tree: ttk.Treeview, event):
        """计算拖拽边缘自动滚动的脉冲行数

        鼠标越靠近边缘，单次滚动行数越多 (1 ~ MAX_SCROLL_UNITS)。
        返回值: 正数=向下，负数=向上，0=不滚动。
        """
        h = tree.winfo_height()
        if h <= 0:
            return 0
        rel_y = event.y / h

        if rel_y < TreeviewScroller.EDGE_THRESHOLD:
            depth = (TreeviewScroller.EDGE_THRESHOLD - rel_y) / TreeviewScroller.EDGE_THRESHOLD
            return -max(1, int(depth * TreeviewScroller.MAX_SCROLL_UNITS))
        elif rel_y > (1 - TreeviewScroller.EDGE_THRESHOLD):
            depth = (rel_y - (1 - TreeviewScroller.EDGE_THRESHOLD)) / TreeviewScroller.EDGE_THRESHOLD
            return max(1, int(depth * TreeviewScroller.MAX_SCROLL_UNITS))
        return 0
