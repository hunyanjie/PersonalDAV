from tkinter import ttk


class TreeviewScroller:
    """Treeview 滚动逻辑抽象"""

    EDGE_THRESHOLD = 0.1  # 边缘阈值 10%

    @staticmethod
    def handle_drag_scroll(tree: ttk.Treeview, event):
        """处理拖拽时的边缘自动滚动

        当鼠标移动到 Treeview 边缘区域时自动滚动列表。
        向上滚动: rel_y < 0.1 (顶部 10%)
        向下滚动: rel_y > 0.9 (底部 10%)
        """
        h = tree.winfo_height()
        if h <= 0:
            return
        rel_y = event.y / h
        if rel_y < TreeviewScroller.EDGE_THRESHOLD:
            tree.yview_scroll(-1, "units")
        elif rel_y > (1 - TreeviewScroller.EDGE_THRESHOLD):
            tree.yview_scroll(1, "units")
