import tkinter as tk
from tkinter import ttk
import webbrowser
from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_AUTHOR, SOFTWARE_DESCRIPTION


class AboutDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title(f"关于 {SOFTWARE_NAME}")
        # self.geometry("480x360")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)

        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=SOFTWARE_NAME, font=("", 18, "bold")).pack(pady=(0, 5))
        ttk.Label(frame, text=f"v{SOFTWARE_VERSION}", font=("", 12)).pack()
        ttk.Label(frame, text=SOFTWARE_DESCRIPTION, foreground="gray").pack(pady=(0, 15))

        sep = ttk.Separator(frame, orient="horizontal")
        sep.pack(fill=tk.X, pady=5)

        info = f"""作者: {SOFTWARE_AUTHOR}
协议: Apache-2.0
Python: 3.10+
数据库: SQLite (WAL)
DAV 协议: CardDAV + CalDAV + WebDAV
AI 集成: MCP (Model Context Protocol)"""

        ttk.Label(frame, text=info, justify=tk.LEFT, font=("", 9)).pack(pady=10)

        link_f = ttk.Frame(frame)
        link_f.pack(pady=5)
        link = ttk.Label(link_f, text="https://github.com/hunyanjie/PersonalDAV",
                         foreground="blue", cursor="hand2", font=("", 9))
        link.pack()
        link.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/hunyanjie/PersonalDAV"))

        ttk.Button(frame, text="确定", command=self.destroy).pack(pady=(10, 0))
        from utils.window_utils import center_window
        center_window(self, parent)
