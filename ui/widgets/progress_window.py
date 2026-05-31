import tkinter as tk
from tkinter import ttk
from datetime import datetime
from ui.widgets.right_click_menu import RightClickMenu

class ProgressWindow(tk.Toplevel):
    """通用的进度显示窗口"""
    def __init__(self, parent, title, cancel_callback=None):
        super().__init__(parent)
        self.title(title)
        self.geometry('700x500')
        self.transient(parent)
        self.grab_set()
        
        self.cancel_callback = cancel_callback
        self.create_widgets(title)
        
        self.protocol('WM_DELETE_WINDOW', self.on_cancel)

    def create_widgets(self, title):
        ttk.Label(self, text=title, font=('Arial', 12)).pack(pady=5)

        self.status_var = tk.StringVar(value='正在初始化...')
        status_label = ttk.Label(self, textvariable=self.status_var, font=('Arial', 10))
        status_label.pack(pady=5)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, padx=20, pady=5)

        # 1:1 还原统计看板 (main_old.py:929-963)
        stats_frame = ttk.Frame(self)
        stats_frame.pack(fill=tk.X, padx=20, pady=5)
        
        self.stat_vars = {
            'new': tk.IntVar(value=0),
            'updated': tk.IntVar(value=0),
            'unchanged': tk.IntVar(value=0),
            'failed': tk.IntVar(value=0)
        }
        
        colors = {'new': 'green', 'updated': 'blue', 'unchanged': 'gray', 'failed': 'red'}
        labels = {'new': '新增', 'updated': '更新', 'unchanged': '相同', 'failed': '失败'}
        
        for key in ['new', 'updated', 'unchanged', 'failed']:
            f = ttk.Frame(stats_frame); f.pack(side=tk.LEFT, expand=True)
            ttk.Label(f, text=f"{labels[key]}:").pack(side=tk.LEFT)
            ttk.Label(f, textvariable=self.stat_vars[key], foreground=colors[key], font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=2)

        error_frame = ttk.LabelFrame(self, text='详细日志')
        error_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = tk.Text(error_frame, wrap=tk.WORD)
        RightClickMenu(self.log_text, widget_type="log")
        scrollbar = ttk.Scrollbar(error_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.cancel_button = ttk.Button(self, text='取消', command=self.on_cancel)
        self.cancel_button.pack(pady=10)

    def on_cancel(self):
        if self.cancel_callback:
            self.cancel_callback()
        self.destroy()

    def update_status(self, text):
        self.status_var.set(text)

    def update_progress(self, value):
        self.progress_var.set(value)

    def log(self, message):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def set_finished(self):
        self.cancel_button.config(text='关闭', command=self.destroy)
        self.protocol('WM_DELETE_WINDOW', self.destroy)
