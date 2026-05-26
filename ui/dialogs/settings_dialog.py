import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from ui.widgets.right_click_menu import RightClickMenu
from ui.dialogs.event_dialog import EventDialog
from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED

class SettingsDialog(tk.Toplevel):
    """系统设置对话框 - 1:1 深度还原，Flawless 设计"""
    def __init__(self, parent, db_service, on_save_callback):
        super().__init__(parent)
        self.title("设置")
        self.geometry("700x650")
        self.transient(parent)
        self.grab_set()
        self.db = db_service
        self.on_save_callback = on_save_callback

        main_frame = ttk.Frame(self); main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook = ttk.Notebook(main_frame); notebook.pack(fill=tk.BOTH, expand=True)

        server_frame = ttk.Frame(notebook); notebook.add(server_frame, text="服务器设置")
        calendar_frame = ttk.Frame(notebook); notebook.add(calendar_frame, text="日历设置")
        log_frame = ttk.Frame(notebook); notebook.add(log_frame, text="日志设置")

        self.create_server_settings(server_frame)
        self.create_calendar_settings(calendar_frame)
        self.create_log_settings(log_frame)

        btn_frame = ttk.Frame(main_frame); btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="保存", command=self.save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=5)

        self.load_settings()

    def create_server_settings(self, parent):
        f = ttk.LabelFrame(parent, text="服务器控制"); f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.auto_save_port_var = tk.BooleanVar()
        ttk.Checkbutton(f, text="自动保存端口号", variable=self.auto_save_port_var).grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.auto_start_server_var = tk.BooleanVar()
        ttk.Checkbutton(f, text="启动时自动启动服务器", variable=self.auto_start_server_var).grid(row=1, column=0, sticky="w", padx=5, pady=5)
        ttk.Label(f, text="默认端口号:").grid(row=2, column=0, sticky="w", padx=5)
        self.default_port_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.default_port_var, width=10).grid(row=2, column=1, sticky="w")

    def create_calendar_settings(self, parent):
        nb = ttk.Notebook(parent); nb.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        b_t = ttk.Frame(nb); nb.add(b_t, text="基本设置")
        r_t = ttk.Frame(nb); nb.add(r_t, text="提醒预设")
        t_t = ttk.Frame(nb); nb.add(t_t, text="默认勾选项")

        # 基本设置
        ttk.Label(b_t, text="默认事件状态:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.default_status_var = tk.StringVar()
        ttk.Combobox(b_t, textvariable=self.default_status_var, values=list(EventDialog.STATUS_MAPPING.keys()), state="readonly").grid(row=0, column=1)

        ttk.Label(b_t, text="默认日历版本:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.default_version_var = tk.StringVar()
        ttk.Combobox(b_t, textvariable=self.default_version_var, values=["1.0", "2.0", "2.1", "3.0"], state="readonly", width=10).grid(row=1, column=1, sticky="w")

        ttk.Label(b_t, text="默认持续时间 (小时):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.default_duration_var = tk.StringVar()
        ttk.Spinbox(b_t, textvariable=self.default_duration_var, from_=1, to=24, width=5).grid(row=2, column=1, sticky="w")

        ttk.Label(b_t, text="默认优先级 (0-9):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.default_priority_var = tk.IntVar()
        ttk.Scale(b_t, from_=0, to=9, variable=self.default_priority_var, orient='horizontal').grid(row=3, column=1, sticky="we")

        ttk.Label(b_t, text="默认透明度:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.default_transparency_var = tk.StringVar()
        ttk.Combobox(b_t, textvariable=self.default_transparency_var, values=list(EventDialog.TRANSPARENCY_MAPPING.keys()), state="readonly", width=10).grid(row=4, column=1, sticky="w")
        
        self.default_sync_timezone_var = tk.BooleanVar()
        ttk.Checkbutton(b_t, text="结束时间使用相同时区", variable=self.default_sync_timezone_var).grid(row=5, column=0, columnspan=2, sticky="w", pady=5)

        # 提醒预设
        ttk.Label(r_t, text="预设提醒列表 (常规事件):").pack(anchor="w", padx=5, pady=(5,0))
        self.preset_reminders_listbox = tk.Listbox(r_t, height=4); self.preset_reminders_listbox.pack(fill=tk.X, padx=5)
        
        ttk.Label(r_t, text="预设提醒列表 (全天事件):").pack(anchor="w", padx=5, pady=(5,0))
        self.preset_allday_reminders_listbox = tk.Listbox(r_t, height=4); self.preset_allday_reminders_listbox.pack(fill=tk.X, padx=5)
        
        p_btn = ttk.Frame(r_t); p_btn.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(p_btn, text="添加常规预设", command=lambda: self.add_preset(self.preset_reminders_listbox)).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="添加全天预设", command=lambda: self.add_preset(self.preset_allday_reminders_listbox)).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="删除选中", command=self.delete_preset).pack(side=tk.LEFT, padx=2)

        # 默认勾选项
        ttk.Label(t_t, text="新建常规事件自动勾选的提醒:").pack(anchor="w", padx=5, pady=5)
        self.default_reminders_listbox = tk.Listbox(t_t, selectmode='multiple', height=6)
        opts = ["日程发生时", "5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前", "2天前", "7天前"]
        for opt in opts: self.default_reminders_listbox.insert(tk.END, opt)
        self.default_reminders_listbox.pack(fill=tk.X, padx=5)

        ttk.Label(t_t, text="新建全天事件自动勾选的提醒:").pack(anchor="w", padx=5, pady=5)
        self.default_allday_reminders_listbox = tk.Listbox(t_t, selectmode='multiple', height=6)
        allday_opts = ["当天上午9点", "1天前上午9点", "2天前上午9点", "3天前上午9点", "5天前上午9点", "7天前上午9点"]
        for opt in allday_opts: self.default_allday_reminders_listbox.insert(tk.END, opt)
        self.default_allday_reminders_listbox.pack(fill=tk.X, padx=5)

    def create_log_settings(self, parent):
        f = ttk.LabelFrame(parent, text="日志记录"); f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.enable_log_file_var = tk.BooleanVar()
        ttk.Checkbutton(f, text="启用日志文件", variable=self.enable_log_file_var).grid(row=0, column=0, columnspan=3, sticky="w", padx=5, pady=10)
        
        ttk.Label(f, text="日志文件路径:").grid(row=1, column=0, padx=5)
        self.log_path_var = tk.StringVar()
        self.log_path_entry = ttk.Entry(f, textvariable=self.log_path_var, width=35)
        self.log_path_entry.grid(row=1, column=1)
        self.log_browse_btn = ttk.Button(f, text="浏览...", command=self.browse_log_file)
        self.log_browse_btn.grid(row=1, column=2, padx=5)
        
        ttk.Label(f, text="日志级别:").grid(row=2, column=0, padx=5, pady=10)
        self.log_level_var = tk.StringVar()
        self.log_level_combo = ttk.Combobox(f, textvariable=self.log_level_var, values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], state="readonly")
        self.log_level_combo.grid(row=2, column=1, sticky="w")
        
        def on_toggle(*args):
            st = tk.NORMAL if self.enable_log_file_var.get() else tk.DISABLED
            self.log_path_entry.config(state=st); self.log_browse_btn.config(state=st); self.log_level_combo.config(state=st)
        self.enable_log_file_var.trace("w", on_toggle)

    def add_preset(self, lb):
        v = simpledialog.askstring("添加预设", "输入提醒文本 (如: 15分钟前):", parent=self)
        if v: lb.insert(tk.END, v)

    def delete_preset(self):
        for lb in [self.preset_reminders_listbox, self.preset_allday_reminders_listbox]:
            s = lb.curselection()
            if s: lb.delete(s[0])

    def browse_log_file(self):
        p = filedialog.asksaveasfilename(defaultextension=".log")
        if p: self.log_path_var.set(p)

    def load_settings(self):
        s = self.db
        self.auto_save_port_var.set(s.get_setting("auto_save_port", "True") == "True")
        self.auto_start_server_var.set(s.get_setting("auto_start_server", "False") == "True")
        self.default_port_var.set(s.get_setting("default_port", "8000"))
        
        status_en = s.get_setting("default_status", "CONFIRMED")
        self.default_status_var.set(next((k for k, v in EventDialog.STATUS_MAPPING.items() if v == status_en), "已确认"))
        self.default_version_var.set(s.get_setting("default_version", "2.0"))
        self.default_duration_var.set(s.get_setting("default_duration", "1"))
        self.default_priority_var.set(int(s.get_setting("default_priority", "5")))
        
        transp_en = s.get_setting("default_transparency", "OPAQUE")
        self.default_transparency_var.set(next((k for k, v in EventDialog.TRANSPARENCY_MAPPING.items() if v == transp_en), "忙碌"))
        
        self.default_sync_timezone_var.set(s.get_setting("default_sync_timezone", "True") == "True")
        
        # 加载列表预设
        for key, lb in [('preset_reminders', self.preset_reminders_listbox), 
                        ('preset_allday_reminders', self.preset_allday_reminders_listbox)]:
            val = s.get_setting(key, '')
            if val:
                for item in val.split(';'):
                    if item: lb.insert(tk.END, item)

        # 加载默认勾选项
        for key, lb in [('default_reminders', self.default_reminders_listbox),
                        ('default_allday_reminders', self.default_allday_reminders_listbox)]:
            sel_str = s.get_setting(key, '')
            sel_list = sel_str.split(';')
            for i in range(lb.size()):
                if lb.get(i) in sel_list: lb.selection_set(i)

        self.enable_log_file_var.set(s.get_setting("enable_log_file", "False") == "True")
        self.log_path_var.set(s.get_setting("log_file_path", "dav_server.log"))
        self.log_level_var.set(s.get_setting("log_level", "INFO"))

    def save_settings(self):
        s = self.db
        s.set_setting("auto_save_port", str(self.auto_save_port_var.get()))
        s.set_setting("auto_start_server", str(self.auto_start_server_var.get()))
        s.set_setting("default_port", self.default_port_var.get())
        
        s.set_setting("default_status", EventDialog.STATUS_MAPPING.get(self.default_status_var.get(), "CONFIRMED"))
        s.set_setting("default_version", self.default_version_var.get())
        s.set_setting("default_duration", self.default_duration_var.get())
        s.set_setting("default_priority", str(self.default_priority_var.get()))
        s.set_setting("default_transparency", EventDialog.TRANSPARENCY_MAPPING.get(self.default_transparency_var.get(), "OPAQUE"))
        s.set_setting("default_sync_timezone", str(self.default_sync_timezone_var.get()))
        
        s.set_setting('preset_reminders', ';'.join([self.preset_reminders_listbox.get(i) for i in range(self.preset_reminders_listbox.size())]))
        s.set_setting('preset_allday_reminders', ';'.join([self.preset_allday_reminders_listbox.get(i) for i in range(self.preset_allday_reminders_listbox.size())]))
        
        s.set_setting('default_reminders', ';'.join([self.default_reminders_listbox.get(i) for i in self.default_reminders_listbox.curselection()]))
        s.set_setting('default_allday_reminders', ';'.join([self.default_allday_reminders_listbox.get(i) for i in self.default_allday_reminders_listbox.curselection()]))

        s.set_setting("enable_log_file", str(self.enable_log_file_var.get()))
        s.set_setting("log_file_path", self.log_path_var.get())
        s.set_setting("log_level", self.log_level_var.get())

        event_bus.publish(EVENT_SETTINGS_CHANGED) # 发布设置变更
        if self.on_save_callback: self.on_save_callback()
        messagebox.showinfo("成功", "设置已保存")
        self.destroy()
