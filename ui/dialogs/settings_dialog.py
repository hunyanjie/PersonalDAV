import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from ui.widgets.right_click_menu import RightClickMenu
from ui.dialogs.event_dialog import EventDialog
from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED
import re


class SettingsDialog(tk.Toplevel):
    """系统设置对话框"""
    def __init__(self, parent, db_service, on_save_callback):
        super().__init__(parent)
        self.title("设置")
        self.geometry("750x700")
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
        r_t = ttk.Frame(nb); nb.add(r_t, text="提醒设置")
        p_t = ttk.Frame(nb); nb.add(p_t, text="预设提醒")

        # ==================== 基本设置 (b_t) ====================
        ttk.Label(b_t, text="默认事件状态:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.default_status_var = tk.StringVar()
        ttk.Combobox(b_t, textvariable=self.default_status_var, values=list(EventDialog.STATUS_MAPPING.keys()), state="readonly").grid(row=0, column=1, sticky="w")

        ttk.Label(b_t, text="默认日历版本:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.default_version_var = tk.StringVar()
        ttk.Combobox(b_t, textvariable=self.default_version_var, values=["1.0", "2.0", "2.1", "3.0"], state="readonly", width=10).grid(row=1, column=1, sticky="w")

        ttk.Label(b_t, text="默认持续时间 (小时):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.default_duration_var = tk.StringVar()
        ttk.Spinbox(b_t, textvariable=self.default_duration_var, from_=1, to=24, width=5).grid(row=2, column=1, sticky="w")

        ttk.Label(b_t, text="默认优先级 (0-9):").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.default_priority_var = tk.IntVar()
        priority_frame = ttk.Frame(b_t)
        priority_frame.grid(row=3, column=1, sticky="w")
        ttk.Scale(priority_frame, from_=0, to=9, variable=self.default_priority_var, orient='horizontal', length=150,
                  command=lambda v: self.default_priority_label.config(text=f" {int(float(v))} ")).pack(side=tk.LEFT)
        self.default_priority_label = ttk.Label(priority_frame, text=" 5 ", width=3, relief=tk.RIDGE, anchor="center")
        self.default_priority_label.pack(side=tk.LEFT, padx=5)

        ttk.Label(b_t, text="默认透明度:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
        self.default_transparency_var = tk.StringVar()
        ttk.Combobox(b_t, textvariable=self.default_transparency_var, values=list(EventDialog.TRANSPARENCY_MAPPING.keys()), state="readonly", width=10).grid(row=4, column=1, sticky="w")

        self.default_sync_timezone_var = tk.BooleanVar()
        ttk.Checkbutton(b_t, text="结束时间使用相同时区", variable=self.default_sync_timezone_var).grid(row=5, column=0, columnspan=2, sticky="w", pady=5)

        # 重复规则设置
        sep = ttk.Separator(b_t, orient='horizontal'); sep.grid(row=6, column=0, columnspan=2, sticky='ew', pady=5)
        ttk.Label(b_t, text="默认重复规则:").grid(row=7, column=0, padx=5, pady=5, sticky="w")
        self.default_repeat_var = tk.StringVar()
        ttk.Combobox(b_t, textvariable=self.default_repeat_var, values=EventDialog.REPEAT_OPTIONS, state="readonly", width=12).grid(row=7, column=1, sticky="w")

        ttk.Label(b_t, text="默认结束条件:").grid(row=8, column=0, padx=5, pady=5, sticky="w")
        self.default_end_cond_var = tk.StringVar()
        ttk.Combobox(b_t, textvariable=self.default_end_cond_var, values=EventDialog.END_CONDITIONS, state="readonly", width=12).grid(row=8, column=1, sticky="w")

        ttk.Label(b_t, text="默认结束次数:").grid(row=9, column=0, padx=5, pady=5, sticky="w")
        self.default_end_count_var = tk.StringVar()
        ttk.Spinbox(b_t, textvariable=self.default_end_count_var, from_=1, to=999, width=5).grid(row=9, column=1, sticky="w")

        self.default_allday_var = tk.BooleanVar()
        ttk.Checkbutton(b_t, text="默认创建全天事件", variable=self.default_allday_var).grid(row=10, column=0, columnspan=2, sticky="w", pady=5)

        self.default_force_reminder_var = tk.BooleanVar()
        ttk.Checkbutton(b_t, text="默认勾选强制提醒", variable=self.default_force_reminder_var).grid(row=11, column=0, columnspan=2, sticky="w", pady=5)

        # ==================== 提醒设置 (r_t) ====================
        config_f = ttk.LabelFrame(r_t, text="全局默认提醒参数")
        config_f.grid(row=0, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        ttk.Label(config_f, text="默认提醒类型:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.default_reminder_type_var = tk.StringVar()
        ttk.Combobox(config_f, textvariable=self.default_reminder_type_var, values=["显示", "声音", "邮件"], state="readonly", width=10).grid(row=0, column=1, sticky="w")

        ttk.Label(config_f, text="默认触发方式:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.default_trigger_type_var = tk.StringVar()
        ttk.Combobox(config_f, textvariable=self.default_trigger_type_var, values=["提前时间提醒", "指定时间提醒"], state="readonly", width=12).grid(row=1, column=1, sticky="w")

        ttk.Label(config_f, text="全天日程默认提醒时间:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.default_allday_reminder_time_var = tk.StringVar()
        ttk.Entry(config_f, textvariable=self.default_allday_reminder_time_var, width=10).grid(row=2, column=1, sticky="w")
        ttk.Label(config_f, text="(格式: HH:MM, 如 09:00)", foreground="gray").grid(row=2, column=2, sticky="w")

        sep_rem = ttk.Separator(r_t, orient='horizontal'); sep_rem.grid(row=1, column=0, columnspan=2, sticky='ew', pady=10)

        detail_f = ttk.LabelFrame(r_t, text="常规事件默认偏移量")
        detail_f.grid(row=2, column=0, columnspan=2, sticky='ew', padx=5, pady=5)

        ttk.Label(detail_f, text="天:").grid(row=0, column=0, padx=5, pady=5)
        self.default_reminder_days_var = tk.StringVar()
        ttk.Spinbox(detail_f, from_=0, to=365, textvariable=self.default_reminder_days_var, width=5).grid(row=0, column=1, sticky='w')

        ttk.Label(detail_f, text="小时:").grid(row=0, column=2, padx=5, pady=5)
        self.default_reminder_hours_var = tk.StringVar()
        ttk.Spinbox(detail_f, from_=0, to=23, textvariable=self.default_reminder_hours_var, width=5).grid(row=0, column=3, sticky='w')

        ttk.Label(detail_f, text="分钟:").grid(row=0, column=4, padx=5, pady=5)
        self.default_reminder_minutes_var = tk.StringVar()
        ttk.Spinbox(detail_f, from_=0, to=59, textvariable=self.default_reminder_minutes_var, width=5).grid(row=0, column=5, sticky='w')

        ttk.Label(r_t, text="预设提醒列表 (常规事件):").grid(row=3, column=0, padx=5, pady=(15,0), sticky="w")
        preset_normal_frame = ttk.Frame(r_t)
        preset_normal_frame.grid(row=4, column=0, padx=5, sticky="nsew")
        self.preset_reminders_listbox = tk.Listbox(preset_normal_frame, height=4)
        self.preset_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        preset_normal_scroll = ttk.Scrollbar(preset_normal_frame, orient=tk.VERTICAL, command=self.preset_reminders_listbox.yview)
        preset_normal_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_reminders_listbox.config(yscrollcommand=preset_normal_scroll.set)

        ttk.Label(r_t, text="预设提醒列表 (全天事件):").grid(row=3, column=1, padx=5, pady=(15,0), sticky="w")
        preset_allday_frame = ttk.Frame(r_t)
        preset_allday_frame.grid(row=4, column=1, padx=5, sticky="nsew")
        self.preset_allday_reminders_listbox = tk.Listbox(preset_allday_frame, height=4)
        self.preset_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        preset_allday_scroll = ttk.Scrollbar(preset_allday_frame, orient=tk.VERTICAL, command=self.preset_allday_reminders_listbox.yview)
        preset_allday_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_allday_reminders_listbox.config(yscrollcommand=preset_allday_scroll.set)

        p_btn = ttk.Frame(r_t); p_btn.grid(row=5, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Button(p_btn, text="添加预设", command=self.add_preset_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="编辑预设", command=self.edit_preset_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="删除预设", command=self.delete_preset_reminder).pack(side=tk.LEFT, padx=2)

        # ==================== 测试/自定义选项 (p_t) ====================
        ttk.Label(p_t, text="新建常规事件自动勾选的提醒:").pack(anchor="w", padx=5, pady=5)
        default_normal_frame = ttk.Frame(p_t)
        default_normal_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        self.default_reminders_listbox = tk.Listbox(default_normal_frame, selectmode='multiple', height=6)
        self.default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        default_normal_scroll = ttk.Scrollbar(default_normal_frame, orient=tk.VERTICAL, command=self.default_reminders_listbox.yview)
        default_normal_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.default_reminders_listbox.config(yscrollcommand=default_normal_scroll.set)
        opts = ["日程发生时", "5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前", "2天前", "7天前"]
        for opt in opts: self.default_reminders_listbox.insert(tk.END, opt)

        ttk.Label(p_t, text="新建全天事件自动勾选的提醒:").pack(anchor="w", padx=5, pady=5)
        default_allday_frame = ttk.Frame(p_t)
        default_allday_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        self.default_allday_reminders_listbox = tk.Listbox(default_allday_frame, selectmode='multiple', height=6)
        self.default_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        default_allday_scroll = ttk.Scrollbar(default_allday_frame, orient=tk.VERTICAL, command=self.default_allday_reminders_listbox.yview)
        default_allday_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.default_allday_reminders_listbox.config(yscrollcommand=default_allday_scroll.set)
        allday_opts = ["当天上午9点", "1天前上午9点", "2天前上午9点", "3天前上午9点", "5天前上午9点", "7天前上午9点"]
        for opt in allday_opts: self.default_allday_reminders_listbox.insert(tk.END, opt)

        # 自定义默认提醒
        ttk.Separator(p_t, orient='horizontal').pack(fill='x', pady=10)
        ttk.Label(p_t, text="自定义默认提醒 (新建事件时自动添加):", font=('Arial', 10, 'bold')).pack(anchor="w", padx=5, pady=5)

        ttk.Label(p_t, text="常规事件:").pack(anchor="w", padx=5)
        custom_normal_frame = ttk.Frame(p_t)
        custom_normal_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        self.custom_default_reminders_listbox = tk.Listbox(custom_normal_frame, height=4)
        self.custom_default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        custom_normal_scroll = ttk.Scrollbar(custom_normal_frame, orient=tk.VERTICAL, command=self.custom_default_reminders_listbox.yview)
        custom_normal_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_default_reminders_listbox.config(yscrollcommand=custom_normal_scroll.set)

        ttk.Label(p_t, text="全天事件:").pack(anchor="w", padx=5)
        custom_allday_frame = ttk.Frame(p_t)
        custom_allday_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        self.custom_allday_default_reminders_listbox = tk.Listbox(custom_allday_frame, height=4)
        self.custom_allday_default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        custom_allday_scroll = ttk.Scrollbar(custom_allday_frame, orient=tk.VERTICAL, command=self.custom_allday_default_reminders_listbox.yview)
        custom_allday_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_allday_default_reminders_listbox.config(yscrollcommand=custom_allday_scroll.set)

        c_btn = ttk.Frame(p_t); c_btn.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(c_btn, text="添加常规", command=lambda: self.add_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="编辑常规", command=lambda: self.edit_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="删除常规", command=lambda: self.delete_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="添加全天", command=lambda: self.add_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="编辑全天", command=lambda: self.edit_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="删除全天", command=lambda: self.delete_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)

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

    def add_preset_reminder(self):
        """添加预设提醒"""
        dialog = tk.Toplevel(self)
        dialog.title('添加预设提醒')
        dialog.geometry('400x200')
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text='预设格式（可选）:').pack(anchor='w', padx=10, pady=5)
        ttk.Label(dialog, text='- 提前提醒: "5分钟前", "1小时前", "2天前"', foreground='gray').pack(anchor='w', padx=10)
        ttk.Label(dialog, text='- 指定时间: "09:30"', foreground='gray').pack(anchor='w', padx=10)
        ttk.Label(dialog, text='- 全天事件: "当天上午9点"', foreground='gray').pack(anchor='w', padx=10)

        frame = ttk.Frame(dialog); frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(frame, text='预设内容:').grid(row=0, column=0, sticky='w')
        entry = ttk.Entry(frame, width=30); entry.grid(row=0, column=1, sticky='we', padx=5)
        var = tk.StringVar(value='normal')
        ttk.Radiobutton(frame, text='常规事件', variable=var, value='normal').grid(row=1, column=0, sticky='w', pady=5)
        ttk.Radiobutton(frame, text='全天事件', variable=var, value='allday').grid(row=1, column=1, sticky='w')

        def save():
            value = entry.get().strip()
            if not value:
                messagebox.showwarning('警告', '请输入预设内容')
                return
            if var.get() == 'allday':
                self.preset_allday_reminders_listbox.insert('end', value)
            else:
                self.preset_reminders_listbox.insert('end', value)
            dialog.destroy()

        btn_frame = ttk.Frame(dialog); btn_frame.pack(side='bottom', pady=10)
        ttk.Button(btn_frame, text='确定', command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text='取消', command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def edit_preset_reminder(self):
        """编辑预设提醒"""
        normal_sel = self.preset_reminders_listbox.curselection()
        allday_sel = self.preset_allday_reminders_listbox.curselection()
        if not (normal_sel or allday_sel):
            messagebox.showinfo('提示', '请先选择一个预设')
            return
        
        # 获取当前值和列表引用
        if normal_sel:
            current = self.preset_reminders_listbox.get(normal_sel[0])
            listbox = self.preset_reminders_listbox
            index = normal_sel[0]
            reminder_type = 'normal'
        else:
            current = self.preset_allday_reminders_listbox.get(allday_sel[0])
            listbox = self.preset_allday_reminders_listbox
            index = allday_sel[0]
            reminder_type = 'allday'

        dialog = tk.Toplevel(self)
        dialog.title('编辑预设提醒')
        dialog.geometry('400x200')
        dialog.transient(self)
        dialog.grab_set()
        
        ttk.Label(dialog, text='预设格式（可选）:').pack(anchor='w', padx=10, pady=5)
        ttk.Label(dialog, text='- 提前提醒: "5分钟前", "1小时前"', foreground='gray').pack(anchor='w', padx=10)
        
        frame = ttk.Frame(dialog); frame.pack(fill='x', padx=10, pady=10)
        ttk.Label(frame, text='预设内容:').grid(row=0, column=0, sticky='w')
        entry = ttk.Entry(frame, width=30); entry.grid(row=0, column=1, sticky='we', padx=5)
        entry.insert(0, current)
        
        var = tk.StringVar(value=reminder_type)
        ttk.Radiobutton(frame, text='常规事件', variable=var, value='normal').grid(row=1, column=0, sticky='w', pady=5)
        ttk.Radiobutton(frame, text='全天事件', variable=var, value='allday').grid(row=1, column=1, sticky='w')

        def save():
            value = entry.get().strip()
            if not value:
                messagebox.showwarning('警告', '请输入预设内容')
                return
            # 删除原项并插入新项
            listbox.delete(index)
            if var.get() == 'allday':
                self.preset_allday_reminders_listbox.insert('end', value)
            else:
                self.preset_reminders_listbox.insert('end', value)
            dialog.destroy()

        btn_frame = ttk.Frame(dialog); btn_frame.pack(side='bottom', pady=10)
        ttk.Button(btn_frame, text='确定', command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text='取消', command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def delete_preset_reminder(self):
        normal_sel = self.preset_reminders_listbox.curselection()
        allday_sel = self.preset_allday_reminders_listbox.curselection()
        if normal_sel:
            self.preset_reminders_listbox.delete(normal_sel[0])
        elif allday_sel:
            self.preset_allday_reminders_listbox.delete(allday_sel[0])
        else:
            messagebox.showinfo('提示', '请先选择一个预设')

    def add_custom_default_reminder(self, is_allday):
        """添加自定义默认提醒"""
        dialog = tk.Toplevel(self)
        dialog.title('添加默认提醒')
        dialog.geometry('500x350')
        dialog.transient(self)
        dialog.grab_set()

        frame = ttk.Frame(dialog); frame.pack(fill='both', expand=True, padx=10, pady=10)

        ttk.Label(frame, text='提醒类型:').grid(row=0, column=0, sticky='w', padx=5, pady=5)
        type_var = tk.StringVar(value='显示')
        ttk.Combobox(frame, textvariable=type_var, values=['显示', '声音', '邮件'], state='readonly').grid(row=0, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(frame, text='触发方式:').grid(row=1, column=0, sticky='w', padx=5, pady=5)
        trigger_type_var = tk.StringVar(value='提前')
        ttk.Combobox(frame, textvariable=trigger_type_var, values=['提前', '指定时间'], state='readonly').grid(row=1, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(frame, text='时间设置:').grid(row=2, column=0, sticky='w', padx=5, pady=5)
        time_frame = ttk.Frame(frame); time_frame.grid(row=2, column=1, sticky='w', padx=5, pady=5)

        relative_frame = ttk.Frame(time_frame); relative_frame.grid(row=0, column=0, sticky='w')

        day_var = tk.StringVar(value='0')
        ttk.Label(relative_frame, text='天:').grid(row=0, column=0, sticky='w')
        ttk.Spinbox(relative_frame, from_=0, to=365, textvariable=day_var, width=3).grid(row=0, column=1, padx=2)

        hour_var = tk.StringVar(value='0')
        ttk.Label(relative_frame, text='小时:').grid(row=0, column=2, sticky='w')
        ttk.Spinbox(relative_frame, from_=0, to=23, textvariable=hour_var, width=3).grid(row=0, column=3, padx=2)

        minute_var = tk.StringVar(value='15')
        ttk.Label(relative_frame, text='分钟:').grid(row=0, column=4, sticky='w')
        ttk.Spinbox(relative_frame, from_=0, to=59, textvariable=minute_var, width=3).grid(row=0, column=5, padx=2)

        absolute_frame = ttk.Frame(time_frame)
        if is_allday:
            absolute_frame.grid(row=0, column=1, sticky='w')
            ttk.Label(absolute_frame, text='时间 (HH:MM):').grid(row=0, column=0, sticky='w')
            time_entry = ttk.Entry(absolute_frame, width=8); time_entry.grid(row=0, column=1, padx=5)
            time_entry.insert(0, '09:00')
            relative_frame.grid_remove()

        def on_trigger_change(*args):
            if trigger_type_var.get() == '指定时间' and is_allday:
                relative_frame.grid_remove()
                absolute_frame.grid(row=0, column=1, sticky='w')
            else:
                relative_frame.grid(row=0, column=0, sticky='w')
                if is_allday:
                    absolute_frame.grid_remove()

        trigger_type_var.trace('w', on_trigger_change)

        ttk.Label(frame, text='描述:').grid(row=3, column=0, sticky='w', padx=5, pady=5)
        desc_text = tk.Text(frame, height=3, width=40); desc_text.grid(row=3, column=1, sticky='nsew', padx=5, pady=5)

        def save():
            trigger_type = trigger_type_var.get()
            if trigger_type == '指定时间' and is_allday:
                time_str = time_entry.get()
                if not re.match(r'^\d{1,2}:\d{2}$', time_str):
                    messagebox.showwarning('警告', '时间格式不正确，应为 HH:MM')
                    return
            else:
                days, hours, minutes = day_var.get(), hour_var.get(), minute_var.get()
                if days == '0' and hours == '0' and minutes == '0':
                    messagebox.showwarning('警告', '提醒时间不能为0')
                    return
                time_str = ''
                if days != '0': time_str += f"{days}天"
                if hours != '0': time_str += f"{hours}小时"
                if minutes != '0': time_str += f"{minutes}分钟"

            reminder_str = f"{type_var.get()}:{trigger_type}:{time_str}:{desc_text.get('1.0', 'end').strip()}"
            if is_allday:
                self.custom_allday_default_reminders_listbox.insert('end', reminder_str)
            else:
                self.custom_default_reminders_listbox.insert('end', reminder_str)
            dialog.destroy()

        btn_frame = ttk.Frame(dialog); btn_frame.pack(side='bottom', fill='x', pady=10)
        ttk.Button(btn_frame, text='确定', command=save).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text='取消', command=dialog.destroy).pack(side=tk.RIGHT, padx=5)

    def edit_custom_default_reminder(self, is_allday):
        """编辑自定义默认提醒"""
        listbox = self.custom_allday_default_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        selection = listbox.curselection()
        if not selection:
            messagebox.showinfo('提示', '请先选择一个提醒')
            return

        current = listbox.get(selection[0])
        parts = current.split(':', 3)
        if len(parts) < 3:
            return

        action_str, trigger_type, time_str = parts[0], parts[1], parts[2]
        description = parts[3] if len(parts) > 3 else ''

        dialog = tk.Toplevel(self)
        dialog.title('编辑默认提醒')
        dialog.geometry('500x350')
        dialog.transient(self)
        dialog.grab_set()

        frame = ttk.Frame(dialog); frame.pack(fill='both', expand=True, padx=10, pady=10)

        ttk.Label(frame, text='提醒类型:').grid(row=0, column=0, sticky='w', padx=5, pady=5)
        type_var = tk.StringVar(value=action_str)
        ttk.Combobox(frame, textvariable=type_var, values=['显示', '声音', '邮件'], state='readonly').grid(row=0, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(frame, text='触发方式:').grid(row=1, column=0, sticky='w', padx=5, pady=5)
        trigger_type_var = tk.StringVar(value=trigger_type)
        ttk.Combobox(frame, textvariable=trigger_type_var, values=['提前', '指定时间'], state='readonly').grid(row=1, column=1, sticky='w', padx=5, pady=5)

        ttk.Label(frame, text='时间设置:').grid(row=2, column=0, sticky='w', padx=5, pady=5)
        time_frame = ttk.Frame(frame); time_frame.grid(row=2, column=1, sticky='w', padx=5, pady=5)

        relative_frame = ttk.Frame(time_frame); relative_frame.grid(row=0, column=0, sticky='w')

        day_var = tk.StringVar(value='0')
        ttk.Label(relative_frame, text='天:').grid(row=0, column=0, sticky='w')
        ttk.Spinbox(relative_frame, from_=0, to=365, textvariable=day_var, width=3).grid(row=0, column=1, padx=2)

        hour_var = tk.StringVar(value='0')
        ttk.Label(relative_frame, text='小时:').grid(row=0, column=2, sticky='w')
        ttk.Spinbox(relative_frame, from_=0, to=23, textvariable=hour_var, width=3).grid(row=0, column=3, padx=2)

        minute_var = tk.StringVar(value='15')
        ttk.Label(relative_frame, text='分钟:').grid(row=0, column=4, sticky='w')
        ttk.Spinbox(relative_frame, from_=0, to=59, textvariable=minute_var, width=3).grid(row=0, column=5, padx=2)

        absolute_frame = ttk.Frame(time_frame)
        if is_allday:
            absolute_frame.grid(row=0, column=1, sticky='w')
            ttk.Label(absolute_frame, text='时间 (HH:MM):').grid(row=0, column=0, sticky='w')
            time_entry = ttk.Entry(absolute_frame, width=8); time_entry.grid(row=0, column=1, padx=5)
            if ':' in time_str:
                time_entry.insert(0, time_str)
            else:
                time_entry.insert(0, '09:00')
            relative_frame.grid_remove()

        def on_trigger_change(*args):
            if trigger_type_var.get() == '指定时间' and is_allday:
                relative_frame.grid_remove()
                absolute_frame.grid(row=0, column=1, sticky='w')
            else:
                relative_frame.grid(row=0, column=0, sticky='w')
                if is_allday:
                    absolute_frame.grid_remove()

        trigger_type_var.trace('w', on_trigger_change)

        ttk.Label(frame, text='描述:').grid(row=3, column=0, sticky='w', padx=5, pady=5)
        desc_text = tk.Text(frame, height=3, width=40); desc_text.grid(row=3, column=1, sticky='nsew', padx=5, pady=5)
        desc_text.insert('1.0', description)

        def save():
            trigger_type = trigger_type_var.get()
            if trigger_type == '指定时间' and is_allday:
                time_str = time_entry.get()
                if not re.match(r'^\d{1,2}:\d{2}$', time_str):
                    messagebox.showwarning('警告', '时间格式不正确')
                    return
            else:
                days, hours, minutes = day_var.get(), hour_var.get(), minute_var.get()
                if days == '0' and hours == '0' and minutes == '0':
                    messagebox.showwarning('警告', '提醒时间不能为0')
                    return
                time_str = ''
                if days != '0': time_str += f"{days}天"
                if hours != '0': time_str += f"{hours}小时"
                if minutes != '0': time_str += f"{minutes}分钟"

            reminder_str = f"{type_var.get()}:{trigger_type}:{time_str}:{desc_text.get('1.0', 'end').strip()}"
            listbox.delete(selection[0])
            listbox.insert(selection[0], reminder_str)
            dialog.destroy()

        btn_frame = ttk.Frame(dialog); btn_frame.pack(side='bottom', fill='x', pady=10)
        ttk.Button(btn_frame, text='确定', command=save).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text='取消', command=dialog.destroy).pack(side=tk.RIGHT, padx=5)

    def delete_custom_default_reminder(self, is_allday):
        listbox = self.custom_allday_default_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        selection = listbox.curselection()
        if not selection:
            messagebox.showinfo('提示', '请先选择一个提醒')
            return
        listbox.delete(selection[0])

    def browse_log_file(self):
        p = filedialog.asksaveasfilename(title="选择日志文件", filetypes=[("日志文件", "*.log"), ("所有文件", "*.*")], defaultextension=".log")
        if p: self.log_path_var.set(p)

    def load_settings(self):
        s = self.db
        # 服务器设置
        self.auto_save_port_var.set(s.get_setting("auto_save_port", "True") == "True")
        self.auto_start_server_var.set(s.get_setting("auto_start_server", "False") == "True")
        self.default_port_var.set(s.get_setting("default_port", "8000"))

        # 日历基本设置
        status_en = s.get_setting("default_status", "CONFIRMED")
        self.default_status_var.set(next((k for k, v in EventDialog.STATUS_MAPPING.items() if v == status_en), "已确认"))
        self.default_version_var.set(s.get_setting("default_version", "2.0"))
        self.default_duration_var.set(s.get_setting("default_duration", "1"))
        self.default_priority_var.set(int(s.get_setting("default_priority", "5")))

        transp_en = s.get_setting("default_transparency", "OPAQUE")
        self.default_transparency_var.set(next((k for k, v in EventDialog.TRANSPARENCY_MAPPING.items() if v == transp_en), "忙碌"))

        self.default_sync_timezone_var.set(s.get_setting("default_sync_timezone", "True") == "True")
        self.default_repeat_var.set(s.get_setting("default_repeat", "不重复"))
        self.default_end_cond_var.set(s.get_setting("default_end_cond", "永不结束"))
        self.default_end_count_var.set(s.get_setting("default_end_count", "5"))
        self.default_allday_var.set(s.get_setting("default_allday", "False") == "True")
        self.default_force_reminder_var.set(s.get_setting("default_force_reminder", "False") == "True")

        # 加载预设提醒
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

        # 加载自定义默认提醒
        for key, lb in [('custom_default_reminders', self.custom_default_reminders_listbox),
                        ('custom_default_allday_reminders', self.custom_allday_default_reminders_listbox)]:
            val = s.get_setting(key, '')
            if val:
                for item in val.split(';'):
                    if item: lb.insert(tk.END, item)

        # 提醒基础参数加载
        self.default_reminder_type_var.set(s.get_setting("default_reminder_type", "显示"))
        self.default_trigger_type_var.set(s.get_setting("default_trigger_type", "提前时间提醒"))
        self.default_allday_reminder_time_var.set(s.get_setting("default_allday_reminder_time", "09:00"))
        self.default_reminder_days_var.set(s.get_setting("default_reminder_days", "0"))
        self.default_reminder_hours_var.set(s.get_setting("default_reminder_hours", "0"))
        self.default_reminder_minutes_var.set(s.get_setting("default_reminder_minutes", "15"))

        # 日志设置
        self.enable_log_file_var.set(s.get_setting("enable_log_file", "False") == "True")
        self.log_path_var.set(s.get_setting("log_file_path", "dav_server.log"))
        self.log_level_var.set(s.get_setting("log_level", "INFO"))

    def save_settings(self):
        s = self.db
        # 服务器设置
        s.set_setting("auto_save_port", str(self.auto_save_port_var.get()))
        s.set_setting("auto_start_server", str(self.auto_start_server_var.get()))
        s.set_setting("default_port", self.default_port_var.get())

        # 日历基本设置
        s.set_setting("default_status", EventDialog.STATUS_MAPPING.get(self.default_status_var.get(), "CONFIRMED"))
        s.set_setting("default_version", self.default_version_var.get())
        s.set_setting("default_duration", self.default_duration_var.get())
        s.set_setting("default_priority", str(self.default_priority_var.get()))
        s.set_setting("default_transparency", EventDialog.TRANSPARENCY_MAPPING.get(self.default_transparency_var.get(), "OPAQUE"))
        s.set_setting("default_sync_timezone", str(self.default_sync_timezone_var.get()))
        s.set_setting("default_repeat", self.default_repeat_var.get())
        s.set_setting("default_end_cond", self.default_end_cond_var.get())
        s.set_setting("default_end_count", self.default_end_count_var.get())
        s.set_setting("default_allday", str(self.default_allday_var.get()))
        s.set_setting("default_force_reminder", str(self.default_force_reminder_var.get()))

        # 保存预设提醒
        s.set_setting('preset_reminders', ';'.join([self.preset_reminders_listbox.get(i) for i in range(self.preset_reminders_listbox.size())]))
        s.set_setting('preset_allday_reminders', ';'.join([self.preset_allday_reminders_listbox.get(i) for i in range(self.preset_allday_reminders_listbox.size())]))

        # 保存默认勾选项
        s.set_setting('default_reminders', ';'.join([self.default_reminders_listbox.get(i) for i in self.default_reminders_listbox.curselection()]))
        s.set_setting('default_allday_reminders', ';'.join([self.default_allday_reminders_listbox.get(i) for i in self.default_allday_reminders_listbox.curselection()]))

        # 保存自定义默认提醒
        s.set_setting('custom_default_reminders', ';'.join([self.custom_default_reminders_listbox.get(i) for i in range(self.custom_default_reminders_listbox.size())]))
        s.set_setting('custom_default_allday_reminders', ';'.join([self.custom_allday_default_reminders_listbox.get(i) for i in range(self.custom_allday_default_reminders_listbox.size())]))

        # 提醒基础参数保存
        s.set_setting("default_reminder_type", self.default_reminder_type_var.get())
        s.set_setting("default_trigger_type", self.default_trigger_type_var.get())
        s.set_setting("default_allday_reminder_time", self.default_allday_reminder_time_var.get())
        s.set_setting("default_reminder_days", self.default_reminder_days_var.get())
        s.set_setting("default_reminder_hours", self.default_reminder_hours_var.get())
        s.set_setting("default_reminder_minutes", self.default_reminder_minutes_var.get())

        # 日志设置
        s.set_setting("enable_log_file", str(self.enable_log_file_var.get()))
        s.set_setting("log_file_path", self.log_path_var.get())
        s.set_setting("log_level", self.log_level_var.get())

        event_bus.publish(EVENT_SETTINGS_CHANGED)
        if self.on_save_callback: self.on_save_callback()
        self.destroy()
