import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from ui.widgets.right_click_menu import RightClickMenu
from ui.dialogs.event_dialog import EventDialog, DetailedReminderEditor, save_alarm_trigger, load_alarm_trigger
from utils.event_bus import event_bus, EVENT_SETTINGS_CHANGED
import re
import json
from datetime import datetime, timedelta
import pytz
from utils.timezone_helper import TimezoneHelper


class SettingsDialog(tk.Toplevel):
    """系统设置对话框 - 完整功能实现"""
    def __init__(self, parent, db_service, on_save_callback):
        super().__init__(parent)
        self.title("设置")
        self.geometry("800x750")
        self.transient(parent)
        self.grab_set()
        self.db = db_service
        self.on_save_callback = on_save_callback
        self._custom_reminders_data = []
        self._custom_allday_reminders_data = []

        main_frame = ttk.Frame(self); main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook = ttk.Notebook(main_frame); notebook.pack(fill=tk.BOTH, expand=True)

        server_frame = ttk.Frame(notebook); notebook.add(server_frame, text="服务器设置")
        calendar_frame = ttk.Frame(notebook); notebook.add(calendar_frame, text="日历设置")
        log_frame = ttk.Frame(notebook); notebook.add(log_frame, text="日志设置")

        self.create_server_settings(server_frame)
        self.create_calendar_settings(calendar_frame)
        self.create_log_settings(log_frame)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
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

        # ==================== 预设提醒 (p_t) ====================
        self.create_preset_settings(p_t)

    def create_preset_settings(self, parent):
        # 1. 预设列表管理
        p_m_f = ttk.LabelFrame(parent, text="管理预设项 (右键菜单内容)")
        p_m_f.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(p_m_f, text="常规预设:").grid(row=0, column=0, sticky="w", padx=5)
        p_r_f = ttk.Frame(p_m_f); p_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.preset_reminders_listbox = tk.Listbox(p_r_f, height=4, exportselection=False)
        self.preset_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_r_sb = ttk.Scrollbar(p_r_f, orient=tk.VERTICAL, command=self.preset_reminders_listbox.yview)
        p_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_reminders_listbox.config(yscrollcommand=p_r_sb.set)
        self.preset_reminders_listbox.bind("<Double-1>", lambda e: self.edit_preset_reminder())

        ttk.Label(p_m_f, text="全天预设:").grid(row=0, column=1, sticky="w", padx=5)
        p_a_f = ttk.Frame(p_m_f); p_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.preset_allday_reminders_listbox = tk.Listbox(p_a_f, height=4, exportselection=False)
        self.preset_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_a_sb = ttk.Scrollbar(p_a_f, orient=tk.VERTICAL, command=self.preset_allday_reminders_listbox.yview)
        p_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_allday_reminders_listbox.config(yscrollcommand=p_a_sb.set)
        self.preset_allday_reminders_listbox.bind("<Double-1>", lambda e: self.edit_preset_reminder())

        p_btn = ttk.Frame(p_m_f); p_btn.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Button(p_btn, text="添加预设", command=self.add_preset_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="编辑预设", command=self.edit_preset_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="删除预设", command=self.delete_preset_reminder).pack(side=tk.LEFT, padx=2)

        # 2. 自动勾选项
        a_c_f = ttk.LabelFrame(parent, text="新建日程时自动勾选")
        a_c_f.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(a_c_f, text="常规自动勾选:").grid(row=0, column=0, sticky="w", padx=5)
        d_r_f = ttk.Frame(a_c_f); d_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.default_reminders_listbox = tk.Listbox(d_r_f, selectmode='multiple', height=4, exportselection=False)
        self.default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_r_sb = ttk.Scrollbar(d_r_f, orient=tk.VERTICAL, command=self.default_reminders_listbox.yview)
        d_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.default_reminders_listbox.config(yscrollcommand=d_r_sb.set)
        opts = ["日程发生时", "5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前", "2天前", "7天前"]
        for opt in opts: self.default_reminders_listbox.insert(tk.END, opt)

        ttk.Label(a_c_f, text="全天自动勾选:").grid(row=0, column=1, sticky="w", padx=5)
        d_a_f = ttk.Frame(a_c_f); d_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.default_allday_reminders_listbox = tk.Listbox(d_a_f, selectmode='multiple', height=4, exportselection=False)
        self.default_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_a_sb = ttk.Scrollbar(d_a_f, orient=tk.VERTICAL, command=self.default_allday_reminders_listbox.yview)
        d_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.default_allday_reminders_listbox.config(yscrollcommand=d_a_sb.set)
        allday_opts = ["当天上午9点", "1天前上午9点", "2天前上午9点", "3天前上午9点", "5天前上午9点", "7天前上午9点"]
        for opt in allday_opts: self.default_allday_reminders_listbox.insert(tk.END, opt)

        # 3. 自定义默认提醒
        c_d_f = ttk.LabelFrame(parent, text="自定义默认提醒 (新建日程时自动添加详情)")
        c_d_f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(c_d_f, text="常规自定义:").grid(row=0, column=0, sticky="w", padx=5)
        c_r_f = ttk.Frame(c_d_f); c_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.custom_default_reminders_listbox = tk.Listbox(c_r_f, height=3, exportselection=False)
        self.custom_default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        c_r_sb = ttk.Scrollbar(c_r_f, orient=tk.VERTICAL, command=self.custom_default_reminders_listbox.yview)
        c_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_default_reminders_listbox.config(yscrollcommand=c_r_sb.set)
        self.custom_default_reminders_listbox.bind("<Double-1>", lambda e: self.edit_custom_default_reminder(False))

        ttk.Label(c_d_f, text="全天自定义:").grid(row=0, column=1, sticky="w", padx=5)
        c_a_f = ttk.Frame(c_d_f); c_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.custom_default_allday_reminders_listbox = tk.Listbox(c_a_f, height=3, exportselection=False)
        self.custom_default_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        c_a_sb = ttk.Scrollbar(c_a_f, orient=tk.VERTICAL, command=self.custom_default_allday_reminders_listbox.yview)
        c_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_default_allday_reminders_listbox.config(yscrollcommand=c_a_sb.set)
        self.custom_default_allday_reminders_listbox.bind("<Double-1>", lambda e: self.edit_custom_default_reminder(True))

        c_btn = ttk.Frame(c_d_f); c_btn.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
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

    def _make_preset_quick_buttons(self, parent, entry):
        common = ["5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前", "2天前", "7天前"]
        allday_common = ["日程发生时", "当天上午9点", "1天前上午9点", "2天前上午9点", "7天前上午9点"]
        qf = ttk.LabelFrame(parent, text="常用预设 (点击快速填入)")
        qf.pack(fill=tk.X, padx=10, pady=5)
        nf = ttk.Frame(qf); nf.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(nf, text="常规:", font=('', 9)).pack(side=tk.LEFT)
        for t in common:
            ttk.Button(nf, text=t, width=10,
                       command=lambda v=t: [entry.delete(0, tk.END), entry.insert(0, v)]).pack(side=tk.LEFT, padx=1)
        af = ttk.Frame(qf); af.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(af, text="全天:", font=('', 9)).pack(side=tk.LEFT)
        for t in allday_common:
            ttk.Button(af, text=t, width=14,
                       command=lambda v=t: [entry.delete(0, tk.END), entry.insert(0, v)]).pack(side=tk.LEFT, padx=1)

    def add_preset_reminder(self):
        dialog = tk.Toplevel(self); dialog.title('添加预设提醒'); dialog.transient(self); dialog.grab_set(); dialog.geometry("520x300")
        ttk.Label(dialog, text="添加预设提醒", font=('Arial', 12, 'bold')).pack(anchor='w', padx=10, pady=(10, 0))
        ttk.Label(dialog, text="输入提醒触发时间，新建日程时可双击预设快速添加。", foreground="gray").pack(anchor='w', padx=10)
        ttk.Label(dialog, text="预设内容:").pack(anchor='w', padx=10, pady=(10, 0))
        entry = ttk.Entry(dialog, width=40); entry.pack(padx=10, pady=5, fill=tk.X)
        entry.focus_set()
        self._make_preset_quick_buttons(dialog, entry)
        var = tk.StringVar(value='normal')
        rf = ttk.Frame(dialog); rf.pack(padx=10, pady=5, anchor='w')
        ttk.Radiobutton(rf, text='常规事件', variable=var, value='normal').pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(rf, text='全天事件', variable=var, value='allday').pack(side=tk.LEFT, padx=2)
        bf = ttk.Frame(dialog); bf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(bf, text='确定', command=lambda: [
            setattr(self, '_tmp_preset_val', entry.get().strip()) if entry.get().strip() else None,
            dialog.destroy() if entry.get().strip() else None
        ][-1]).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text='取消', command=dialog.destroy).pack(side=tk.RIGHT, padx=2)
        dialog.wait_window()
        v = getattr(self, '_tmp_preset_val', None)
        if v:
            lb = self.preset_allday_reminders_listbox if var.get() == 'allday' else self.preset_reminders_listbox
            lb.insert('end', v)

    def edit_preset_reminder(self):
        n_sel = self.preset_reminders_listbox.curselection()
        a_sel = self.preset_allday_reminders_listbox.curselection()
        if not (n_sel or a_sel):
            messagebox.showinfo("提示", "请先选中要编辑的预设项")
            return
        lb = self.preset_reminders_listbox if n_sel else self.preset_allday_reminders_listbox
        idx = n_sel[0] if n_sel else a_sel[0]
        cur = lb.get(idx)
        dialog = tk.Toplevel(self); dialog.title('编辑预设提醒'); dialog.transient(self); dialog.grab_set(); dialog.geometry("520x300")
        ttk.Label(dialog, text="编辑预设提醒", font=('Arial', 12, 'bold')).pack(anchor='w', padx=10, pady=(10, 0))
        ttk.Label(dialog, text="修改提醒触发时间。", foreground="gray").pack(anchor='w', padx=10)
        ttk.Label(dialog, text="预设内容:").pack(anchor='w', padx=10, pady=(10, 0))
        entry = ttk.Entry(dialog, width=40); entry.insert(0, cur); entry.pack(padx=10, pady=5, fill=tk.X)
        entry.focus_set(); entry.selection_range(0, tk.END)
        self._make_preset_quick_buttons(dialog, entry)
        bf = ttk.Frame(dialog); bf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(bf, text='确定', command=lambda: [
            lb.delete(idx), lb.insert(idx, entry.get().strip()), dialog.destroy()
        ] if entry.get().strip() else None).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text='取消', command=dialog.destroy).pack(side=tk.RIGHT, padx=2)

    def delete_preset_reminder(self):
        for lb in [self.preset_reminders_listbox, self.preset_allday_reminders_listbox]:
            sel = lb.curselection()
            if sel: lb.delete(sel[0]); return

    def add_custom_default_reminder(self, is_allday):
        data_list = self._custom_allday_reminders_data if is_allday else self._custom_reminders_data
        listbox = self.custom_default_allday_reminders_listbox if is_allday else self.custom_default_reminders_listbox

        def on_save(new_alarm):
            save_data = new_alarm.copy()
            save_data['trigger'] = save_alarm_trigger(save_data['trigger'])
            if 'duration' in save_data and isinstance(save_data['duration'], timedelta):
                save_data['duration'] = save_data['duration'].total_seconds()
            data_list.append(save_data)
            self._refresh_custom_listbox(listbox, data_list)

        DetailedReminderEditor(self, callback=on_save)

    def edit_custom_default_reminder(self, is_allday):
        data_list = self._custom_allday_reminders_data if is_allday else self._custom_reminders_data
        listbox = self.custom_default_allday_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        sel = listbox.curselection()
        if not sel: return

        idx = sel[0]
        try:
            initial_data = data_list[idx].copy()
            initial_data['trigger'] = load_alarm_trigger(initial_data.get('trigger'))
            if 'duration' in initial_data and isinstance(initial_data['duration'], (int, float)):
                initial_data['duration'] = timedelta(seconds=initial_data['duration'])
        except:
            initial_data = None

        def on_save(new_alarm):
            save_data = new_alarm.copy()
            save_data['trigger'] = save_alarm_trigger(save_data['trigger'])
            if 'duration' in save_data and isinstance(save_data['duration'], timedelta):
                save_data['duration'] = save_data['duration'].total_seconds()
            data_list[idx] = save_data
            self._refresh_custom_listbox(listbox, data_list)

        DetailedReminderEditor(self, initial_alarm=initial_data, callback=on_save)

    def delete_custom_default_reminder(self, is_allday):
        data_list = self._custom_allday_reminders_data if is_allday else self._custom_reminders_data
        listbox = self.custom_default_allday_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        sel = listbox.curselection()
        if sel:
            del data_list[sel[0]]
            self._refresh_custom_listbox(listbox, data_list)

    def browse_log_file(self):
        p = filedialog.asksaveasfilename(title="选择日志文件", filetypes=[("日志文件", "*.log"), ("所有文件", "*.*")], defaultextension=".log")
        if p: self.log_path_var.set(p)

    @staticmethod
    def _format_alarm_display(alarm_data):
        action_map = {"DISPLAY": "显示", "AUDIO": "声音", "EMAIL": "邮件"}
        action = action_map.get(alarm_data.get('action', ''), alarm_data.get('action', ''))
        trigger = alarm_data.get('trigger', {})
        if isinstance(trigger, dict):
            t_type = trigger.get('type')
            if t_type == 'td':
                seconds = trigger.get('seconds', 0)
                prefix = "前" if seconds < 0 else ""
                seconds = abs(seconds)
                days = int(seconds // 86400)
                hours = int((seconds % 86400) // 3600)
                mins = int((seconds % 3600) // 60)
                parts = []
                if days: parts.append(f"{days}天")
                if hours: parts.append(f"{hours}小时")
                if mins: parts.append(f"{mins}分钟")
                trigger_str = "".join(parts) + prefix if parts else ("发生时" if prefix else str(seconds))
            elif t_type == 'dt':
                trigger_str = trigger.get('iso', '')
            else:
                trigger_str = str(trigger)
        elif isinstance(trigger, str):
            trigger_str = trigger
        else:
            trigger_str = str(trigger)
        desc = alarm_data.get('description', '')
        result = f"{action} - {trigger_str}"
        if desc:
            result += f" | 描述: {desc}"
        return result

    def _refresh_custom_listbox(self, listbox, data_list):
        listbox.delete(0, tk.END)
        for alarm_data in data_list:
            listbox.insert(tk.END, self._format_alarm_display(alarm_data))

    def load_settings(self):
        s = self.db
        self.auto_save_port_var.set(s.get_setting("auto_save_port", "True") == "True")
        self.auto_start_server_var.set(s.get_setting("auto_start_server", "False") == "True")
        self.default_port_var.set(s.get_setting("default_port", "8000"))
        self.default_status_var.set(next((k for k, v in EventDialog.STATUS_MAPPING.items() if v == s.get_setting("default_status", "CONFIRMED")), "已确认"))
        self.default_version_var.set(s.get_setting("default_version", "2.0"))
        self.default_duration_var.set(s.get_setting("default_duration", "1"))
        p = int(s.get_setting("default_priority", "5")); self.default_priority_var.set(p); self.default_priority_label.config(text=f" {p} ")
        self.default_transparency_var.set(next((k for k, v in EventDialog.TRANSPARENCY_MAPPING.items() if v == s.get_setting("default_transparency", "OPAQUE")), "忙碌"))
        self.default_sync_timezone_var.set(s.get_setting("default_sync_timezone", "True") == "True")
        self.default_repeat_var.set(s.get_setting("default_repeat", "不重复"))
        self.default_end_cond_var.set(s.get_setting("default_end_cond", "永不结束"))
        self.default_end_count_var.set(s.get_setting("default_end_count", "5"))
        self.default_allday_var.set(s.get_setting("default_allday", "False") == "True")
        self.default_force_reminder_var.set(s.get_setting("default_force_reminder", "False") == "True")
        for key, lb in [('preset_reminders', self.preset_reminders_listbox), ('preset_allday_reminders', self.preset_allday_reminders_listbox)]:
            val = s.get_setting(key, '')
            if val:
                for item in val.split(';'):
                    if item: lb.insert(tk.END, item)
        
        # 加载自定义 JSON 格式提醒
        self._custom_reminders_data = []
        self._custom_allday_reminders_data = []
        for key, data_list, lb in [
            ('custom_default_reminders', self._custom_reminders_data, self.custom_default_reminders_listbox),
            ('custom_default_allday_reminders', self._custom_allday_reminders_data, self.custom_default_allday_reminders_listbox)
        ]:
            val = s.get_setting(key, '')
            if val:
                for item_str in val.split(';'):
                    if not item_str:
                        continue
                    # 尝试转换旧格式到新 JSON 格式 (平滑迁移)
                    if not item_str.startswith('{'):
                        parts = item_str.split(':', 3)
                        if len(parts) >= 3:
                            act = {"显示": "DISPLAY", "声音": "AUDIO", "邮件": "EMAIL"}.get(parts[0], "DISPLAY")
                            trig_str = parts[2]
                            if ":" in trig_str:
                                h, m = map(int, trig_str.split(':'))
                                t_val = {'type': 'td', 'seconds': h*3600 + m*60}
                            else:
                                t_val = {'type': 'td', 'seconds': -900}
                            item_str = json.dumps({'action': act, 'trigger': t_val, 'description': parts[3] if len(parts)>3 else ""}, ensure_ascii=False)
                    try:
                        alarm_data = json.loads(item_str)
                        data_list.append(alarm_data)
                    except:
                        data_list.append({'action': 'DISPLAY', 'trigger': {'type': 'td', 'seconds': -900}, 'description': item_str})
            self._refresh_custom_listbox(lb, data_list)

        for key, lb in [('default_reminders', self.default_reminders_listbox), ('default_allday_reminders', self.default_allday_reminders_listbox)]:
            sel_str = s.get_setting(key, ''); sel_list = sel_str.split(';')
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
        s.set_setting("default_repeat", self.default_repeat_var.get())
        s.set_setting("default_end_cond", self.default_end_cond_var.get())
        s.set_setting("default_end_count", self.default_end_count_var.get())
        s.set_setting("default_allday", str(self.default_allday_var.get()))
        s.set_setting("default_force_reminder", str(self.default_force_reminder_var.get()))
        s.set_setting('preset_reminders', ';'.join([self.preset_reminders_listbox.get(i) for i in range(self.preset_reminders_listbox.size())]))
        s.set_setting('preset_allday_reminders', ';'.join([self.preset_allday_reminders_listbox.get(i) for i in range(self.preset_allday_reminders_listbox.size())]))
        s.set_setting('default_reminders', ';'.join([self.default_reminders_listbox.get(i) for i in self.default_reminders_listbox.curselection()]))
        s.set_setting('default_allday_reminders', ';'.join([self.default_allday_reminders_listbox.get(i) for i in self.default_allday_reminders_listbox.curselection()]))
        s.set_setting('custom_default_reminders', ';'.join([json.dumps(item, ensure_ascii=False) for item in self._custom_reminders_data]))
        s.set_setting('custom_default_allday_reminders', ';'.join([json.dumps(item, ensure_ascii=False) for item in self._custom_allday_reminders_data]))
        s.set_setting("enable_log_file", str(self.enable_log_file_var.get()))
        s.set_setting("log_file_path", self.log_path_var.get())
        s.set_setting("log_level", self.log_level_var.get())
        event_bus.publish(EVENT_SETTINGS_CHANGED)
        if self.on_save_callback:
            self.on_save_callback()
        self.destroy()
