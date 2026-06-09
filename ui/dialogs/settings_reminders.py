import tkinter as tk
from tkinter import ttk, messagebox
from datetime import timedelta
import json
from ui.dialogs.detailed_reminder_editor import DetailedReminderEditor, save_alarm_trigger, load_alarm_trigger
from models.constants import ALARM_ACTION_MAPPING, ALARM_ACTION_REV_MAPPING


class ReminderPresetSection:
    """预设提醒设置 — 从 SettingsDialog 提取"""

    def __init__(self, dialog):
        self.dialog = dialog
        self._custom_reminders_data = []
        self._custom_allday_reminders_data = []

    def create_ui(self, parent):
        p_m_f = ttk.LabelFrame(parent, text="管理预设项 (右键菜单内容)")
        p_m_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(p_m_f, text="常规预设:").grid(row=0, column=0, sticky="w", padx=5)
        p_r_f = ttk.Frame(p_m_f); p_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.preset_reminders_listbox = tk.Listbox(p_r_f, height=4, exportselection=False)
        self.preset_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_r_sb = ttk.Scrollbar(p_r_f, orient=tk.VERTICAL, command=self.preset_reminders_listbox.yview)
        p_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_reminders_listbox.config(yscrollcommand=p_r_sb.set)
        self.preset_reminders_listbox.bind("<Double-1>", lambda e: self._edit_preset_reminder())

        ttk.Label(p_m_f, text="全天预设:").grid(row=0, column=1, sticky="w", padx=5)
        p_a_f = ttk.Frame(p_m_f); p_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.preset_allday_reminders_listbox = tk.Listbox(p_a_f, height=4, exportselection=False)
        self.preset_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        p_a_sb = ttk.Scrollbar(p_a_f, orient=tk.VERTICAL, command=self.preset_allday_reminders_listbox.yview)
        p_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_allday_reminders_listbox.config(yscrollcommand=p_a_sb.set)
        self.preset_allday_reminders_listbox.bind("<Double-1>", lambda e: self._edit_preset_reminder())

        p_btn = ttk.Frame(p_m_f); p_btn.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Button(p_btn, text="添加预设", command=self._add_preset_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="编辑预设", command=self._edit_preset_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(p_btn, text="删除预设", command=self._delete_preset_reminder).pack(side=tk.LEFT, padx=2)

        a_c_f = ttk.LabelFrame(parent, text="新建日程时自动勾选")
        a_c_f.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(a_c_f, text="常规自动勾选:").grid(row=0, column=0, sticky="w", padx=5)
        d_r_f = ttk.Frame(a_c_f); d_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.default_reminders_listbox = tk.Listbox(d_r_f, selectmode='multiple', height=4, exportselection=False)
        self.default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_r_sb = ttk.Scrollbar(d_r_f, orient=tk.VERTICAL, command=self.default_reminders_listbox.yview)
        d_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.default_reminders_listbox.config(yscrollcommand=d_r_sb.set)
        for opt in ["日程发生时", "5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前", "2天前", "7天前"]:
            self.default_reminders_listbox.insert(tk.END, opt)

        ttk.Label(a_c_f, text="全天自动勾选:").grid(row=0, column=1, sticky="w", padx=5)
        d_a_f = ttk.Frame(a_c_f); d_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.default_allday_reminders_listbox = tk.Listbox(d_a_f, selectmode='multiple', height=4, exportselection=False)
        self.default_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        d_a_sb = ttk.Scrollbar(d_a_f, orient=tk.VERTICAL, command=self.default_allday_reminders_listbox.yview)
        d_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.default_allday_reminders_listbox.config(yscrollcommand=d_a_sb.set)
        for opt in ["当天上午9点", "1天前上午9点", "2天前上午9点", "3天前上午9点", "5天前上午9点", "7天前上午9点"]:
            self.default_allday_reminders_listbox.insert(tk.END, opt)

        c_d_f = ttk.LabelFrame(parent, text="自定义默认提醒 (新建日程时自动添加详情)")
        c_d_f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Label(c_d_f, text="常规自定义:").grid(row=0, column=0, sticky="w", padx=5)
        c_r_f = ttk.Frame(c_d_f); c_r_f.grid(row=1, column=0, padx=5, sticky="nsew")
        self.custom_default_reminders_listbox = tk.Listbox(c_r_f, height=3, exportselection=False)
        self.custom_default_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        c_r_sb = ttk.Scrollbar(c_r_f, orient=tk.VERTICAL, command=self.custom_default_reminders_listbox.yview)
        c_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_default_reminders_listbox.config(yscrollcommand=c_r_sb.set)
        self.custom_default_reminders_listbox.bind("<Double-1>", lambda e: self._edit_custom_default_reminder(False))

        ttk.Label(c_d_f, text="全天自定义:").grid(row=0, column=1, sticky="w", padx=5)
        c_a_f = ttk.Frame(c_d_f); c_a_f.grid(row=1, column=1, padx=5, sticky="nsew")
        self.custom_default_allday_reminders_listbox = tk.Listbox(c_a_f, height=3, exportselection=False)
        self.custom_default_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        c_a_sb = ttk.Scrollbar(c_a_f, orient=tk.VERTICAL, command=self.custom_default_allday_reminders_listbox.yview)
        c_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.custom_default_allday_reminders_listbox.config(yscrollcommand=c_a_sb.set)
        self.custom_default_allday_reminders_listbox.bind("<Double-1>", lambda e: self._edit_custom_default_reminder(True))

        c_btn = ttk.Frame(c_d_f); c_btn.grid(row=2, column=0, columnspan=2, sticky="ew", padx=5, pady=5)
        ttk.Button(c_btn, text="添加常规", command=lambda: self._add_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="编辑常规", command=lambda: self._edit_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="删除常规", command=lambda: self._delete_custom_default_reminder(False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="添加全天", command=lambda: self._add_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="编辑全天", command=lambda: self._edit_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(c_btn, text="删除全天", command=lambda: self._delete_custom_default_reminder(True)).pack(side=tk.LEFT, padx=2)

    # ── 预设提醒增删改 ──

    def _make_quick_buttons(self, parent, entry):
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

    def _add_preset_reminder(self):
        dialog = tk.Toplevel(self.dialog); dialog.title('添加预设提醒'); dialog.transient(self.dialog); dialog.grab_set()
        from utils.window_utils import center_window; center_window(dialog, self.dialog)
        ttk.Label(dialog, text="添加预设提醒", font=('Arial', 12, 'bold')).pack(anchor='w', padx=10, pady=(10, 0))
        ttk.Label(dialog, text="输入提醒触发时间，新建日程时可双击预设快速添加。", foreground="gray").pack(anchor='w', padx=10)
        ttk.Label(dialog, text="预设内容:").pack(anchor='w', padx=10, pady=(10, 0))
        entry = ttk.Entry(dialog, width=40); entry.pack(padx=10, pady=5, fill=tk.X)
        entry.focus_set()
        self._make_quick_buttons(dialog, entry)
        var = tk.StringVar(value='normal')
        rf = ttk.Frame(dialog); rf.pack(padx=10, pady=5, anchor='w')
        ttk.Radiobutton(rf, text='常规事件', variable=var, value='normal').pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(rf, text='全天事件', variable=var, value='allday').pack(side=tk.LEFT, padx=2)
        def _confirm(*_):
            v = entry.get().strip()
            if v:
                self._tmp_val = v; dialog.destroy()
        entry.bind("<Return>", _confirm)
        bf = ttk.Frame(dialog); bf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(bf, text='确定', command=_confirm).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text='取消', command=dialog.destroy).pack(side=tk.RIGHT, padx=2)
        dialog.wait_window()
        v = getattr(self, '_tmp_val', None)
        if v:
            lb = self.preset_allday_reminders_listbox if var.get() == 'allday' else self.preset_reminders_listbox
            lb.insert('end', v)

    def _edit_preset_reminder(self):
        n_sel = self.preset_reminders_listbox.curselection()
        a_sel = self.preset_allday_reminders_listbox.curselection()
        if not (n_sel or a_sel):
            messagebox.showinfo("提示", "请先选中要编辑的预设项")
            return
        lb = self.preset_reminders_listbox if n_sel else self.preset_allday_reminders_listbox
        idx = n_sel[0] if n_sel else a_sel[0]
        cur = lb.get(idx)
        dialog = tk.Toplevel(self.dialog); dialog.title('编辑预设提醒'); dialog.transient(self.dialog); dialog.grab_set()
        from utils.window_utils import center_window; center_window(dialog, self.dialog)
        ttk.Label(dialog, text="编辑预设提醒", font=('Arial', 12, 'bold')).pack(anchor='w', padx=10, pady=(10, 0))
        ttk.Label(dialog, text="修改提醒触发时间。", foreground="gray").pack(anchor='w', padx=10)
        ttk.Label(dialog, text="预设内容:").pack(anchor='w', padx=10, pady=(10, 0))
        entry = ttk.Entry(dialog, width=40); entry.insert(0, cur); entry.pack(padx=10, pady=5, fill=tk.X)
        entry.focus_set(); entry.selection_range(0, tk.END)
        self._make_quick_buttons(dialog, entry)
        def _confirm(*_):
            v = entry.get().strip()
            if v: lb.delete(idx); lb.insert(idx, v); dialog.destroy()
        entry.bind("<Return>", _confirm)
        bf = ttk.Frame(dialog); bf.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(bf, text='确定', command=_confirm).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bf, text='取消', command=dialog.destroy).pack(side=tk.RIGHT, padx=2)

    def _delete_preset_reminder(self):
        for lb in [self.preset_reminders_listbox, self.preset_allday_reminders_listbox]:
            sel = lb.curselection()
            if sel: lb.delete(sel[0]); return

    def _add_custom_default_reminder(self, is_allday):
        data_list = self._custom_allday_reminders_data if is_allday else self._custom_reminders_data
        listbox = self.custom_default_allday_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        def on_save(new_alarm):
            save_data = new_alarm.copy()
            save_data['trigger'] = save_alarm_trigger(save_data['trigger'])
            if 'duration' in save_data and isinstance(save_data['duration'], timedelta):
                save_data['duration'] = save_data['duration'].total_seconds()
            data_list.append(save_data)
            self._refresh_custom_listbox(listbox, data_list)
        DetailedReminderEditor(self.dialog, callback=on_save)

    def _edit_custom_default_reminder(self, is_allday):
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
        except Exception:
            initial_data = None
        def on_save(new_alarm):
            save_data = new_alarm.copy()
            save_data['trigger'] = save_alarm_trigger(save_data['trigger'])
            if 'duration' in save_data and isinstance(save_data['duration'], timedelta):
                save_data['duration'] = save_data['duration'].total_seconds()
            data_list[idx] = save_data
            self._refresh_custom_listbox(listbox, data_list)
        DetailedReminderEditor(self.dialog, initial_alarm=initial_data, callback=on_save)

    def _delete_custom_default_reminder(self, is_allday):
        data_list = self._custom_allday_reminders_data if is_allday else self._custom_reminders_data
        listbox = self.custom_default_allday_reminders_listbox if is_allday else self.custom_default_reminders_listbox
        sel = listbox.curselection()
        if sel:
            del data_list[sel[0]]
            self._refresh_custom_listbox(listbox, data_list)

    def _refresh_custom_listbox(self, listbox, data_list):
        listbox.delete(0, tk.END)
        for alarm_data in data_list:
            listbox.insert(tk.END, self._format_alarm_display(alarm_data))

    @staticmethod
    def _format_alarm_display(alarm_data):
        action = ALARM_ACTION_REV_MAPPING.get(alarm_data.get('action', ''), alarm_data.get('action', ''))
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
        if desc: result += f" | 描述: {desc}"
        return result

    def load(self):
        s = self.dialog.db
        for key, lb in [('preset_reminders', self.preset_reminders_listbox),
                        ('preset_allday_reminders', self.preset_allday_reminders_listbox)]:
            val = s.get_setting(key, '')
            if val:
                for item in val.split(';'):
                    if item: lb.insert(tk.END, item)
        self._custom_reminders_data = []
        self._custom_allday_reminders_data = []
        for key, data_list, lb in [
            ('custom_default_reminders', self._custom_reminders_data, self.custom_default_reminders_listbox),
            ('custom_default_allday_reminders', self._custom_allday_reminders_data, self.custom_default_allday_reminders_listbox)
        ]:
            val = s.get_setting(key, '')
            if val:
                for item_str in val.split(';'):
                    if not item_str: continue
                    if not item_str.startswith('{'):
                        parts = item_str.split(':', 3)
                        if len(parts) >= 3:
                            act = ALARM_ACTION_MAPPING.get(parts[0], "DISPLAY")
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
                    except Exception:
                        data_list.append({'action': 'DISPLAY', 'trigger': {'type': 'td', 'seconds': -900}, 'description': item_str})
            self._refresh_custom_listbox(lb, data_list)

        for key, lb in [('default_reminders', self.default_reminders_listbox),
                        ('default_allday_reminders', self.default_allday_reminders_listbox)]:
            sel_str = s.get_setting(key, '')
            for i in range(lb.size()):
                if lb.get(i) in sel_str.split(';'): lb.selection_set(i)

    def reset(self):
        self.preset_reminders_listbox.delete(0, tk.END)
        for p in ["5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前"]:
            self.preset_reminders_listbox.insert(tk.END, p)
        self.preset_allday_reminders_listbox.delete(0, tk.END)
        for p in ["日程发生时", "1天前", "2天前", "7天前"]:
            self.preset_allday_reminders_listbox.insert(tk.END, p)
        self.default_reminders_listbox.selection_clear(0, tk.END)
        self.default_allday_reminders_listbox.selection_clear(0, tk.END)
        self._custom_reminders_data.clear()
        self._custom_allday_reminders_data.clear()
        self.custom_default_reminders_listbox.delete(0, tk.END)
        self.custom_default_allday_reminders_listbox.delete(0, tk.END)

    def save(self):
        s = self.dialog.db
        s.set_setting('preset_reminders', ';'.join([self.preset_reminders_listbox.get(i) for i in range(self.preset_reminders_listbox.size())]))
        s.set_setting('preset_allday_reminders', ';'.join([self.preset_allday_reminders_listbox.get(i) for i in range(self.preset_allday_reminders_listbox.size())]))
        s.set_setting('default_reminders', ';'.join([self.default_reminders_listbox.get(i) for i in self.default_reminders_listbox.curselection()]))
        s.set_setting('default_allday_reminders', ';'.join([self.default_allday_reminders_listbox.get(i) for i in self.default_allday_reminders_listbox.curselection()]))
        s.set_setting('custom_default_reminders', ';'.join([json.dumps(item, ensure_ascii=False) for item in self._custom_reminders_data]))
        s.set_setting('custom_default_allday_reminders', ';'.join([json.dumps(item, ensure_ascii=False) for item in self._custom_allday_reminders_data]))
