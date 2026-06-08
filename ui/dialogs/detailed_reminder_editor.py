import tkinter as tk
from tkinter import ttk, messagebox
import pytz
import re
from datetime import datetime, timedelta
from tkcalendar import DateEntry
from ui.widgets.right_click_menu import RightClickMenu
from utils.logger import logger
from utils.timezone_helper import TimezoneHelper
from models.constants import ALARM_ACTION_MAPPING, ALARM_ACTION_REV_MAPPING


class DetailedReminderEditor(tk.Toplevel):
    """精细化提醒编辑器 (独立窗口)"""
    def __init__(self, parent, initial_alarm=None, callback=None):
        super().__init__(parent)
        self.title("编辑提醒" if initial_alarm else "添加提醒")
        self.transient(parent); self.grab_set()
        self.callback = callback
        self.initial_alarm = initial_alarm
        self.create_widgets()
        if initial_alarm: self.load_data(initial_alarm)
        from utils.window_utils import center_window
        center_window(self, parent)

    def create_widgets(self):
        main_f = ttk.Frame(self); main_f.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        basic_f = ttk.LabelFrame(main_f, text="提醒基本设置"); basic_f.pack(fill=tk.X, pady=5)
        ttk.Label(basic_f, text="提醒类型:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.rem_type_var = tk.StringVar(value="显示")
        ttk.Combobox(basic_f, textvariable=self.rem_type_var, values=["显示", "声音", "邮件"], state="readonly", width=10).grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(basic_f, text="触发方式:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.trig_type_var = tk.StringVar(value="relative")
        ttk.Radiobutton(basic_f, text="提前时间", variable=self.trig_type_var, value="relative").grid(row=1, column=1, sticky="w", padx=5)
        ttk.Radiobutton(basic_f, text="指定时间", variable=self.trig_type_var, value="absolute").grid(row=1, column=2, sticky="w", padx=5)

        self.rel_f = ttk.Frame(basic_f); self.rel_f.grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        self.days_v = tk.StringVar(value="0"); self.hours_v = tk.StringVar(value="0"); self.mins_v = tk.StringVar(value="15")
        ttk.Label(self.rel_f, text="天:").pack(side=tk.LEFT)
        ttk.Spinbox(self.rel_f, from_=0, to=365, textvariable=self.days_v, width=3).pack(side=tk.LEFT, padx=2)
        ttk.Label(self.rel_f, text="时:").pack(side=tk.LEFT)
        ttk.Spinbox(self.rel_f, from_=0, to=23, textvariable=self.hours_v, width=3).pack(side=tk.LEFT, padx=2)
        ttk.Label(self.rel_f, text="分:").pack(side=tk.LEFT)
        ttk.Spinbox(self.rel_f, from_=0, to=59, textvariable=self.mins_v, width=3).pack(side=tk.LEFT, padx=2)

        self.abs_f = ttk.Frame(basic_f); self.abs_f.grid(row=3, column=0, columnspan=3, sticky="w", padx=5, pady=5); self.abs_f.grid_remove()
        self.abs_d = DateEntry(self.abs_f, date_pattern='yyyy-mm-dd', width=12); self.abs_d.pack(side=tk.LEFT, padx=2)
        self.abs_h = ttk.Combobox(self.abs_f, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly"); self.abs_h.pack(side=tk.LEFT, padx=2); self.abs_h.set("09")
        ttk.Label(self.abs_f, text=":").pack(side=tk.LEFT)
        self.abs_m = ttk.Combobox(self.abs_f, width=3, values=[f"{m:02d}" for m in range(0, 60, 5)], state="readonly"); self.abs_m.pack(side=tk.LEFT, padx=2); self.abs_m.set("00")
        tz_list = TimezoneHelper.get_localized_timezones()
        self.abs_tz_v = tk.StringVar(value=TimezoneHelper.get_timezone_display_name(TimezoneHelper.get_local_timezone_id()))
        ttk.Combobox(self.abs_f, textvariable=self.abs_tz_v, values=tz_list, width=25, state="readonly").pack(side=tk.LEFT, padx=2)

        def toggle_t(*args):
            if self.trig_type_var.get() == "relative": self.rel_f.grid(); self.abs_f.grid_remove()
            else: self.rel_f.grid_remove(); self.abs_f.grid()
        self.trig_type_var.trace("w", toggle_t)

        rep_f = ttk.Frame(basic_f); rep_f.grid(row=4, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        self.rep_v = tk.StringVar(value="0"); self.dur_v = tk.StringVar(value="15")
        ttk.Label(rep_f, text="重复次数:").pack(side=tk.LEFT)
        ttk.Spinbox(rep_f, from_=0, to=99, textvariable=self.rep_v, width=3).pack(side=tk.LEFT, padx=2)
        ttk.Label(rep_f, text="间隔(分):").pack(side=tk.LEFT, padx=(10,0))
        ttk.Spinbox(rep_f, from_=1, to=1440, textvariable=self.dur_v, width=5).pack(side=tk.LEFT, padx=2)

        ext_f = ttk.LabelFrame(main_f, text="提醒内容详情"); ext_f.pack(fill=tk.BOTH, expand=True, pady=5)

        disp_f = ttk.Frame(ext_f); disp_f.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(disp_f, text="描述:").pack(side=tk.LEFT)
        self.desc_t = tk.Text(disp_f, height=3, width=40); self.desc_t.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5); RightClickMenu(self.desc_t, "text")

        self.audio_f = ttk.Frame(ext_f); self.audio_f.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(self.audio_f, text="音频:").pack(side=tk.LEFT)
        self.attach_v = tk.StringVar(); ttk.Entry(self.audio_f, textvariable=self.attach_v).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.mail_f = ttk.Frame(ext_f); self.mail_f.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(self.mail_f, text="收件人:").pack(side=tk.LEFT)
        self.mail_to_v = tk.StringVar(); ttk.Entry(self.mail_f, textvariable=self.mail_to_v).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Label(self.mail_f, text="主题:").pack(side=tk.LEFT)
        self.mail_sub_v = tk.StringVar(); ttk.Entry(self.mail_f, textvariable=self.mail_sub_v).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        def update_ext_ui(*args):
            t = self.rem_type_var.get()
            for f, target in [(self.audio_f, "声音"), (self.mail_f, "邮件")]:
                if t == target: f.pack(fill=tk.X, padx=5, pady=2)
                else: f.pack_forget()
        self.rem_type_var.trace("w", update_ext_ui); update_ext_ui()

        ttk.Button(main_f, text="保存提醒", command=self.save).pack(pady=10)

    def load_data(self, a):
        self.rem_type_var.set(ALARM_ACTION_REV_MAPPING.get(a.get('action'), "显示"))
        tr = a.get('trigger')
        if isinstance(tr, datetime):
            self.trig_type_var.set("absolute")
            try:
                local_dt = tr.astimezone(pytz.timezone(TimezoneHelper.get_local_timezone_id()))
                self.abs_d.set_date(local_dt.date()); self.abs_h.set(local_dt.strftime("%H")); self.abs_m.set(local_dt.strftime("%M"))
            except Exception:
                logger.debug("闹钟时间解析失败")
        elif isinstance(tr, timedelta):
            self.trig_type_var.set("relative")
            sec = abs(tr.total_seconds())
            self.days_v.set(int(sec // 86400)); self.hours_v.set(int((sec % 86400) // 3600)); self.mins_v.set(int((sec % 3600) // 60))
        if 'description' in a: self.desc_t.insert("1.0", a['description'])
        if 'attach' in a: self.attach_v.set(a['attach'])
        if 'attendee' in a: self.mail_to_v.set(a['attendee'])
        if 'summary' in a: self.mail_sub_v.set(a['summary'])
        if 'repeat' in a: self.rep_v.set(a['repeat'])
        if 'duration' in a:
            d = a['duration']
            if isinstance(d, timedelta): self.dur_v.set(str(int(d.total_seconds() // 60)))
            elif isinstance(d, str) and 'PT' in d: self.dur_v.set(d.replace('PT', '').replace('M', ''))

    def save(self):
        try:
            act = ALARM_ACTION_MAPPING.get(self.rem_type_var.get(), "DISPLAY")
            if self.trig_type_var.get() == "relative":
                d, h, m = int(self.days_v.get() or 0), int(self.hours_v.get() or 0), int(self.mins_v.get() or 0)
                trig = -timedelta(days=d, hours=h, minutes=m)
            else:
                try:
                    tz_id = TimezoneHelper.extract_tz_id(self.abs_tz_v.get())
                    dt_naive = datetime.combine(self.abs_d.get_date(), datetime.strptime(f"{self.abs_h.get()}:{self.abs_m.get()}", "%H:%M").time())
                    trig = pytz.timezone(tz_id).localize(dt_naive).astimezone(pytz.UTC)
                except Exception: messagebox.showerror("错误", "时间格式非法", parent=self); return

            new_a = {'action': act, 'trigger': trig, 'description': self.desc_t.get("1.0", "end-1c").strip()}
            if self.attach_v.get(): new_a['attach'] = self.attach_v.get()
            if self.mail_to_v.get(): new_a['attendee'] = self.mail_to_v.get()
            if self.mail_sub_v.get(): new_a['summary'] = self.mail_sub_v.get()
            try:
                rc = int(self.rep_v.get() or 0)
                if rc > 0: new_a['repeat'] = rc; new_a['duration'] = timedelta(minutes=int(self.dur_v.get() or 15))
            except Exception:
                logger.debug("忽略异常")

            if self.callback: self.callback(new_a)
            self.destroy()
        except Exception as e: messagebox.showerror("保存失败", f"数据验证未通过: {e}", parent=self)


def save_alarm_trigger(trig):
    if isinstance(trig, timedelta): return {'type': 'td', 'seconds': trig.total_seconds()}
    if isinstance(trig, datetime): return {'type': 'dt', 'iso': trig.isoformat()}
    return trig


def load_alarm_trigger(trig_data):
    if isinstance(trig_data, dict):
        if trig_data.get('type') == 'td': return timedelta(seconds=trig_data['seconds'])
        if trig_data.get('type') == 'dt': return datetime.fromisoformat(trig_data['iso'])
    return trig_data
