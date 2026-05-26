import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import uuid
import pytz
import vobject
from datetime import datetime, timedelta
from dateutil import parser
from babel.dates import get_timezone_name
from tzlocal import get_localzone
import locale
import quopri
from tkcalendar import DateEntry
from ui.widgets.right_click_menu import RightClickMenu
from config import SOFTWARE_NAME, SOFTWARE_VERSION
from utils.logger import logger
from models.event import EventModel
from utils.timezone_helper import TimezoneHelper
from utils.encoding_helper import smart_quoted_printable_encode, should_encode

class EventDialog:
    """日历事件编辑对话框 - 1:1 深度还原，Flawless 架构演进版"""
    STATUS_MAPPING = {"待定": "TENTATIVE", "已确认": "CONFIRMED", "已取消": "CANCELLED"}
    STATUS_REV_MAPPING = {v: k for k, v in STATUS_MAPPING.items()}
    TRANSPARENCY_MAPPING = {"忙碌": "OPAQUE", "空闲": "TRANSPARENT"}
    REPEAT_OPTIONS = ["不重复", "每天", "每周", "每两周", "每月", "每年", "自定义"]
    WEEKDAYS = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
    WEEKDAYS_RRULE = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"]
    END_CONDITIONS = ["永不结束", "按日期结束", "按次数结束"]

    def __init__(self, parent, initial=None, db=None):
        self.root = tk.Toplevel(parent)
        self.root.title("添加/编辑日历事件")
        self.root.geometry("900x800")
        self.root.transient(parent)
        self.root.grab_set()

        self.initial = initial or {}
        self.db = db
        self.result = None
        self.alarms = []
        self.custom_repeat_data = {}
        self.end_count_var = tk.StringVar(value="5")
        self.raw_ical = None
        
        # 将原始字典映射为强类型 DTO
        self.model = EventModel(
            uid=self.initial.get('uid', f"event-{uuid.uuid4().hex}"),
            summary=self.initial.get('summary', ''),
            dtstart=str(self.initial.get('dtstart', '')),
            dtend=str(self.initial.get('dtend', '')),
            ical=self.initial.get('ical', '')
        )
        
        self.setup_initial_defaults()
        self.create_widgets()
        self.set_initial_values()

        self.root.protocol("WM_DELETE_WINDOW", self.cancel)
        self.root.wait_window(self.root)

    def setup_initial_defaults(self):
        if self.db:
            self.initial.setdefault('status', self.db.get_setting('default_status', 'CONFIRMED'))
            self.initial.setdefault('version', self.db.get_setting('default_version', '2.0'))
            self.initial.setdefault('allday', self.db.get_setting('default_allday', 'False') == 'True')
            self.initial.setdefault('force_reminder', self.db.get_setting('default_force_reminder', 'False') == 'True')
            self.initial.setdefault('priority', int(self.db.get_setting('default_priority', '5')))
            self.initial.setdefault('transparency', self.db.get_setting('default_transparency', 'OPAQUE'))
            self.initial.setdefault('repeat', self.db.get_setting('default_repeat', '不重复'))
            
            if not self.initial.get('ical'):
                is_allday = self.initial.get('allday')
                key = 'default_allday_reminders' if is_allday else 'default_reminders'
                def_rem_str = self.db.get_setting(key, '')
                if def_rem_str:
                    mapping = {
                        "日程发生时": timedelta(seconds=0), "5分钟前": timedelta(minutes=-5),
                        "15分钟前": timedelta(minutes=-15), "30分钟前": timedelta(minutes=-30),
                        "1小时前": timedelta(hours=-1), "2小时前": timedelta(hours=-2),
                        "1天前": timedelta(days=-1), "2天前": timedelta(days=-2), "7天前": timedelta(days=-7)
                    }
                    for r_text in def_rem_str.split(';'):
                        if r_text in mapping:
                            self.alarms.append({'action': 'DISPLAY', 'trigger': mapping[r_text]})
        
        self.initial.setdefault('uid', f"event-{uuid.uuid4().hex}")
        self.initial.setdefault('is_edit', bool(self.initial.get('uid') and 'ical' in self.initial))

    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.basic_tab = ttk.Frame(self.notebook); self.notebook.add(self.basic_tab, text="基本信息")
        self.time_tab = ttk.Frame(self.notebook); self.notebook.add(self.time_tab, text="时间设置")
        self.reminder_tab = ttk.Frame(self.notebook); self.notebook.add(self.reminder_tab, text="提醒设置")
        self.advanced_tab = ttk.Frame(self.notebook); self.notebook.add(self.advanced_tab, text="高级设置")

        self.create_basic_tab()
        self.create_time_tab()
        self.create_reminder_tab()
        self.create_advanced_tab()

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text="确定", command=self.ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="取消", command=self.cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="查看原始数据", command=self.show_raw_data).pack(side=tk.LEFT, padx=5)

    def create_basic_tab(self):
        frame = ttk.LabelFrame(self.basic_tab, text="事件基本信息")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Label(frame, text="事件ID:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.uid_var = tk.StringVar()
        self.uid_entry = ttk.Entry(frame, textvariable=self.uid_var, width=40)
        self.uid_entry.grid(row=0, column=1, columnspan=3, sticky="we", padx=5)
        RightClickMenu(self.uid_entry)

        ttk.Label(frame, text="事件标题*:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.summary_var = tk.StringVar()
        self.summary_entry = ttk.Entry(frame, textvariable=self.summary_var, width=40)
        self.summary_entry.grid(row=1, column=1, columnspan=3, sticky="we", padx=5)
        RightClickMenu(self.summary_entry)

        ttk.Label(frame, text="地点:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.location_var = tk.StringVar()
        self.location_entry = ttk.Entry(frame, textvariable=self.location_var, width=40)
        self.location_entry.grid(row=2, column=1, columnspan=3, sticky="we", padx=5)
        RightClickMenu(self.location_entry)

        ttk.Label(frame, text="描述:").grid(row=3, column=0, sticky="nw", padx=5, pady=5)
        self.description_text = tk.Text(frame, height=5, width=50, undo=True)
        self.description_text.grid(row=3, column=1, columnspan=3, sticky="nsew", padx=5)
        RightClickMenu(self.description_text, "text")

        ttk.Label(frame, text="事件状态:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.status_var = tk.StringVar()
        ttk.Combobox(frame, textvariable=self.status_var, values=list(self.STATUS_MAPPING.keys()), state="readonly").grid(row=4, column=1, sticky="w", padx=5)
        
        ttk.Label(frame, text="日历版本:").grid(row=4, column=2, sticky="e", padx=5)
        self.version_var = tk.StringVar(value="2.0")
        ttk.Combobox(frame, textvariable=self.version_var, values=["1.0", "2.0", "2.1", "3.0"], state="readonly", width=5).grid(row=4, column=3, sticky="w", padx=5)

    def create_time_tab(self):
        frame = ttk.LabelFrame(self.time_tab, text="时间设置")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.allday_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="全天事件", variable=self.allday_var, command=self.toggle_allday).grid(row=0, column=0, sticky="w", padx=5, pady=5)

        s_frame = ttk.Frame(frame); s_frame.grid(row=1, column=0, columnspan=3, sticky="w")
        ttk.Label(s_frame, text="开始日期*:").pack(side=tk.LEFT, padx=5)
        self.start_date = DateEntry(s_frame, date_pattern='yyyy-mm-dd', width=12); self.start_date.pack(side=tk.LEFT)
        self.start_hour = ttk.Combobox(s_frame, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly"); self.start_hour.pack(side=tk.LEFT, padx=2)
        self.start_minute = ttk.Combobox(s_frame, width=3, values=[f"{m:02d}" for m in range(0, 60, 5)], state="readonly"); self.start_minute.pack(side=tk.LEFT)
        ttk.Button(s_frame, text="当前时间", command=self.set_start_now).pack(side=tk.LEFT, padx=10)

        e_frame = ttk.Frame(frame); e_frame.grid(row=2, column=0, columnspan=3, sticky="w", pady=5)
        ttk.Label(e_frame, text="结束日期*:").pack(side=tk.LEFT, padx=5)
        self.end_date = DateEntry(e_frame, date_pattern='yyyy-mm-dd', width=12); self.end_date.pack(side=tk.LEFT)
        self.end_hour = ttk.Combobox(e_frame, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly"); self.end_hour.pack(side=tk.LEFT, padx=2)
        self.end_minute = ttk.Combobox(e_frame, width=3, values=[f"{m:02d}" for m in range(0, 60, 5)], state="readonly"); self.end_minute.pack(side=tk.LEFT)
        ttk.Button(e_frame, text="当前时间", command=self.set_end_now).pack(side=tk.LEFT, padx=10)

        tz_list = TimezoneHelper.get_localized_timezones()
        ttk.Label(frame, text="开始时区:").grid(row=3, column=0, sticky="w", padx=5)
        self.start_tz_var = tk.StringVar()
        self.start_tz_combo = ttk.Combobox(frame, textvariable=self.start_tz_var, values=tz_list, width=45, state="readonly")
        self.start_tz_combo.grid(row=3, column=1, sticky="we", padx=5, pady=2)

        ttk.Label(frame, text="结束时区:").grid(row=4, column=0, sticky="w", padx=5)
        self.end_tz_var = tk.StringVar()
        self.end_tz_combo = ttk.Combobox(frame, textvariable=self.end_tz_var, values=tz_list, width=45, state="readonly")
        self.end_tz_combo.grid(row=4, column=1, sticky="we", padx=5, pady=2)

        self.sync_tz_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="结束时间使用相同时区", variable=self.sync_tz_var, command=self.toggle_sync_tz).grid(row=5, column=1, sticky="w")

        # 快速调整持续时间框架 (1:1 还原旧版)
        self.duration_frame = ttk.Frame(frame)
        self.duration_frame.grid(row=6, column=0, columnspan=3, sticky='w', padx=5, pady=10)
        ttk.Label(self.duration_frame, text="快速调整持续时间:").pack(side='left')
        dur_opts = ["1小时", "2小时", (self.db.get_setting('default_duration', '1') if self.db else "1") + "小时", "半天", "全天"]
        for opt in dur_opts:
            ttk.Button(self.duration_frame, text=opt, command=lambda o=opt: self.apply_duration(o)).pack(side='left', padx=2)

        ttk.Label(frame, text="重复规则:").grid(row=7, column=0, sticky="w", padx=5, pady=5)
        self.repeat_var = tk.StringVar(value="不重复")
        ttk.Combobox(frame, textvariable=self.repeat_var, values=self.REPEAT_OPTIONS, state="readonly").grid(row=7, column=1, sticky="w", padx=5)
        self.repeat_var.trace("w", self.on_repeat_changed)

        ttk.Label(frame, text="结束条件:").grid(row=8, column=0, sticky="w", padx=5, pady=5)
        self.end_cond_var = tk.StringVar(value="永不结束")
        ttk.Combobox(frame, textvariable=self.end_cond_var, values=self.END_CONDITIONS, state="readonly").grid(row=8, column=1, sticky="w", padx=5)

        self.end_count_spin = ttk.Spinbox(frame, from_=1, to=999, textvariable=self.end_count_var, width=5)
        self.end_count_spin.grid(row=8, column=2, sticky="w")
        self.end_date_entry = DateEntry(frame, date_pattern='yyyy-mm-dd', width=12)
        self.end_date_entry.grid(row=8, column=3, sticky="w", padx=5)

        def update_end_ui(*args):
            c = self.end_cond_var.get()
            self.end_count_spin.config(state=tk.NORMAL if c == "按次数结束" else tk.DISABLED)
            self.end_date_entry.config(state=tk.NORMAL if c == "按日期结束" else tk.DISABLED)
        self.end_cond_var.trace("w", update_end_ui)
        update_end_ui()

    def apply_duration(self, dur_str):
        """1:1 还原旧版快速调整逻辑"""
        try:
            start_dt = datetime.combine(self.start_date.get_date(), 
                                        datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}", "%H:%M").time())
            if dur_str == "半天": delta = timedelta(hours=12)
            elif dur_str == "全天": delta = timedelta(days=1)
            else:
                h = int(dur_str.replace("小时", ""))
                delta = timedelta(hours=h)
            
            end_dt = start_dt + delta
            self.end_date.set_date(end_dt.date())
            self.end_hour.set(end_dt.strftime("%H"))
            self.end_minute.set(end_dt.strftime("%M"))
        except: pass

    def create_reminder_tab(self):
        frame = ttk.LabelFrame(self.reminder_tab, text="提醒设置")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.reminder_listbox = tk.Listbox(frame, height=8)
        self.reminder_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, padx=5)
        ttk.Button(btn_frame, text="添加提醒", command=self.add_reminder_dialog).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除提醒", command=self.delete_reminder).pack(side=tk.LEFT, padx=2)

    def create_advanced_tab(self):
        frame = ttk.LabelFrame(self.advanced_tab, text="高级设置")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(frame, text="分类:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.categories_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.categories_var, width=30).grid(row=0, column=1, sticky="we", padx=5)
        ttk.Label(frame, text="优先级:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.priority_var = tk.IntVar(value=5)
        ttk.Scale(frame, from_=0, to=9, variable=self.priority_var, orient=tk.HORIZONTAL).grid(row=1, column=1, sticky="we", padx=5)
        ttk.Label(frame, text="透明度:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.transparency_var = tk.StringVar(value="忙碌")
        ttk.Combobox(frame, textvariable=self.transparency_var, values=["忙碌", "空闲"], state="readonly").grid(row=2, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="组织者:").grid(row=3, column=0, sticky="w", padx=5)
        self.organizer_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.organizer_var, width=40).grid(row=3, column=1, sticky="we", padx=5)

    def get_local_tz_str(self):
        return str(get_localzone())

    def set_initial_values(self):
        """1:1 还原数据回显逻辑，支持 DTO 模型"""
        m = self.model
        self.uid_var.set(m.uid)
        self.summary_var.set(m.summary)
        local_tz = self.get_local_tz_str()
        
        # 寻找本地化名称
        match_tz = local_tz
        for opt in self.start_tz_combo['values']:
            if opt.startswith(local_tz): match_tz = opt; break
        self.start_tz_var.set(match_tz); self.end_tz_var.set(match_tz)

        v = self.initial
        self.end_cond_var.set(v.get('end_cond', '永不结束'))
        self.end_count_var.set(v.get('end_count', '5'))
        if 'end_date' in v: self.end_date_entry.set_date(v['end_date'])

        if 'ical' in v and v['ical']:
            try:
                ical = vobject.readOne(v['ical'])
                ev = ical.vevent
                if hasattr(ev, 'location'): self.location_var.set(ev.location.value)
                if hasattr(ev, 'description'): self.description_text.insert("1.0", ev.description.value)
                if hasattr(ev, 'categories'): self.categories_var.set(",".join(ev.categories.value))
                if hasattr(ev, 'priority'): self.priority_var.set(int(ev.priority.value))
                if hasattr(ev, 'organizer'): self.organizer_var.set(ev.organizer.value)
                
                # 状态转换补全
                if hasattr(ev, 'status'):
                    self.status_var.set(self.STATUS_REV_MAPPING.get(ev.status.value, "已确认"))

                # 时间解析还原
                if hasattr(ev, 'dtstart'):
                    dt = ev.dtstart.value
                    if isinstance(dt, datetime):
                        self.start_date.set_date(dt.date())
                        self.start_hour.set(f"{dt.hour:02d}")
                        self.start_minute.set(f"{dt.minute:02d}")
                        if 'TZID' in ev.dtstart.params:
                            tzid = ev.dtstart.params['TZID'][0]
                            for opt in self.start_tz_combo['values']:
                                if opt.startswith(tzid): self.start_tz_var.set(opt); break
                    else:
                        self.start_date.set_date(dt)
                        self.allday_var.set(True)
                
                if hasattr(ev, 'dtend'):
                    dt = ev.dtend.value
                    if isinstance(dt, datetime):
                        self.end_date.set_date(dt.date())
                        self.end_hour.set(f"{dt.hour:02d}")
                        self.end_minute.set(f"{dt.minute:02d}")
                        if 'TZID' in ev.dtend.params:
                            tzid = ev.dtend.params['TZID'][0]
                            for opt in self.end_tz_combo['values']:
                                if opt.startswith(tzid): self.end_tz_var.set(opt); break
                    else:
                        self.end_date.set_date(dt - timedelta(days=1)) 
            except: pass
        self.update_reminder_listbox()

    def toggle_allday(self):
        s = "disabled" if self.allday_var.get() else "readonly"
        for w in [self.start_hour, self.start_minute, self.end_hour, self.end_minute]: w.config(state=s)

    def toggle_sync_tz(self):
        if self.sync_tz_var.get():
            self.end_tz_var.set(self.start_tz_var.get()); self.end_tz_combo.config(state="disabled")
        else:
            self.end_tz_combo.config(state="readonly")

    def on_repeat_changed(self, *args):
        if self.repeat_var.get() == "自定义":
            self.custom_repeat_settings()
        elif self.repeat_var.get() == "不重复":
            self.custom_repeat_data = {}

    def custom_repeat_settings(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("自定义重复设置")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        main_f = ttk.Frame(dialog); main_f.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(main_f, text="重复频率:").grid(row=0, column=0, sticky="w")
        self.freq_var = tk.StringVar(value="每周")
        ttk.Combobox(main_f, textvariable=self.freq_var, values=["每天", "每周", "每月", "每年"], state="readonly").grid(row=0, column=1, pady=5)
        ttk.Label(main_f, text="重复间隔:").grid(row=1, column=0, sticky="w")
        self.interval_var = tk.StringVar(value="1")
        ttk.Spinbox(main_f, from_=1, to=99, textvariable=self.interval_var, width=5).grid(row=1, column=1, pady=5, sticky="w")
        def save_custom():
            f_map = {"每天": "DAILY", "每周": "WEEKLY", "每月": "MONTHLY", "每年": "YEARLY"}
            self.custom_repeat_data = {'freq': f_map.get(self.freq_var.get(), "WEEKLY"), 'interval': self.interval_var.get()}
            dialog.destroy()
        ttk.Button(main_f, text="确定", command=save_custom).grid(row=2, column=1, pady=20)

    def add_reminder_dialog(self):
        m = tk.simpledialog.askinteger("添加提醒", "提前多少分钟提醒？(如 15):", initialvalue=15, parent=self.root)
        if m is not None:
            self.alarms.append({'action': 'DISPLAY', 'trigger': timedelta(minutes=-m)})
            self.update_reminder_listbox()

    def update_reminder_listbox(self):
        self.reminder_listbox.delete(0, tk.END)
        for a in self.alarms: self.reminder_listbox.insert(tk.END, f"{a['action']} - {a['trigger']}")

    def delete_reminder(self):
        s = self.reminder_listbox.curselection()
        if s: del self.alarms[s[0]]; self.update_reminder_listbox()

    def encode_text(self, text):
        if not text: return ""
        if not should_encode(text): return text
        return f"ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:{quopri.encodestring(text.encode('utf-8')).decode('utf-8')}"

    def generate_ical(self):
        cal = vobject.iCalendar()
        cal.add('version').value = self.version_var.get()
        cal.add('prodid').value = f"-//{SOFTWARE_NAME}//{SOFTWARE_VERSION}//ZH-CN"
        ev = cal.add('vevent')
        ev.add('uid').value = self.uid_var.get()
        ev.add('summary').value = self.encode_text(self.summary_var.get())
        ev.add('location').value = self.encode_text(self.location_var.get())
        ev.add('description').value = self.encode_text(self.description_text.get("1.0", "end-1c").strip())
        ev.add('status').value = self.STATUS_MAPPING.get(self.status_var.get(), "CONFIRMED")
        
        if self.allday_var.get():
            ev.add('dtstart').value = self.start_date.get_date()
            ev.add('dtend').value = self.end_date.get_date() + timedelta(days=1)
            ev.add('X-ALLDAY').value = "1"
        else:
            s_tz_id = TimezoneHelper.extract_tz_id(self.start_tz_var.get())
            e_tz_id = TimezoneHelper.extract_tz_id(self.end_tz_var.get())
            s_tz = pytz.timezone(s_tz_id)
            e_tz = pytz.timezone(e_tz_id)
            s_dt = s_tz.localize(datetime.combine(self.start_date.get_date(), datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}", "%H:%M").time()))
            e_dt = e_tz.localize(datetime.combine(self.end_date.get_date(), datetime.strptime(f"{self.end_hour.get()}:{self.end_minute.get()}", "%H:%M").time()))
            ev.add('dtstart').value = s_dt
            ev.add('dtend').value = e_dt
            if s_tz_id != "UTC": ev.dtstart.params['TZID'] = [s_tz_id]
            if e_tz_id != "UTC": ev.dtend.params['TZID'] = [e_tz_id]

        r_opt = self.repeat_var.get()
        if r_opt != "不重复":
            if r_opt == "每天": rrule = "FREQ=DAILY"
            elif r_opt == "每周": rrule = "FREQ=WEEKLY"
            elif r_opt == "每两周": rrule = "FREQ=WEEKLY;INTERVAL=2"
            elif r_opt == "每月": rrule = "FREQ=MONTHLY"
            elif r_opt == "每年": rrule = "FREQ=YEARLY"
            elif r_opt == "自定义" and self.custom_repeat_data:
                rrule = f"FREQ={self.custom_repeat_data['freq']};INTERVAL={self.custom_repeat_data['interval']}"
            else: rrule = ""
            if rrule:
                cond = self.end_cond_var.get()
                if cond == "按日期结束": rrule += f";UNTIL={self.end_date_entry.get_date().strftime('%Y%m%dT235959Z')}"
                elif cond == "按次数结束": rrule += f";COUNT={self.end_count_var.get()}"
                ev.add('rrule').value = rrule

        for a in self.alarms:
            al = ev.add('valarm')
            al.add('action').value = a['action']
            al.add('trigger').value = a['trigger']

        if self.categories_var.get(): ev.add('categories').value = self.categories_var.get()
        ev.add('priority').value = str(self.priority_var.get())
        ev.add('transp').value = self.TRANSPARENCY_MAPPING.get(self.transparency_var.get(), "OPAQUE")
        if self.organizer_var.get(): ev.add('organizer').value = self.organizer_var.get()
        return cal.serialize()

    def show_raw_data(self):
        data = self.generate_ical()
        win = tk.Toplevel(self.root); win.title("原始数据")
        txt = tk.Text(win); txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, data); txt.config(state=tk.DISABLED)

    def ok(self):
        self.raw_ical = self.generate_ical()
        self.result = {'summary': self.summary_var.get()}
        self.root.destroy()

    def cancel(self): self.result = None; self.root.destroy()
    def get_raw_ical(self): return self.raw_ical
    def set_start_now(self):
        n = datetime.now(); self.start_date.set_date(n); self.start_hour.set(f"{n.hour:02d}"); self.start_minute.set(f"{n.minute:02d}")
    def set_end_now(self):
        n = datetime.now()+timedelta(hours=1); self.end_date.set_date(n); self.end_hour.set(f"{n.hour:02d}"); self.end_minute.set(f"{n.minute:02d}")
