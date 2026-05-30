import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import uuid
import pytz
import vobject
import re
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
from utils.encoding_helper import smart_quoted_printable_encode, should_encode, decode_ical_value
from models.constants import STANDARD_ICAL_FIELDS
import json

class DetailedReminderEditor(tk.Toplevel):
    """精细化提醒编辑器 (独立窗口)"""
    def __init__(self, parent, initial_alarm=None, callback=None):
        super().__init__(parent)
        self.title("编辑提醒" if initial_alarm else "添加提醒")
        self.geometry("500x550") # 设置固定大小
        self.transient(parent); self.grab_set()
        self.callback = callback
        self.initial_alarm = initial_alarm
        self.create_widgets()
        if initial_alarm: self.load_data(initial_alarm)

    def create_widgets(self):
        main_f = ttk.Frame(self); main_f.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 1. 基础设置
        basic_f = ttk.LabelFrame(main_f, text="提醒基本设置"); basic_f.pack(fill=tk.X, pady=5)
        ttk.Label(basic_f, text="提醒类型:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.rem_type_var = tk.StringVar(value="显示")
        ttk.Combobox(basic_f, textvariable=self.rem_type_var, values=["显示", "声音", "邮件"], state="readonly", width=10).grid(row=0, column=1, sticky="w", padx=5)
        
        ttk.Label(basic_f, text="触发方式:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.trig_type_var = tk.StringVar(value="relative")
        ttk.Radiobutton(basic_f, text="提前时间", variable=self.trig_type_var, value="relative").grid(row=1, column=1, sticky="w", padx=5)
        ttk.Radiobutton(basic_f, text="指定时间", variable=self.trig_type_var, value="absolute").grid(row=1, column=2, sticky="w", padx=5)
        
        # 提前时间 Frame
        self.rel_f = ttk.Frame(basic_f); self.rel_f.grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        self.days_v = tk.StringVar(value="0"); self.hours_v = tk.StringVar(value="0"); self.mins_v = tk.StringVar(value="15")
        ttk.Label(self.rel_f, text="天:").pack(side=tk.LEFT)
        ttk.Spinbox(self.rel_f, from_=0, to=365, textvariable=self.days_v, width=3).pack(side=tk.LEFT, padx=2)
        ttk.Label(self.rel_f, text="时:").pack(side=tk.LEFT)
        ttk.Spinbox(self.rel_f, from_=0, to=23, textvariable=self.hours_v, width=3).pack(side=tk.LEFT, padx=2)
        ttk.Label(self.rel_f, text="分:").pack(side=tk.LEFT)
        ttk.Spinbox(self.rel_f, from_=0, to=59, textvariable=self.mins_v, width=3).pack(side=tk.LEFT, padx=2)
        
        # 指定时间 Frame
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

        # 2. 详情设置
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
        self.rem_type_var.set({"DISPLAY": "显示", "AUDIO": "声音", "EMAIL": "邮件"}.get(a.get('action'), "显示"))
        tr = a.get('trigger')
        if isinstance(tr, datetime):
            self.trig_type_var.set("absolute")
            try:
                local_dt = tr.astimezone(pytz.timezone(TimezoneHelper.get_local_timezone_id()))
                self.abs_d.set_date(local_dt.date()); self.abs_h.set(local_dt.strftime("%H")); self.abs_m.set(local_dt.strftime("%M"))
            except: pass
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
            act = {"显示": "DISPLAY", "声音": "AUDIO", "邮件": "EMAIL"}.get(self.rem_type_var.get(), "DISPLAY")
            if self.trig_type_var.get() == "relative":
                d, h, m = int(self.days_v.get() or 0), int(self.hours_v.get() or 0), int(self.mins_v.get() or 0)
                trig = -timedelta(days=d, hours=h, minutes=m)
            else:
                try: 
                    tz_id = TimezoneHelper.extract_tz_id(self.abs_tz_v.get())
                    dt_naive = datetime.combine(self.abs_d.get_date(), datetime.strptime(f"{self.abs_h.get()}:{self.abs_m.get()}", "%H:%M").time())
                    trig = pytz.timezone(tz_id).localize(dt_naive).astimezone(pytz.UTC)
                except: messagebox.showerror("错误", "时间格式非法", parent=self); return
            
            new_a = {'action': act, 'trigger': trig, 'description': self.desc_t.get("1.0", "end-1c").strip()}
            if self.attach_v.get(): new_a['attach'] = self.attach_v.get()
            if self.mail_to_v.get(): new_a['attendee'] = self.mail_to_v.get()
            if self.mail_sub_v.get(): new_a['summary'] = self.mail_sub_v.get()
            try:
                rc = int(self.rep_v.get() or 0)
                if rc > 0: new_a['repeat'] = rc; new_a['duration'] = timedelta(minutes=int(self.dur_v.get() or 15))
            except: pass
            
            if self.callback: self.callback(new_a)
            self.destroy()
        except Exception as e: messagebox.showerror("保存失败", f"数据验证未通过: {e}", parent=self)

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

        self._loading = True # 标记正在加载数据
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

        self._loading = False # 加载完成

        # 增加全天状态监听，以便动态切换默认提醒
        if not self.initial.get('ical'):
            self.allday_var.trace("w", self._on_allday_toggled)

        # 强制触发一次最终的 UI 状态同步
        self.toggle_allday()
        self.toggle_sync_tz()
        self.on_status_changed()
        self.update_reminder_listbox()

        self.root.protocol("WM_DELETE_WINDOW", self.cancel)
        self.root.wait_window(self.root)

    def _on_allday_toggled(self, *args):
        """当用户切换全天状态时，如果是新建模式且提醒列表为空，重新应用默认提醒"""
        if not self._loading and not self.initial.get('ical'):
            # 如果当前提醒列表是空的，或者用户还没手动改过（这里简单判断是否为空）
            if not self.alarms:
                self.apply_default_reminders(self.allday_var.get())
                self.update_reminder_listbox()

    def setup_initial_defaults(self):
        if self.db:
            self.initial.setdefault('status', self.db.get_setting('default_status', 'CONFIRMED'))
            self.initial.setdefault('version', self.db.get_setting('default_version', '2.0'))
            self.initial.setdefault('allday', self.db.get_setting('default_allday', 'False') == 'True')
            self.initial.setdefault('force_reminder', self.db.get_setting('default_force_reminder', 'False') == 'True')
            self.initial.setdefault('priority', int(self.db.get_setting('default_priority', '5')))
            self.initial.setdefault('transparency', self.db.get_setting('default_transparency', 'OPAQUE'))
            self.initial.setdefault('repeat', self.db.get_setting('default_repeat', '不重复'))
            self.initial.setdefault('end_cond', self.db.get_setting('default_end_cond', '永不结束'))
            self.initial.setdefault('end_count', self.db.get_setting('default_end_count', '5'))
            self.initial.setdefault('duration', self.db.get_setting('default_duration', '1'))
            self.initial.setdefault('sync_timezone', self.db.get_setting('default_sync_timezone', 'True') == 'True')

            if not self.initial.get('ical'):
                is_allday = self.initial.get('allday')
                self.apply_default_reminders(is_allday)

        self.initial.setdefault('uid', f"event-{uuid.uuid4().hex}")
        self.initial.setdefault('is_edit', bool(self.initial.get('uid') and 'ical' in self.initial))

    def apply_default_reminders(self, is_allday):
        """从数据库读取并应用默认提醒"""
        if not self.db: return
        
        # 1. 处理“新建日程时自动勾选”
        key = 'default_allday_reminders' if is_allday else 'default_reminders'
        def_rem_str = self.db.get_setting(key, '')
        if def_rem_str:
            for r_text in def_rem_str.split(';'):
                if not r_text: continue
                trigger = self.parse_reminder_string(r_text)
                if trigger is not None:
                    # 确保不会重复添加相同的提醒
                    if not any(a['trigger'] == trigger and a['action'] == 'DISPLAY' for a in self.alarms):
                        self.alarms.append({'action': 'DISPLAY', 'trigger': trigger, 'description': f"默认提醒: {r_text}"})

        # 2. 处理“自定义默认提醒 (自动添加详情)”
        custom_key = 'custom_default_allday_reminders' if is_allday else 'custom_default_reminders'
        custom_rem_str = self.db.get_setting(custom_key, '')
        if custom_rem_str:
            for item in custom_rem_str.split(';'):
                if not item: continue
                try:
                    if item.startswith('{'):
                        alarm_data = json.loads(item)
                        # 还原 trigger
                        t_data = alarm_data.get('trigger')
                        if isinstance(t_data, dict):
                            if t_data.get('type') == 'td':
                                alarm_data['trigger'] = timedelta(seconds=t_data['seconds'])
                            elif t_data.get('type') == 'dt':
                                alarm_data['trigger'] = datetime.fromisoformat(t_data['iso'])
                        # 还原 duration
                        if 'duration' in alarm_data and isinstance(alarm_data['duration'], (int, float)):
                            alarm_data['duration'] = timedelta(seconds=alarm_data['duration'])
                        
                        if not any(a['trigger'] == alarm_data['trigger'] and a['action'] == alarm_data['action'] for a in self.alarms):
                            self.alarms.append(alarm_data)
                    else:
                        # 旧版格式兼容
                        parts = item.split(':', 3)
                        if len(parts) >= 3:
                            act_en = {"显示": "DISPLAY", "声音": "AUDIO", "邮件": "EMAIL"}.get(parts[0], "DISPLAY")
                            trig_mode, time_val, desc = parts[1], parts[2], parts[3] if len(parts) > 3 else ""
                            trigger = None
                            if trig_mode == "提前": trigger = self.parse_reminder_string(time_val)
                            elif trig_mode == "指定时间" and ":" in time_val:
                                h, m = map(int, time_val.split(':'))
                                trigger = timedelta(hours=h, minutes=m)
                            if trigger is not None:
                                if not any(a['trigger'] == trigger and a['action'] == act_en for a in self.alarms):
                                    self.alarms.append({'action': act_en, 'trigger': trigger, 'description': desc})
                except Exception as e:
                    logger.error(f"应用自定义默认提醒失败: {e}")

    def parse_reminder_string(self, text):
        """解析提醒字符串为 timedelta"""
        if not text: return None
        mapping = {
            "日程发生时": timedelta(0), "发生时": timedelta(0),
            "5分钟前": timedelta(minutes=-5), "15分钟前": timedelta(minutes=-15),
            "30分钟前": timedelta(minutes=-30), "1小时前": timedelta(hours=-1),
            "2小时前": timedelta(hours=-2), "1天前": timedelta(days=-1),
            "2天前": timedelta(days=-2), "7天前": timedelta(days=-7),
            "当天上午9点": timedelta(hours=9), "1天前上午9点": timedelta(days=-1, hours=9),
            "2天前上午9点": timedelta(days=-2, hours=9), "3天前上午9点": timedelta(days=-3, hours=9),
            "5天前上午9点": timedelta(days=-5, hours=9), "7天前上午9点": timedelta(days=-7, hours=9)
        }
        if text in mapping: return mapping[text]
        
        # 尝试正则解析 "X天Y小时Z分钟前"
        try:
            days, hours, mins = 0, 0, 0
            d_m = re.search(r'(\d+)天', text)
            h_m = re.search(r'(\d+)小时', text)
            m_m = re.search(r'(\d+)分钟', text)
            if d_m: days = int(d_m.group(1))
            if h_m: hours = int(h_m.group(1))
            if m_m: mins = int(m_m.group(1))
            if days or hours or mins:
                return -timedelta(days=days, hours=hours, minutes=mins)
        except: pass
        return None

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
        status_combo = ttk.Combobox(frame, textvariable=self.status_var, values=list(self.STATUS_MAPPING.keys()), state="readonly")
        status_combo.grid(row=4, column=1, sticky="w", padx=5)
        self.status_var.trace("w", self.on_status_changed)
        
        ttk.Label(frame, text="日历版本:").grid(row=4, column=2, sticky="e", padx=5)
        self.version_var = tk.StringVar(value="2.0")
        ttk.Combobox(frame, textvariable=self.version_var, values=["1.0", "2.0", "2.1", "3.0"], state="readonly", width=5).grid(row=4, column=3, sticky="w", padx=5)

    def _compute_snapped_start(self):
        mode = (self.db.get_setting("start_time_snap", "current")
                if self.db else "current")
        if mode == "current":
            return datetime.now()
        step = int(mode)
        now = datetime.now()
        minute = (now.minute // step + 1) * step
        hour = now.hour
        if minute >= 60:
            hour += 1
            minute = 0
        if hour >= 24:
            hour = 0
        return now.replace(hour=hour, minute=minute, second=0, microsecond=0)

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

        # 初始化默认值（根据吸附设置自动计算开始时间）
        start = self._compute_snapped_start()
        self.start_hour.set(f"{start.hour:02d}")
        self.start_minute.set(f"{start.minute:02d}")
        dur = int(self.db.get_setting("default_duration", "1")) if self.db else 1
        end = start + timedelta(hours=dur)
        self.end_date.set_date(end)
        self.end_hour.set(f"{end.hour:02d}")
        self.end_minute.set(f"{end.minute:02d}")

        tz_list = TimezoneHelper.get_localized_timezones()
        ttk.Label(frame, text="开始时区:").grid(row=3, column=0, sticky="w", padx=5)
        self.start_tz_var = tk.StringVar()
        self.start_tz_combo = ttk.Combobox(frame, textvariable=self.start_tz_var, values=tz_list, width=60, state="readonly")
        self.start_tz_combo.grid(row=3, column=1, sticky="we", padx=5, pady=2)
        
        self.start_tz_var.trace_add("write", self._on_start_tz_change)
        self.start_tz_combo.bind("<<ComboboxSelected>>", self._on_start_tz_change)
        self.start_tz_combo.bind("<MouseWheel>", self._on_tz_wheel)
        self.start_tz_combo.bind("<Button-4>", self._on_tz_wheel)
        self.start_tz_combo.bind("<Button-5>", self._on_tz_wheel)

        ttk.Label(frame, text="结束时区:").grid(row=4, column=0, sticky="w", padx=5)
        self.end_tz_var = tk.StringVar()
        self.end_tz_combo = ttk.Combobox(frame, textvariable=self.end_tz_var, values=tz_list, width=60, state="readonly")
        self.end_tz_combo.grid(row=4, column=1, sticky="we", padx=5, pady=2)
        self.end_tz_combo.bind("<MouseWheel>", self._on_tz_wheel)

        self.sync_tz_var = tk.BooleanVar(value=True)
        self.sync_tz_check = ttk.Checkbutton(frame, text="结束时间使用相同时区", variable=self.sync_tz_var, command=self.toggle_sync_tz)
        self.sync_tz_check.grid(row=5, column=1, sticky="w")
        self.end_tz_combo.config(state="disabled")

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
        main_frame = ttk.Frame(self.reminder_tab)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        list_frame = ttk.LabelFrame(main_frame, text="提醒列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        list_inner = ttk.Frame(list_frame); list_inner.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.reminder_listbox = tk.Listbox(list_inner, height=10, exportselection=False); self.reminder_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(list_inner, command=self.reminder_listbox.yview); scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.reminder_listbox.config(yscrollcommand=scrollbar.set)
        btn_frame = ttk.Frame(list_frame); btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="添加提醒", command=self.add_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="编辑提醒", command=self.edit_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除提醒", command=self.delete_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Label(btn_frame, text="双击列表项编辑", foreground="gray").pack(side=tk.RIGHT, padx=10)
        self.reminder_listbox.bind("<Double-1>", lambda e: self.edit_reminder())
        self.force_reminder_var = tk.BooleanVar()
        ttk.Checkbutton(main_frame, text="强制提醒 (让客户端尽可能显示提醒)", variable=self.force_reminder_var).pack(anchor="w", padx=5, pady=5)
        preset_section = ttk.LabelFrame(main_frame, text="预设提醒（双击添加）"); preset_section.pack(fill=tk.X, padx=5, pady=5)
        preset_frame = ttk.Frame(preset_section); preset_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(preset_frame, text="常规事件:").grid(row=0, column=0, sticky="w")
        e_p_r_f = ttk.Frame(preset_frame); e_p_r_f.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.preset_reminders_listbox = tk.Listbox(e_p_r_f, height=5, width=35, exportselection=False); self.preset_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        e_p_r_sb = ttk.Scrollbar(e_p_r_f, orient=tk.VERTICAL, command=self.preset_reminders_listbox.yview); e_p_r_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_reminders_listbox.config(yscrollcommand=e_p_r_sb.set)
        self.preset_reminders_listbox.bind("<Double-1>", lambda e: self.apply_preset_reminder(False))
        ttk.Label(preset_frame, text="全天事件:").grid(row=0, column=1, sticky="w")
        e_p_a_f = ttk.Frame(preset_frame); e_p_a_f.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        self.preset_allday_reminders_listbox = tk.Listbox(e_p_a_f, height=5, width=35, exportselection=False); self.preset_allday_reminders_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        e_p_a_sb = ttk.Scrollbar(e_p_a_f, orient=tk.VERTICAL, command=self.preset_allday_reminders_listbox.yview); e_p_a_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.preset_allday_reminders_listbox.config(yscrollcommand=e_p_a_sb.set)
        self.preset_allday_reminders_listbox.bind("<Double-1>", lambda e: self.apply_preset_reminder(True))
        self.load_preset_reminders()

    def create_advanced_tab(self):
        frame = ttk.LabelFrame(self.advanced_tab, text="高级设置")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        ttk.Label(frame, text="分类:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.categories_var = tk.StringVar(); categories_entry = ttk.Entry(frame, textvariable=self.categories_var, width=30); categories_entry.grid(row=0, column=1, sticky="we", padx=5)
        RightClickMenu(categories_entry)
        ttk.Label(frame, text="优先级:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.priority_var = tk.IntVar(value=5); priority_frame = ttk.Frame(frame); priority_frame.grid(row=1, column=1, sticky="w", padx=5)
        self.priority_scale = ttk.Scale(priority_frame, from_=0, to=9, variable=self.priority_var, orient=tk.HORIZONTAL, length=150, command=lambda v: self.priority_label.config(text=f" {int(float(v))} "))
        self.priority_scale.grid(row=0, column=0, sticky="w")
        self.priority_label = ttk.Label(priority_frame, text=" 5 ", width=3, relief=tk.RIDGE, anchor="center"); self.priority_label.grid(row=0, column=1, padx=5)
        ttk.Label(frame, text="透明度:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.transparency_var = tk.StringVar(value="忙碌"); ttk.Combobox(frame, textvariable=self.transparency_var, values=["忙碌", "空闲"], state="readonly").grid(row=2, column=1, sticky="w", padx=5)
        ttk.Label(frame, text="组织者:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.organizer_var = tk.StringVar(); organizer_entry = ttk.Entry(frame, textvariable=self.organizer_var, width=40); organizer_entry.grid(row=3, column=1, sticky="we", padx=5)
        RightClickMenu(organizer_entry)
        ttk.Label(frame, text="序列号:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.sequence_var = tk.StringVar(value="0"); sequence_entry = ttk.Entry(frame, textvariable=self.sequence_var, width=10); sequence_entry.grid(row=4, column=1, sticky="w", padx=5)
        RightClickMenu(sequence_entry)
        ttk.Label(frame, text="URL:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
        self.url_var = tk.StringVar(); url_entry = ttk.Entry(frame, textvariable=self.url_var, width=40); url_entry.grid(row=5, column=1, sticky="we", padx=5)
        RightClickMenu(url_entry)
        ttk.Label(frame, text="参与者:").grid(row=6, column=0, sticky="nw", padx=5, pady=5)
        self.attendee_text = tk.Text(frame, height=3, width=40); self.attendee_text.grid(row=6, column=1, sticky="nsew", padx=5, pady=5)
        RightClickMenu(self.attendee_text, "text"); attendee_scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.attendee_text.yview); attendee_scrollbar.grid(row=6, column=2, sticky="ns"); self.attendee_text.config(yscrollcommand=attendee_scrollbar.set)
        ttk.Label(frame, text="其他字段:").grid(row=7, column=0, sticky="nw", padx=5, pady=5)
        self.other_text = tk.Text(frame, height=4, width=40); self.other_text.grid(row=7, column=1, sticky="nsew", padx=5, pady=5)
        RightClickMenu(self.other_text, "text"); other_scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.other_text.yview); other_scrollbar.grid(row=7, column=2, sticky="ns"); self.other_text.config(yscrollcommand=other_scrollbar.set)

    def get_local_tz_str(self): return TimezoneHelper.get_local_timezone_id()

    def set_initial_values(self):
        m = self.model; self.uid_var.set(m.uid); self.summary_var.set(m.summary)
        local_tz_id = self.get_local_tz_str(); local_display = TimezoneHelper.get_timezone_display_name(local_tz_id)
        self.start_tz_var.set(local_display); self.end_tz_var.set(local_display)
        v = self.initial; is_edit_mode = 'ical' in v and v['ical']
        self.end_cond_var.set(v.get('end_cond', '永不结束')); self.end_count_var.set(v.get('end_count', '5'))
        if 'end_date' in v: self.end_date_entry.set_date(v['end_date'])
        if not is_edit_mode:
            if v.get('status'): self.status_var.set(self.STATUS_REV_MAPPING.get(v.get('status'), "已确认"))
            if v.get('priority') is not None:
                p = int(v.get('priority')); self.priority_var.set(p); self.priority_label.config(text=f" {p} ")
            if v.get('transparency'):
                trans_map = {"OPAQUE": "忙碌", "TRANSPARENT": "空闲"}; self.transparency_var.set(trans_map.get(v.get('transparency'), "忙碌"))
            if v.get('allday'): self.allday_var.set(True)
            if v.get('force_reminder'): self.force_reminder_var.set(True)
            if v.get('repeat'): self.repeat_var.set(v.get('repeat'))
            if v.get('version'): self.version_var.set(v.get('version'))
            if v.get('sync_timezone') is not None: self.sync_tz_var.set(v.get('sync_timezone'))
        if is_edit_mode:
            try:
                ical = vobject.readOne(v['ical']); ev = ical.vevent
                if hasattr(ev, 'summary'): self.summary_var.set(decode_ical_value(ev.summary.value))
                if hasattr(ev, 'location'): self.location_var.set(decode_ical_value(ev.location.value))
                if hasattr(ev, 'description'): self.description_text.insert("1.0", decode_ical_value(ev.description.value))
                if hasattr(ev, 'categories'): self.categories_var.set(decode_ical_value(",".join(ev.categories.value) if hasattr(ev.categories, 'value') else ev.categories.value))
                if hasattr(ev, 'priority'):
                    p = int(ev.priority.value); self.priority_var.set(p); self.priority_label.config(text=f" {p} ")
                if hasattr(ev, 'organizer'): self.organizer_var.set(decode_ical_value(ev.organizer.value))
                if hasattr(ev, 'status'): self.status_var.set(self.STATUS_REV_MAPPING.get(ev.status.value, "已确认"))
                if hasattr(ev, 'url'): self.url_var.set(decode_ical_value(ev.url.value))
                if hasattr(ev, 'sequence'): self.sequence_var.set(str(ev.sequence.value))
                
                # 恢复自定义扩展状态 (使用 contents[key][0] 安全读取带连字符的属性)
                if 'x-force-reminder' in ev.contents: self.force_reminder_var.set(ev.contents['x-force-reminder'][0].value == "1")
                if 'x-sync-tz' in ev.contents: self.sync_tz_var.set(ev.contents['x-sync-tz'][0].value == "1")
                if 'x-allday' in ev.contents: self.allday_var.set(ev.contents['x-allday'][0].value == "1")
                
                self.attendee_text.delete("1.0", tk.END); attendee_values = set()
                if hasattr(ev, 'attendee_list'):
                    for a in ev.attendee_list:
                        val = decode_ical_value(a.value); attendee_values.add(val)
                elif hasattr(ev, 'attendee'):
                    val = decode_ical_value(ev.attendee.value); attendee_values.add(val)
                if attendee_values: self.attendee_text.insert("1.0", "\n".join(sorted(list(attendee_values))))
                others = []; standard = STANDARD_ICAL_FIELDS
                for child in ev.contents.values():
                    for item in child:
                        name = item.name.upper()
                        if name not in standard: others.append(f"{name}: {item.value}")
                self.other_text.insert(tk.END, "\n".join(others))
                if hasattr(ev, 'dtstart'):
                    dt = ev.dtstart.value
                    if isinstance(dt, datetime):
                        self.start_date.set_date(dt.date()); self.start_hour.set(f"{dt.hour:02d}"); self.start_minute.set(f"{dt.minute:02d}")
                        if 'TZID' in ev.dtstart.params:
                            tzid = ev.dtstart.params['TZID'][0]; display = TimezoneHelper.get_timezone_display_name(tzid); self.start_tz_var.set(display)
                    else: self.start_date.set_date(dt); self.allday_var.set(True)
                if hasattr(ev, 'dtend'):
                    dt = ev.dtend.value
                    if isinstance(dt, datetime):
                        self.end_date.set_date(dt.date()); self.end_hour.set(f"{dt.hour:02d}"); self.end_minute.set(f"{dt.minute:02d}")
                        if 'TZID' in ev.dtend.params:
                            tzid = ev.dtend.params['TZID'][0]; display = TimezoneHelper.get_timezone_display_name(tzid); self.end_tz_var.set(display)
                    else: self.end_date.set_date(dt - timedelta(days=1))
                if hasattr(ev, 'rrule'):
                    rrule_str = ev.rrule.value; parts = dict(item.split('=') for item in rrule_str.split(';') if '=' in item)
                    freq = parts.get('FREQ'); interval = parts.get('INTERVAL', '1')
                    if freq == 'DAILY' and interval == '1': self.repeat_var.set('每天')
                    elif freq == 'WEEKLY' and interval == '1': self.repeat_var.set('每周')
                    elif freq == 'WEEKLY' and interval == '2': self.repeat_var.set('每两周')
                    elif freq == 'MONTHLY' and interval == '1': self.repeat_var.set('每月')
                    elif freq == 'YEARLY' and interval == '1': self.repeat_var.set('每年')
                    else: self.repeat_var.set('自定义'); self.custom_repeat_data = {'freq': freq, 'interval': interval}
                    if 'UNTIL' in parts:
                        self.end_cond_var.set('按日期结束')
                        try: self.end_date_entry.set_date(parser.parse(parts['UNTIL']).date())
                        except: pass
                    elif 'COUNT' in parts: self.end_cond_var.set('按次数结束'); self.end_count_var.set(parts['COUNT'])
                    else: self.end_cond_var.set('永不结束')
                self.alarms = []; valarms = ev.contents.get('valarm', [])
                if not valarms: valarms = [c for c in ev.getChildren() if c.name.upper() == 'VALARM']
                for alarm in valarms:
                    trigger = alarm.trigger.value if hasattr(alarm, 'trigger') else None
                    if trigger is None: continue
                    alarm_data = {'action': alarm.action.value if hasattr(alarm, 'action') else 'DISPLAY', 'trigger': trigger}
                    if hasattr(alarm, 'attach'): alarm_data['attach'] = alarm.attach.value
                    if hasattr(alarm, 'summary'): alarm_data['summary'] = alarm.summary.value
                    if hasattr(alarm, 'description'): alarm_data['description'] = alarm.description.value
                    if hasattr(alarm, 'attendee'): alarm_data['attendee'] = alarm.attendee.value
                    if hasattr(alarm, 'repeat'): 
                        try: alarm_data['repeat'] = int(alarm.repeat.value)
                        except: pass
                    if hasattr(alarm, 'duration'): alarm_data['duration'] = alarm.duration.value
                    self.alarms.append(alarm_data)
            except Exception as e: logger.error(f"解析 iCalendar 数据失败: {e}")
        self.toggle_allday(); self.toggle_sync_tz(); self.on_status_changed(); self.update_reminder_listbox()

    def toggle_allday(self):
        is_allday = self.allday_var.get(); state = "disabled" if is_allday else "readonly"
        for w in [self.start_hour, self.start_minute, self.end_hour, self.end_minute]: w.config(state=state)
        if is_allday: self.start_tz_combo.config(state="disabled"); self.end_tz_combo.config(state="disabled"); self.sync_tz_check.config(state="disabled"); self.toggle_sync_tz()
        else: self.start_tz_combo.config(state="readonly"); self.sync_tz_check.config(state="normal"); self.toggle_sync_tz()

    def toggle_sync_tz(self):
        if self.allday_var.get(): self.start_tz_combo.config(state="disabled"); self.end_tz_combo.config(state="disabled"); return
        if self.sync_tz_var.get(): self.end_tz_var.set(self.start_tz_var.get()); self.end_tz_combo.config(state="disabled")
        else: self.end_tz_combo.config(state="readonly")

    def _on_start_tz_change(self, *args):
        if getattr(self, '_loading', False): return
        if not self.allday_var.get() and self.sync_tz_var.get():
            val = self.start_tz_var.get()
            if val != self.end_tz_var.get(): self.end_tz_var.set(val)

    def _on_tz_wheel(self, event):
        if getattr(self, '_loading', False): return
        self.root.after(10, self._on_start_tz_change)

    def on_status_changed(self, *args):
        if getattr(self, '_loading', False): return
        status = self.status_var.get()
        if not hasattr(self, 'original_settings'):
            self.original_settings = {'start_date': self.start_date.get_date(), 'start_hour': self.start_hour.get(), 'start_minute': self.start_minute.get(), 'end_date': self.end_date.get_date(), 'end_hour': self.end_hour.get(), 'end_minute': self.end_minute.get(), 'alarms': self.alarms.copy()}
        if status == "已取消": self.notebook.tab(self.time_tab, state="disabled"); self.notebook.tab(self.reminder_tab, state="disabled")
        elif status == "待定": self.notebook.tab(self.time_tab, state="normal"); self.notebook.tab(self.reminder_tab, state="disabled")
        else:
            if hasattr(self, 'original_settings'):
                s = self.original_settings; self.start_date.set_date(s['start_date']); self.start_hour.set(s['start_hour']); self.start_minute.set(s['start_minute']); self.end_date.set_date(s['end_date']); self.end_hour.set(s['end_hour']); self.end_minute.set(s['end_minute']); self.alarms = s['alarms'].copy(); self.update_reminder_listbox()
            self.notebook.tab(self.time_tab, state="normal"); self.notebook.tab(self.reminder_tab, state="normal")

    def on_repeat_changed(self, *args):
        if getattr(self, '_loading', False): return
        if self.repeat_var.get() == "自定义": self.custom_repeat_settings()
        elif self.repeat_var.get() == "不重复": self.custom_repeat_data = {}

    def custom_repeat_settings(self):
        dialog = tk.Toplevel(self.root); dialog.title("自定义重复设置"); dialog.grab_set()
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

    def update_reminder_listbox(self):
        self.reminder_listbox.delete(0, tk.END)
        for a in self.alarms:
            trigger = a.get('trigger')
            if trigger is None: continue
            trigger_str = str(trigger)
            if isinstance(trigger, timedelta):
                total_min = int(abs(trigger.total_seconds()) / 60)
                if total_min == 0: trigger_str = "发生时"
                elif total_min < 60: trigger_str = f"{total_min}分钟前"
                elif total_min < 1440: trigger_str = f"{total_min//60}小时前"
                else: trigger_str = f"{total_min//1440}天前"
            act_display = {"DISPLAY": "显示", "AUDIO": "声音", "EMAIL": "邮件"}.get(a.get('action', 'DISPLAY'))
            self.reminder_listbox.insert(tk.END, f"{act_display} - {trigger_str}")

    def delete_reminder(self):
        s = self.reminder_listbox.curselection()
        if s: del self.alarms[s[0]]; self.update_reminder_listbox()

    def add_reminder(self): self.reminder_listbox.selection_clear(0, tk.END); self._edit_reminder(-1)
    def edit_reminder(self):
        s = self.reminder_listbox.curselection()
        if s: self._edit_reminder(s[0])
        else: messagebox.showwarning("提示", "请先选择要编辑的提醒", parent=self.root)

    def _open_reminder_editor(self, initial_alarm=None, callback=None):
        """打开提醒编辑器对话框 (精细化)"""
        DetailedReminderEditor(self.root, initial_alarm, callback)

    def _edit_reminder(self, index):
        initial = self.alarms[index] if index >= 0 else None
        def on_save(new_a):
            if index >= 0: self.alarms[index] = new_a
            else: self.alarms.append(new_a)
            self.update_reminder_listbox()
        self._open_reminder_editor(initial, on_save)

    def apply_preset_reminder(self, is_allday=False):
        lb = self.preset_allday_reminders_listbox if is_allday else self.preset_reminders_listbox; s = lb.curselection()
        if not s: return
        p_text = lb.get(s[0])
        trigger = self.parse_reminder_string(p_text)
        if trigger is not None:
            self.alarms.append({'action': 'DISPLAY', 'trigger': trigger, 'description': f"事件提醒: {p_text}"})
            self.update_reminder_listbox()

    def load_preset_reminders(self):
        if not self.db:
            # 备选默认值
            presets = ["5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前"]
            allday_presets = ["日程发生时", "1天前", "2天前", "7天前"]
        else:
            p_val = self.db.get_setting('preset_reminders', "5分钟前;15分钟前;30分钟前;1小时前;2小时前;1天前")
            a_val = self.db.get_setting('preset_allday_reminders', "日程发生时;1天前;2天前;7天前")
            presets = [x for x in p_val.split(';') if x]
            allday_presets = [x for x in a_val.split(';') if x]
            
        self.preset_reminders_listbox.delete(0, tk.END)
        for p in presets: self.preset_reminders_listbox.insert(tk.END, p)
        self.preset_allday_reminders_listbox.delete(0, tk.END)
        for p in allday_presets: self.preset_allday_reminders_listbox.insert(tk.END, p)

    def generate_ical(self):
        cal = vobject.iCalendar(); cal.add('version').value = self.version_var.get(); cal.add('prodid').value = f"-//{SOFTWARE_NAME}//{SOFTWARE_VERSION}//ZH-CN"; ev = cal.add('vevent'); ev.add('uid').value = self.uid_var.get(); ev.add('summary').value = self.summary_var.get()
        if self.location_var.get(): ev.add('location').value = self.location_var.get()
        if self.description_text.get("1.0", "end-1c").strip(): ev.add('description').value = self.description_text.get("1.0", "end-1c").strip()
        ev.add('status').value = self.STATUS_MAPPING.get(self.status_var.get(), "CONFIRMED")
        if self.allday_var.get(): ev.add('dtstart').value = self.start_date.get_date(); ev.add('dtend').value = self.end_date.get_date() + timedelta(days=1); ev.add('X-ALLDAY').value = "1"
        else:
            s_tz = pytz.timezone(TimezoneHelper.extract_tz_id(self.start_tz_var.get())); e_tz = pytz.timezone(TimezoneHelper.extract_tz_id(self.end_tz_var.get())); ev.add('dtstart').value = s_tz.localize(datetime.combine(self.start_date.get_date(), datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}", "%H:%M").time())); ev.add('dtend').value = e_tz.localize(datetime.combine(self.end_date.get_date(), datetime.strptime(f"{self.end_hour.get()}:{self.end_minute.get()}", "%H:%M").time()))
            if s_tz.zone != "UTC": ev.dtstart.params['TZID'] = [s_tz.zone]
            if e_tz.zone != "UTC": ev.dtend.params['TZID'] = [e_tz.zone]
        r_opt = self.repeat_var.get()
        if r_opt != "不重复":
            rrule = {"每天": "DAILY", "每周": "WEEKLY", "每两周": "WEEKLY;INTERVAL=2", "每月": "MONTHLY", "每年": "YEARLY"}.get(r_opt, "")
            if r_opt == "自定义" and self.custom_repeat_data: rrule = f"FREQ={self.custom_repeat_data['freq']};INTERVAL={self.custom_repeat_data['interval']}"
            if rrule:
                cond = self.end_cond_var.get()
                if cond == "按日期结束": rrule += f";UNTIL={self.end_date_entry.get_date().strftime('%Y%m%dT235959Z')}"
                elif cond == "按次数结束": rrule += f";COUNT={self.end_count_var.get()}"
                ev.add('rrule').value = rrule
        for a in self.alarms:
            al = ev.add('valarm'); al.add('action').value = a['action']; al.add('trigger').value = a['trigger']
            if 'description' in a: al.add('description').value = a['description']
            if 'attach' in a: al.add('attach').value = a['attach']
            if 'attendee' in a: al.add('attendee').value = a['attendee']
            if 'summary' in a: al.add('summary').value = a['summary']
            if 'repeat' in a: al.add('repeat').value = str(a['repeat']); al.add('duration').value = a['duration']
        if self.categories_var.get(): ev.add('categories').value = self.categories_var.get()
        ev.add('priority').value = str(self.priority_var.get()); ev.add('transp').value = self.TRANSPARENCY_MAPPING.get(self.transparency_var.get(), "OPAQUE")
        if self.organizer_var.get(): ev.add('organizer').value = str(self.organizer_var.get())
        try:
            seq = int(self.sequence_var.get() or "0")
            if self.initial.get('ical'): seq += 1
            ev.add('sequence').value = str(seq)
        except: pass
        if self.url_var.get().strip(): ev.add('url').value = self.url_var.get().strip()

        # 保存自定义扩展状态
        if self.force_reminder_var.get(): ev.add('x-force-reminder').value = "1"
        if self.sync_tz_var.get(): ev.add('x-sync-tz').value = "1"

        if hasattr(self, 'attendee_text'):
            for line in self.attendee_text.get("1.0", "end-1c").split('\n'):
                if line.strip(): ev.add('attendee').value = line.strip()
        if hasattr(self, 'other_text'):
            for line in self.other_text.get("1.0", "end-1c").splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    if k.strip().upper() not in STANDARD_ICAL_FIELDS:
                        try: ev.add(k.strip().lower()).value = v.strip()
                        except: pass
        return cal.serialize()

    def show_raw_data(self):
        win = tk.Toplevel(self.root); win.title("原始数据")
        sb_h = ttk.Scrollbar(win, orient=tk.HORIZONTAL)
        sb_v = ttk.Scrollbar(win, orient=tk.VERTICAL)
        txt = tk.Text(win, wrap=tk.NONE, xscrollcommand=sb_h.set, yscrollcommand=sb_v.set)
        RightClickMenu(txt, "text")
        sb_h.config(command=txt.xview); sb_v.config(command=txt.yview)
        sb_h.pack(side=tk.BOTTOM, fill=tk.X)
        sb_v.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, self.generate_ical()); txt.config(state=tk.DISABLED)

    def ok(self):
        summary = self.summary_var.get().strip()
        if not summary: messagebox.showwarning("提示", "请填写事件标题", parent=self.root); return
        if not self.allday_var.get():
            try: datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}", "%H:%M"); datetime.strptime(f"{self.end_hour.get()}:{self.end_minute.get()}", "%H:%M")
            except: messagebox.showwarning("提示", "请填写完整的时间", parent=self.root); return
        self.raw_ical = self.generate_ical(); self.result = {'summary': summary}; self.root.destroy()

    def cancel(self): self.result = None; self.root.destroy()
    def get_raw_ical(self): return self.raw_ical
    def set_start_now(self): self.start_date.set_date(datetime.now())
    def set_end_now(self):
        n = datetime.now() + timedelta(hours=1); self.end_date.set_date(n); self.end_hour.set(f"{n.hour:02d}"); self.end_minute.set("00")

def save_alarm_trigger(trig):
    if isinstance(trig, timedelta): return {'type': 'td', 'seconds': trig.total_seconds()}
    if isinstance(trig, datetime): return {'type': 'dt', 'iso': trig.isoformat()}
    return trig

def load_alarm_trigger(trig_data):
    if isinstance(trig_data, dict):
        if trig_data.get('type') == 'td': return timedelta(seconds=trig_data['seconds'])
        if trig_data.get('type') == 'dt': return datetime.fromisoformat(trig_data['iso'])
    return trig_data
