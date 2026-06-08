import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import uuid
import pytz
import re
import os
import base64
from datetime import datetime, timedelta
from dateutil import parser
from tkcalendar import DateEntry
from ui.widgets.right_click_menu import RightClickMenu
from ui.widgets.enhanced_tooltip import EnhancedTooltip
from config import SOFTWARE_NAME, SOFTWARE_VERSION
from utils.logger import logger
from models.event import EventModel
from utils.timezone_helper import TimezoneHelper
from utils import attachment_store
from ui.dialogs.confirm_dialog import ConfirmDialog
from models.constants import (
    STATUS_MAPPING, STATUS_REV_MAPPING,
    TRANSPARENCY_MAPPING, TRANSPARENCY_REV_MAPPING,
    REPEAT_OPTIONS, WEEKDAYS, WEEKDAYS_RRULE, END_CONDITIONS,
    ALARM_ACTION_MAPPING, ALARM_ACTION_REV_MAPPING,
    DURATION_QUICK_OPTIONS, FREQ_MAPPING,
    PRESET_REMINDERS_DEFAULT, PRESET_ALLDAY_REMINDERS_DEFAULT,
    REMINDER_STRING_MAPPING,
)
import json
from ui.dialogs.detailed_reminder_editor import DetailedReminderEditor
from services.ical_builder import parse_ical_event, build_ical

class EventDialog:
    """日历事件编辑对话框 - 1:1 深度还原，Flawless 架构演进版"""
    STATUS_MAPPING = STATUS_MAPPING
    STATUS_REV_MAPPING = STATUS_REV_MAPPING
    TRANSPARENCY_MAPPING = TRANSPARENCY_MAPPING
    REPEAT_OPTIONS = REPEAT_OPTIONS
    WEEKDAYS = WEEKDAYS
    WEEKDAYS_RRULE = WEEKDAYS_RRULE
    END_CONDITIONS = END_CONDITIONS

    def __init__(self, parent, initial=None, db=None):
        self.root = tk.Toplevel(parent)
        self.root.title("添加/编辑日历事件")
        # self.root.geometry("900x800")
        self.root.transient(parent)
        self.root.grab_set()

        self._loading = True # 标记正在加载数据
        self.initial = initial or {}
        self.db = db
        self.result = None
        self.alarms = []
        self.custom_repeat_data = {}
        self.other_fields = []
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
        from utils.window_utils import center_window
        center_window(self.root, parent)
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
            self.initial.setdefault('duration', self.db.get_setting('default_duration', '60'))
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
                            act_en = ALARM_ACTION_MAPPING.get(parts[0], "DISPLAY")
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
        if text in REMINDER_STRING_MAPPING: return REMINDER_STRING_MAPPING[text]
        
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
        except Exception:
            logger.debug("忽略异常")
        return None

    def create_widgets(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.basic_tab = ttk.Frame(self.notebook); self.notebook.add(self.basic_tab, text="基本信息")
        self.time_tab = ttk.Frame(self.notebook); self.notebook.add(self.time_tab, text="时间设置")
        self.reminder_tab = ttk.Frame(self.notebook); self.notebook.add(self.reminder_tab, text="提醒设置")
        self.attachment_tab = ttk.Frame(self.notebook); self.notebook.add(self.attachment_tab, text="附件")
        self.advanced_tab = ttk.Frame(self.notebook); self.notebook.add(self.advanced_tab, text="高级设置")

        self.create_basic_tab()
        self.create_time_tab()
        self.create_reminder_tab()
        self.create_attachment_tab()
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
        EnhancedTooltip(self.summary_entry, "必填。事件的简要标题")
        RightClickMenu(self.summary_entry)

        ttk.Label(frame, text="地点:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.location_var = tk.StringVar()
        self.location_entry = ttk.Entry(frame, textvariable=self.location_var, width=40)
        self.location_entry.grid(row=2, column=1, columnspan=3, sticky="we", padx=5)
        EnhancedTooltip(self.location_entry, "事件发生的地点或会议室")
        RightClickMenu(self.location_entry)

        ttk.Label(frame, text="描述:").grid(row=3, column=0, sticky="nw", padx=5, pady=5)
        self.description_text = tk.Text(frame, height=5, width=50, undo=True)
        self.description_text.grid(row=3, column=1, columnspan=3, sticky="nsew", padx=5)
        EnhancedTooltip(self.description_text, "事件的详细描述或备注")
        RightClickMenu(self.description_text, "text")

        ttk.Label(frame, text="事件状态:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.status_var = tk.StringVar()
        status_combo = ttk.Combobox(frame, textvariable=self.status_var, values=list(self.STATUS_MAPPING.keys()), state="readonly")
        status_combo.grid(row=4, column=1, sticky="w", padx=5)
        EnhancedTooltip(status_combo, "事件状态: 已确认/待定/已取消")
        self.status_var.trace("w", self.on_status_changed)
        
        ttk.Label(frame, text="日历版本:").grid(row=4, column=2, sticky="e", padx=5)
        self.version_var = tk.StringVar(value="2.0")
        ver_combo = ttk.Combobox(frame, textvariable=self.version_var, values=["1.0", "2.0", "2.1", "3.0"], state="readonly", width=5)
        ver_combo.grid(row=4, column=3, sticky="w", padx=5)
        EnhancedTooltip(ver_combo, "iCalendar 版本号，通常保持 2.0")

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

    def _get_default_duration_minutes(self):
        if not self.db:
            return 60
        mode = self.db.get_setting("default_duration", "60")
        if mode == "custom":
            return int(self.db.get_setting("default_duration_custom", "45"))
        try:
            v = int(mode)
            if v <= 24:  # 旧版 DB 存小时数 → 转为分钟
                v *= 60
            return v
        except Exception:
            return 60

    def create_time_tab(self):
        frame = ttk.LabelFrame(self.time_tab, text="时间设置")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.allday_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="全天事件", variable=self.allday_var, command=self.toggle_allday).grid(row=0, column=0, sticky="w", padx=5, pady=5)

        s_frame = ttk.Frame(frame); s_frame.grid(row=1, column=0, columnspan=3, sticky="w")
        ttk.Label(s_frame, text="开始日期*:").pack(side=tk.LEFT, padx=5)
        self.start_date = DateEntry(s_frame, date_pattern='yyyy-mm-dd', width=12); self.start_date.pack(side=tk.LEFT)
        self.start_hour = ttk.Combobox(s_frame, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly"); self.start_hour.pack(side=tk.LEFT, padx=2)
        self.start_minute = ttk.Combobox(s_frame, width=3, values=[f"{m:02d}" for m in range(60)], state="readonly"); self.start_minute.pack(side=tk.LEFT)
        ttk.Button(s_frame, text="当前时间", command=self.set_start_now).pack(side=tk.LEFT, padx=10)

        e_frame = ttk.Frame(frame); e_frame.grid(row=2, column=0, columnspan=3, sticky="w", pady=5)
        ttk.Label(e_frame, text="结束日期*:").pack(side=tk.LEFT, padx=5)
        self.end_date = DateEntry(e_frame, date_pattern='yyyy-mm-dd', width=12); self.end_date.pack(side=tk.LEFT)
        self.end_hour = ttk.Combobox(e_frame, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly"); self.end_hour.pack(side=tk.LEFT, padx=2)
        self.end_minute = ttk.Combobox(e_frame, width=3, values=[f"{m:02d}" for m in range(60)], state="readonly"); self.end_minute.pack(side=tk.LEFT)
        ttk.Button(e_frame, text="当前时间", command=self.set_end_now).pack(side=tk.LEFT, padx=10)

        # 初始化默认值（根据吸附设置自动计算开始时间）
        start = self._compute_snapped_start()
        self.start_hour.set(f"{start.hour:02d}")
        self.start_minute.set(f"{start.minute:02d}")
        dur_min = self._get_default_duration_minutes()
        end = start + timedelta(minutes=dur_min)
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
        for opt in DURATION_QUICK_OPTIONS:
            ttk.Button(self.duration_frame, text=opt, command=lambda o=opt: self.apply_duration(o)).pack(side='left', padx=2)

        dur_min = self._get_default_duration_minutes()
        h, m = dur_min // 60, dur_min % 60
        parts = []
        if h: parts.append(f"{h}小时")
        if m: parts.append(f"{m}分钟")
        custom_text = "自定义: " + ("".join(parts) or "0分钟")
        ttk.Button(self.duration_frame, text=custom_text, width=16,
                   command=self.apply_default_duration).pack(side='left', padx=2)

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

        ttk.Label(frame, text="例外日期:").grid(row=9, column=0, sticky="nw", padx=5, pady=5)
        exc_f = ttk.Frame(frame); exc_f.grid(row=9, column=1, columnspan=3, sticky="we", padx=5, pady=5)
        self.exdate_listbox = tk.Listbox(exc_f, height=3, exportselection=False)
        self.exdate_listbox.bind("<Double-Button-1>", lambda e: self._edit_exdate())
        self.exdate_listbox.pack(fill=tk.X, pady=(0, 3))
        exc_btn_f = ttk.Frame(exc_f); exc_btn_f.pack(fill=tk.X)
        ttk.Button(exc_btn_f, text="添加日期", command=self._add_exdate, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(exc_btn_f, text="编辑", command=self._edit_exdate, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(exc_btn_f, text="移除选中", command=self._remove_exdate, width=8).pack(side=tk.LEFT, padx=2)
        ttk.Label(exc_f, text="例外日期在重复事件中跳过", foreground="gray").pack(anchor="w")

    def apply_duration(self, dur_str):
        try:
            start_dt = datetime.combine(self.start_date.get_date(),
                                        datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}", "%H:%M").time())
            if dur_str == "半天": delta = timedelta(hours=12)
            elif dur_str == "全天": delta = timedelta(days=1)
            elif dur_str == "30分钟": delta = timedelta(minutes=30)
            else:
                h = int(dur_str.replace("小时", ""))
                delta = timedelta(hours=h)
            end_dt = start_dt + delta
            self.end_date.set_date(end_dt.date())
            self.end_hour.set(end_dt.strftime("%H"))
            self.end_minute.set(end_dt.strftime("%M"))
        except Exception:
            logger.debug("忽略异常")

    def _add_exdate(self):
        from tkcalendar import Calendar
        w = tk.Toplevel(self.root); w.title("选择例外日期"); w.grab_set()
        cal = Calendar(w, date_pattern='yyyy-mm-dd')
        cal.pack(padx=10, pady=10)
        def confirm():
            d = cal.get_date()
            if d not in self.exdate_listbox.get(0, tk.END):
                self.exdate_listbox.insert(tk.END, d)
            w.destroy()
        ttk.Button(w, text="确定", command=confirm).pack(pady=5)

    def _edit_exdate(self):
        sel = self.exdate_listbox.curselection()
        if not sel: return
        idx = sel[0]
        old = self.exdate_listbox.get(idx)
        from tkcalendar import Calendar
        w = tk.Toplevel(self.root); w.title("编辑例外日期"); w.grab_set()
        cal = Calendar(w, date_pattern='yyyy-mm-dd')
        from datetime import datetime as _dt
        try: cal.selection_set(_dt.strptime(old, '%Y-%m-%d'))
        except Exception:
            logger.debug("忽略异常")
        cal.pack(padx=10, pady=10)
        def confirm():
            d = cal.get_date()
            if d not in self.exdate_listbox.get(0, tk.END):
                self.exdate_listbox.delete(idx)
                self.exdate_listbox.insert(idx, d)
            w.destroy()
        ttk.Button(w, text="确定", command=confirm).pack(pady=5)

    def _remove_exdate(self):
        sel = self.exdate_listbox.curselection()
        for i in reversed(sel):
            self.exdate_listbox.delete(i)

    def apply_default_duration(self):
        try:
            dur_min = self._get_default_duration_minutes()
            start_dt = datetime.combine(self.start_date.get_date(),
                                        datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}", "%H:%M").time())
            end_dt = start_dt + timedelta(minutes=dur_min)
            self.end_date.set_date(end_dt.date())
            self.end_hour.set(end_dt.strftime("%H"))
            self.end_minute.set(end_dt.strftime("%M"))
        except Exception:
            logger.debug("忽略异常")

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

    def create_attachment_tab(self):
        frame = ttk.LabelFrame(self.attachment_tab, text="事件附件")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.attachments = []
        btn_f = ttk.Frame(frame); btn_f.pack(fill=tk.X, pady=(0, 5))
        ttk.Button(btn_f, text="添加文件", command=self._attach_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="添加链接", command=self._attach_uri).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="编辑选中", command=self._attach_edit).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="移除选中", command=self._attach_remove).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="打开选中", command=self._attach_open).pack(side=tk.LEFT, padx=2)
        tree_f = ttk.Frame(frame); tree_f.pack(fill=tk.BOTH, expand=True)
        self.attach_tree = ttk.Treeview(tree_f, columns=('filename', 'size', 'type'), show="headings", height=6)
        self.attach_tree.heading('filename', text='文件名/链接')
        self.attach_tree.heading('size', text='大小')
        self.attach_tree.heading('type', text='类型')
        self.attach_tree.column('filename', width=280); self.attach_tree.column('size', width=80, anchor='center')
        self.attach_tree.column('type', width=120, anchor='center')
        tv_scroll = ttk.Scrollbar(tree_f, orient="vertical", command=self.attach_tree.yview)
        self.attach_tree.configure(yscrollcommand=tv_scroll.set)
        self.attach_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); tv_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.attach_tree.bind("<Double-1>", lambda e: self._attach_open())

    def _attach_file(self):
        paths = filedialog.askopenfilenames(title="选择附件文件", parent=self.root)
        for p in paths:
            try:
                with open(p, 'rb') as f:
                    data = f.read()
                name = os.path.basename(p)
                ext = os.path.splitext(name)[1].lower()
                fmt_map = {'.pdf': 'application/pdf', '.png': 'image/png', '.jpg': 'image/jpeg',
                           '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.doc': 'application/msword',
                           '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                           '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                           '.txt': 'text/plain', '.zip': 'application/zip', '.mp3': 'audio/mpeg'}
                fmttype = fmt_map.get(ext, 'application/octet-stream')
                rec = attachment_store.save(data, name, fmttype)
                rec['inline'] = True
                self.attachments.append(rec)
                self._attach_refresh()
            except Exception as e:
                messagebox.showerror("错误", f"无法读取文件:\n{e}", parent=self.root)

    def _attach_uri(self):
        uri = simpledialog.askstring("添加链接", "请输入附件链接 URL:", parent=self.root)
        if uri:
            self.attachments.append({'inline': False, 'uri': uri, 'filename': uri,
                                     'fmttype': 'text/uri-list', 'size': 0})
            self._attach_refresh()

    def _attach_remove(self):
        sel = self.attach_tree.selection()
        for item in reversed(sel):
            idx = self.attach_tree.index(item)
            if 0 <= idx < len(self.attachments):
                attachment_store.delete(self.attachments[idx])
                self.attachments.pop(idx)
        self._attach_refresh()

    def _attach_open(self):
        sel = self.attach_tree.selection()
        if not sel: return
        idx = self.attach_tree.index(sel[0])
        if idx < 0 or idx >= len(self.attachments): return
        a = self.attachments[idx]
        if a.get('inline'):
            data = attachment_store.read(a)
            if data is None:
                messagebox.showerror("错误", "附件文件不存在或无法读取", parent=self.root)
                return
            tmp = os.path.join(os.environ.get('TEMP', os.environ.get('TMP', '.')), a['filename'])
            try:
                with open(tmp, 'wb') as f:
                    f.write(data)
                os.startfile(tmp)
            except Exception as e:
                messagebox.showerror("错误", f"无法打开附件:\n{e}", parent=self.root)
        else:
            import webbrowser
            webbrowser.open(a['uri'])

    def _attach_edit(self):
        sel = self.attach_tree.selection()
        if not sel: return
        idx = self.attach_tree.index(sel[0])
        if idx < 0 or idx >= len(self.attachments): return
        a = self.attachments[idx]
        if a.get('inline'):
            path = filedialog.askopenfilename(title="选择替换文件", parent=self.root)
            if not path: return
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                name = os.path.basename(path)
                ext = os.path.splitext(name)[1].lower()
                fmt_map = {'.pdf': 'application/pdf', '.png': 'image/png', '.jpg': 'image/jpeg',
                           '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.doc': 'application/msword',
                           '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                           '.xls': 'application/vnd.ms-excel', '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                           '.txt': 'text/plain', '.zip': 'application/zip', '.mp3': 'audio/mpeg'}
                attachment_store.delete(a)
                new_rec = attachment_store.save(data, name, fmt_map.get(ext, 'application/octet-stream'))
                new_rec['inline'] = True
                self.attachments[idx] = new_rec
                self._attach_refresh()
            except Exception as e:
                messagebox.showerror("错误", f"无法替换文件:\n{e}", parent=self.root)
        else:
            uri = simpledialog.askstring("编辑链接", "修改附件链接 URL:", initialvalue=a.get('uri', ''), parent=self.root)
            if uri is not None:
                a['uri'] = uri
                a['filename'] = uri
                self._attach_refresh()

    def _attach_refresh(self):
        for item in self.attach_tree.get_children():
            self.attach_tree.delete(item)
        for a in self.attachments:
            name = a['filename'] if a.get('inline') else a.get('uri', '')
            size = self._format_size(a['size']) if a.get('inline') else '链接'
            fmt = a.get('fmttype', '')
            self.attach_tree.insert("", tk.END, values=(name, size, fmt))

    def _format_size(self, bytes_):
        if bytes_ < 1024: return f"{bytes_} B"
        elif bytes_ < 1024*1024: return f"{bytes_/1024:.1f} KB"
        else: return f"{bytes_/1024/1024:.1f} MB"

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
        other_frame = ttk.Frame(frame)
        other_frame.grid(row=7, column=1, columnspan=2, sticky="nsew", padx=5, pady=5)
        form_f = ttk.Frame(other_frame); form_f.pack(fill=tk.X)
        ttk.Label(form_f, text="键:").pack(side=tk.LEFT)
        self.other_key_var = tk.StringVar()
        ttk.Entry(form_f, textvariable=self.other_key_var, width=14).pack(side=tk.LEFT, padx=2)
        ttk.Label(form_f, text="值:").pack(side=tk.LEFT)
        self.other_val_var = tk.StringVar()
        ttk.Entry(form_f, textvariable=self.other_val_var, width=24).pack(side=tk.LEFT, padx=2)
        ttk.Button(form_f, text="增加", command=self._other_add).pack(side=tk.LEFT, padx=1)
        ttk.Button(form_f, text="修改", command=self._other_update).pack(side=tk.LEFT, padx=1)
        ttk.Button(form_f, text="删除", command=self._other_delete).pack(side=tk.LEFT, padx=1)
        tree_f = ttk.Frame(other_frame); tree_f.pack(fill=tk.BOTH, expand=True, pady=2)
        self.other_tree = ttk.Treeview(tree_f, columns=('key', 'value'), show="headings", height=5, selectmode='extended')
        self.other_tree.heading('key', text='键', command=lambda: self._other_sort('key'))
        self.other_tree.heading('value', text='值', command=lambda: self._other_sort('value'))
        self.other_tree.column('key', width=120); self.other_tree.column('value', width=250)
        tv_scroll = ttk.Scrollbar(tree_f, orient="vertical", command=self.other_tree.yview)
        self.other_tree.configure(yscrollcommand=tv_scroll.set)
        self.other_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); tv_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.other_tree.bind("<Double-1>", lambda e: self._other_edit())
        self.other_tree.bind("<Button-3>", self._other_popup)
        frame.grid_rowconfigure(7, weight=1); frame.grid_columnconfigure(1, weight=1)

    def _other_add(self):
        key = self.other_key_var.get().strip()
        value = self.other_val_var.get().strip()
        if not key:
            Toast.warning(self.root, "键不能为空")
            return
        self.other_fields.append({"key": key.upper(), "value": value})
        self._other_refresh()

    def _other_update(self):
        sel = self.other_tree.selection()
        if len(sel) != 1:
            Toast.warning(self.root, "请选择一个字段")
            return
        idx = self.other_tree.index(sel[0])
        key = self.other_key_var.get().strip()
        value = self.other_val_var.get().strip()
        if not key:
            Toast.warning(self.root, "键不能为空")
            return
        self.other_fields[idx] = {"key": key.upper(), "value": value}
        self._other_refresh()

    def _other_edit(self):
        sel = self.other_tree.selection()
        if len(sel) != 1:
            Toast.warning(self.root, "请选择一个字段")
            return
        idx = self.other_tree.index(sel[0])
        self.other_key_var.set(self.other_fields[idx]['key'])
        self.other_val_var.set(self.other_fields[idx]['value'])

    def _other_delete(self):
        sel = self.other_tree.selection()
        if not sel:
            Toast.warning(self.root, "请选择要删除的字段")
            return
        if not ConfirmDialog.ask(self.root, "确认", f"确定删除选中的 {len(sel)} 个字段?"):
            return
        indices = sorted([self.other_tree.index(i) for i in sel], reverse=True)
        for idx in indices:
            del self.other_fields[idx]
        self._other_refresh()

    def _other_duplicate(self):
        sel = self.other_tree.selection()
        if not sel:
            return
        new_items = []
        for iid in sel:
            idx = self.other_tree.index(iid)
            new_items.append(dict(self.other_fields[idx]))
        self.other_fields.extend(new_items)
        self._other_refresh()

    def _other_refresh(self):
        for item in self.other_tree.get_children():
            self.other_tree.delete(item)
        for f in self.other_fields:
            self.other_tree.insert("", tk.END, values=(f['key'], f['value']))
        self.other_key_var.set(""); self.other_val_var.set("")

    def _other_sort(self, col):
        self.other_fields.sort(key=lambda x: x[col])
        self._other_refresh()

    def _other_popup(self, e):
        iid = self.other_tree.identify_row(e.y)
        if iid:
            self.other_tree.selection_set(iid)
        sel = self.other_tree.selection()
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="编辑", command=self._other_edit, state=tk.NORMAL if len(sel) == 1 else tk.DISABLED)
        menu.add_command(label="删除", command=self._other_delete)
        menu.add_command(label="重复", command=self._other_duplicate)
        menu.post(e.x_root, e.y_root)

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
                self.transparency_var.set(TRANSPARENCY_REV_MAPPING.get(v.get('transparency'), "忙碌"))
            if v.get('allday'): self.allday_var.set(True)
            if v.get('force_reminder'): self.force_reminder_var.set(True)
            if v.get('repeat'): self.repeat_var.set(v.get('repeat'))
            if v.get('version'): self.version_var.set(v.get('version'))
            if v.get('sync_timezone') is not None: self.sync_tz_var.set(v.get('sync_timezone'))
        if is_edit_mode:
            try:
                parsed = parse_ical_event(v['ical'])
                if 'summary' in parsed: self.summary_var.set(parsed['summary'])
                if 'location' in parsed: self.location_var.set(parsed['location'])
                if 'description' in parsed: self.description_text.insert("1.0", parsed['description'])
                if 'categories' in parsed: self.categories_var.set(parsed['categories'])
                if 'priority' in parsed:
                    p = parsed['priority']; self.priority_var.set(p); self.priority_label.config(text=f" {p} ")
                if 'organizer' in parsed: self.organizer_var.set(parsed['organizer'])
                if 'status' in parsed: self.status_var.set(STATUS_REV_MAPPING.get(parsed['status'], "已确认"))
                if 'url' in parsed: self.url_var.set(parsed['url'])
                if 'sequence' in parsed: self.sequence_var.set(str(parsed['sequence']))
                if parsed.get('force_reminder'): self.force_reminder_var.set(True)
                if parsed.get('sync_tz'): self.sync_tz_var.set(True)
                if parsed.get('allday'): self.allday_var.set(True)
                if 'attendees' in parsed:
                    self.attendee_text.delete("1.0", tk.END)
                    if parsed['attendees']:
                        self.attendee_text.insert("1.0", "\n".join(parsed['attendees']))
                if 'other_fields' in parsed:
                    self.other_fields = parsed['other_fields']
                    self._other_refresh()
                dtstart = parsed.get('dtstart')
                if dtstart is not None:
                    if isinstance(dtstart, datetime):
                        self.start_date.set_date(dtstart.date())
                        self.start_hour.set(f"{dtstart.hour:02d}")
                        self.start_minute.set(f"{dtstart.minute:02d}")
                        if parsed.get('start_tzid'):
                            self.start_tz_var.set(TimezoneHelper.get_timezone_display_name(parsed['start_tzid']))
                    else:
                        self.start_date.set_date(dtstart)
                        self.allday_var.set(True)
                dtend = parsed.get('dtend')
                if dtend is not None:
                    if isinstance(dtend, datetime):
                        self.end_date.set_date(dtend.date())
                        self.end_hour.set(f"{dtend.hour:02d}")
                        self.end_minute.set(f"{dtend.minute:02d}")
                        if parsed.get('end_tzid'):
                            self.end_tz_var.set(TimezoneHelper.get_timezone_display_name(parsed['end_tzid']))
                    else:
                        self.end_date.set_date(dtend)
                if 'repeat' in parsed:
                    self.repeat_var.set(parsed['repeat'])
                    if parsed.get('custom_repeat'):
                        self.custom_repeat_data = parsed['custom_repeat']
                if 'end_cond' in parsed:
                    self.end_cond_var.set(parsed['end_cond'])
                if 'end_count' in parsed:
                    self.end_count_var.set(parsed['end_count'])
                if 'end_date' in parsed:
                    try: self.end_date_entry.set_date(parsed['end_date'])
                    except Exception: pass
                self.exdate_listbox.delete(0, tk.END)
                for d in parsed.get('exdates', []):
                    self.exdate_listbox.insert(tk.END, d)
                self.attachments = parsed.get('attachments', [])
                self._attach_refresh()
                self.alarms = parsed.get('alarms', [])
            except Exception as e: logger.error(f"解析 iCalendar 数据失败 (UID={self.uid_var.get()}): {e}")
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
            self.custom_repeat_data = {'freq': FREQ_MAPPING.get(self.freq_var.get(), "WEEKLY"), 'interval': self.interval_var.get()}
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
            act_display = ALARM_ACTION_REV_MAPPING.get(a.get('action', 'DISPLAY'))
            self.reminder_listbox.insert(tk.END, f"{act_display} - {trigger_str}")

    def delete_reminder(self):
        s = self.reminder_listbox.curselection()
        if s: del self.alarms[s[0]]; self.update_reminder_listbox()

    def add_reminder(self): self.reminder_listbox.selection_clear(0, tk.END); self._edit_reminder(-1)
    def edit_reminder(self):
        s = self.reminder_listbox.curselection()
        if s: self._edit_reminder(s[0])
        else: Toast.warning(self.root, "请先选择要编辑的提醒")

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
            presets = PRESET_REMINDERS_DEFAULT
            allday_presets = PRESET_ALLDAY_REMINDERS_DEFAULT
        else:
            p_val = self.db.get_setting('preset_reminders', ";".join(PRESET_REMINDERS_DEFAULT))
            a_val = self.db.get_setting('preset_allday_reminders', ";".join(PRESET_ALLDAY_REMINDERS_DEFAULT))
            presets = [x for x in p_val.split(';') if x]
            allday_presets = [x for x in a_val.split(';') if x]
            
        self.preset_reminders_listbox.delete(0, tk.END)
        for p in presets: self.preset_reminders_listbox.insert(tk.END, p)
        self.preset_allday_reminders_listbox.delete(0, tk.END)
        for p in allday_presets: self.preset_allday_reminders_listbox.insert(tk.END, p)

    def _collect_form_data(self):
        """将 UI 控件值收集为表单字典"""
        data = {
            'uid': self.uid_var.get(),
            'summary': self.summary_var.get(),
            'version': self.version_var.get(),
            'status': self.STATUS_MAPPING.get(self.status_var.get(), "CONFIRMED"),
            'is_edit': bool(self.initial.get('ical')),
            'allday': self.allday_var.get(),
            'priority': self.priority_var.get(),
            'transparency': self.TRANSPARENCY_MAPPING.get(self.transparency_var.get(), "OPAQUE"),
            'sequence': self.sequence_var.get() or "0",
            'repeat': self.repeat_var.get(),
            'custom_repeat': self.custom_repeat_data,
            'end_cond': self.end_cond_var.get(),
            'end_count': self.end_count_var.get(),
            'force_reminder': self.force_reminder_var.get(),
            'sync_tz': self.sync_tz_var.get(),
            'alarms': self.alarms,
            'attachments': self.attachments,
            'other_fields': self.other_fields,
        }
        loc = self.location_var.get()
        if loc: data['location'] = loc
        desc = self.description_text.get("1.0", "end-1c").strip()
        if desc: data['description'] = desc
        if self.organizer_var.get(): data['organizer'] = self.organizer_var.get()
        if self.url_var.get().strip(): data['url'] = self.url_var.get().strip()
        if self.categories_var.get(): data['categories'] = self.categories_var.get()

        attendees = []
        for line in self.attendee_text.get("1.0", "end-1c").split('\n'):
            if line.strip(): attendees.append(line.strip())
        data['attendees'] = attendees

        if self.allday_var.get():
            data['start_date'] = self.start_date.get_date()
            data['end_date'] = self.end_date.get_date()
        else:
            from datetime import time as dttime
            data['start_datetime'] = datetime.combine(
                self.start_date.get_date(),
                datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}", "%H:%M").time())
            data['end_datetime'] = datetime.combine(
                self.end_date.get_date(),
                datetime.strptime(f"{self.end_hour.get()}:{self.end_minute.get()}", "%H:%M").time())
            data['start_tzid'] = TimezoneHelper.extract_tz_id(self.start_tz_var.get())
            data['end_tzid'] = TimezoneHelper.extract_tz_id(self.end_tz_var.get())

        if self.repeat_var.get() != "不重复" and self.end_cond_var.get() == "按日期结束":
            data['end_date_entry'] = self.end_date_entry.get_date()

        exdates = self.exdate_listbox.get(0, tk.END)
        if exdates: data['exdates'] = list(exdates)

        return data

    def generate_ical(self):
        return build_ical(self._collect_form_data())

    def show_raw_data(self):
        win = tk.Toplevel(self.root); win.title("原始数据")
        sb_v = ttk.Scrollbar(win, orient=tk.VERTICAL)
        txt = tk.Text(win, wrap=tk.CHAR, yscrollcommand=sb_v.set)
        RightClickMenu(txt, "text", actions=["copy", None, "select_all"])
        sb_v.config(command=txt.yview)
        sb_v.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(fill=tk.BOTH, expand=True)
        content = self.initial.get('ical') or self.generate_ical()
        txt.insert(tk.END, content)
        txt.config(state=tk.DISABLED)

    def ok(self):
        summary = self.summary_var.get().strip()
        if not summary: messagebox.showwarning("提示", "请填写事件标题", parent=self.root); return
        if not self.allday_var.get():
            try: datetime.strptime(f"{self.start_hour.get()}:{self.start_minute.get()}", "%H:%M"); datetime.strptime(f"{self.end_hour.get()}:{self.end_minute.get()}", "%H:%M")
            except Exception: messagebox.showwarning("提示", "请填写完整的时间", parent=self.root); return
        self.raw_ical = self.generate_ical(); self.result = {'summary': summary}; self.root.destroy()

    def cancel(self): self.result = None; self.root.destroy()
    def get_raw_ical(self): return self.raw_ical
    def set_start_now(self): self.start_date.set_date(datetime.now())
    def set_end_now(self):
        n = datetime.now() + timedelta(hours=1); self.end_date.set_date(n); self.end_hour.set(f"{n.hour:02d}"); self.end_minute.set("00")
