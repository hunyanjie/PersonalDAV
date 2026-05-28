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
from utils.encoding_helper import smart_quoted_printable_encode, should_encode, decode_ical_value

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

        self._loading = True # 标记正在加载数据，防止 Trace 干扰
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
        
        # 强制触发一次最终的 UI 状态同步
        self.toggle_allday()
        self.toggle_sync_tz()
        self.on_status_changed()
        self.update_reminder_listbox()

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
            self.initial.setdefault('end_cond', self.db.get_setting('default_end_cond', '永不结束'))
            self.initial.setdefault('end_count', self.db.get_setting('default_end_count', '5'))
            self.initial.setdefault('duration', self.db.get_setting('default_duration', '1'))
            # 加载时区同步设置
            self.initial.setdefault('sync_timezone', self.db.get_setting('default_sync_timezone', 'True') == 'True')
            
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
        status_combo = ttk.Combobox(frame, textvariable=self.status_var, values=list(self.STATUS_MAPPING.keys()), state="readonly")
        status_combo.grid(row=4, column=1, sticky="w", padx=5)
        self.status_var.trace("w", self.on_status_changed)
        
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

        # 初始化默认值：开始时间为当前时间，结束时间为当前时间+1小时
        now = datetime.now()
        self.start_hour.set(f"{now.hour:02d}")
        self.start_minute.set("00")
        end = now + timedelta(hours=1)
        self.end_date.set_date(end)
        self.end_hour.set(f"{end.hour:02d}")
        self.end_minute.set("00")

        tz_list = TimezoneHelper.get_localized_timezones()
        ttk.Label(frame, text="开始时区:").grid(row=3, column=0, sticky="w", padx=5)
        self.start_tz_var = tk.StringVar()
        self.start_tz_combo = ttk.Combobox(frame, textvariable=self.start_tz_var, values=tz_list, width=60, state="readonly")
        self.start_tz_combo.grid(row=3, column=1, sticky="we", padx=5, pady=2)
        
        # 增加追踪和绑定：确保鼠标滚轮、键盘选择、点击选择都能同步 (1:1 还原旧版卓越体验)
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
        self.end_tz_combo.config(state="disabled")  # 默认勾选相同时区，初始化时禁用结束时时区

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
        """快速调整逻辑"""
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

        # 提醒列表区域 - 使用 pack
        list_frame = ttk.LabelFrame(main_frame, text="提醒列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        list_inner = ttk.Frame(list_frame)
        list_inner.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.reminder_listbox = tk.Listbox(list_inner, height=5)
        self.reminder_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(list_inner, command=self.reminder_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.reminder_listbox.config(yscrollcommand=scrollbar.set)

        # 提醒操作按钮
        btn_frame = ttk.Frame(list_frame)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(btn_frame, text="添加提醒", command=self.add_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="编辑提醒", command=self.edit_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除提醒", command=self.delete_reminder).pack(side=tk.LEFT, padx=2)
        ttk.Label(btn_frame, text="双击列表项编辑", foreground="gray").pack(side=tk.RIGHT, padx=10)

        # 绑定双击事件
        self.reminder_listbox.bind("<Double-1>", lambda e: self.edit_reminder())

        # 提醒设置区域 - 使用 grid 布局
        settings_frame = ttk.LabelFrame(main_frame, text="提醒设置")
        settings_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(settings_frame, text="提醒类型:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.reminder_type_var = tk.StringVar(value="显示")
        ttk.Combobox(settings_frame, textvariable=self.reminder_type_var, values=["显示", "声音", "邮件"], state="readonly", width=10).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        self.reminder_type_var.trace("w", self.on_reminder_type_change)

        ttk.Label(settings_frame, text="触发方式:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.reminder_trigger_type = tk.StringVar(value="relative")
        ttk.Radiobutton(settings_frame, text="提前时间提醒", variable=self.reminder_trigger_type, value="relative", command=self.toggle_reminder_trigger_type).grid(row=1, column=1, sticky="w", padx=5)
        ttk.Radiobutton(settings_frame, text="指定时间提醒", variable=self.reminder_trigger_type, value="absolute", command=self.toggle_reminder_trigger_type).grid(row=1, column=2, sticky="w", padx=5)

        # 提前时间控件
        self.reminder_time_frame = ttk.Frame(settings_frame)
        self.reminder_time_frame.grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        self.reminder_days_var = tk.StringVar(value="0")
        ttk.Label(self.reminder_time_frame, text="天:").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=365, textvariable=self.reminder_days_var, width=3).grid(row=0, column=1, padx=2)

        self.reminder_hours_var = tk.StringVar(value="0")
        ttk.Label(self.reminder_time_frame, text="小时:").grid(row=0, column=2, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=23, textvariable=self.reminder_hours_var, width=3).grid(row=0, column=3, padx=2)

        self.reminder_minutes_var = tk.StringVar(value="15")
        ttk.Label(self.reminder_time_frame, text="分钟:").grid(row=0, column=4, sticky="w")
        ttk.Spinbox(self.reminder_time_frame, from_=0, to=59, textvariable=self.reminder_minutes_var, width=3).grid(row=0, column=5, padx=2)

        # 绝对时间控件
        self.absolute_trigger_frame = ttk.Frame(settings_frame)
        self.absolute_trigger_frame.grid(row=3, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        self.absolute_trigger_frame.grid_remove()

        ttk.Label(self.absolute_trigger_frame, text="提醒日期:").grid(row=0, column=0, sticky="w")
        self.absolute_trigger_date = DateEntry(self.absolute_trigger_frame, date_pattern='yyyy-mm-dd', width=12)
        self.absolute_trigger_date.grid(row=0, column=1, padx=5)

        ttk.Label(self.absolute_trigger_frame, text="时间:").grid(row=0, column=2, padx=(10, 0))
        self.absolute_trigger_hour = ttk.Combobox(self.absolute_trigger_frame, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly")
        self.absolute_trigger_hour.grid(row=0, column=3, padx=5)
        self.absolute_trigger_hour.set("09")

        ttk.Label(self.absolute_trigger_frame, text=":").grid(row=0, column=4)
        self.absolute_trigger_minute = ttk.Combobox(self.absolute_trigger_frame, width=3, values=[f"{m:02d}" for m in range(0, 60, 5)], state="readonly")
        self.absolute_trigger_minute.grid(row=0, column=5, padx=5)
        self.absolute_trigger_minute.set("00")

        # 提醒重复设置
        repeat_frame = ttk.Frame(settings_frame)
        repeat_frame.grid(row=4, column=0, columnspan=3, sticky="w", padx=5, pady=5)

        ttk.Label(repeat_frame, text="重复次数:").grid(row=0, column=0, sticky="w")
        self.reminder_repeat_var = tk.StringVar(value="0")
        ttk.Spinbox(repeat_frame, from_=0, to=999, textvariable=self.reminder_repeat_var, width=3).grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(repeat_frame, text="间隔时间:").grid(row=0, column=2, sticky="w", padx=(10, 0))
        self.reminder_duration_days_var = tk.StringVar(value="0")
        ttk.Label(repeat_frame, text="天:").grid(row=0, column=3, sticky="w")
        ttk.Spinbox(repeat_frame, from_=0, to=365, textvariable=self.reminder_duration_days_var, width=3).grid(row=0, column=4, padx=2)

        self.reminder_duration_hours_var = tk.StringVar(value="0")
        ttk.Label(repeat_frame, text="小时:").grid(row=0, column=5, sticky="w")
        ttk.Spinbox(repeat_frame, from_=0, to=23, textvariable=self.reminder_duration_hours_var, width=3).grid(row=0, column=6, padx=2)

        self.reminder_duration_minutes_var = tk.StringVar(value="15")
        ttk.Label(repeat_frame, text="分钟:").grid(row=0, column=7, sticky="w")
        ttk.Spinbox(repeat_frame, from_=0, to=59, textvariable=self.reminder_duration_minutes_var, width=3).grid(row=0, column=8, padx=2)

        # 强制提醒
        self.force_reminder_var = tk.BooleanVar()
        ttk.Checkbutton(settings_frame, text="强制提醒", variable=self.force_reminder_var).grid(row=5, column=0, columnspan=2, sticky="w", padx=5, pady=10)

        # 提醒类型特定控件
        self.display_frame = ttk.Frame(settings_frame)
        self.display_frame.grid(row=6, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        self.display_frame.grid_remove()

        self.audio_attach_frame = ttk.Frame(settings_frame)
        self.audio_attach_frame.grid(row=6, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        self.audio_attach_frame.grid_remove()

        self.email_frame = ttk.Frame(settings_frame)
        self.email_frame.grid(row=6, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        self.email_frame.grid_remove()

        # 显示提醒描述框
        ttk.Label(self.display_frame, text="提醒描述:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.display_description = tk.Text(self.display_frame, height=3, width=40)
        self.display_description.configure(undo=True, autoseparators=True, maxundo=-1)
        RightClickMenu(self.display_description, "text")
        self.display_description.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        display_scrollbar = ttk.Scrollbar(self.display_frame, command=self.display_description.yview)
        display_scrollbar.grid(row=0, column=2, sticky="ns")
        self.display_description.config(yscrollcommand=display_scrollbar.set)

        # 声音提醒附件框
        ttk.Label(self.audio_attach_frame, text="音频文件地址:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.audio_attach_var = tk.StringVar()
        self.audio_attach_entry = ttk.Entry(self.audio_attach_frame, textvariable=self.audio_attach_var, width=40)
        RightClickMenu(self.audio_attach_entry)
        self.audio_attach_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        # 邮件提醒框
        ttk.Label(self.email_frame, text="收件人邮箱:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.email_attendee_var = tk.StringVar()
        self.email_attendee_entry = ttk.Entry(self.email_frame, textvariable=self.email_attendee_var, width=40)
        RightClickMenu(self.email_attendee_entry)
        self.email_attendee_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        ttk.Label(self.email_frame, text="邮件主题:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.email_summary_var = tk.StringVar()
        self.email_summary_entry = ttk.Entry(self.email_frame, textvariable=self.email_summary_var, width=40)
        RightClickMenu(self.email_summary_entry)
        self.email_summary_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        ttk.Label(self.email_frame, text="邮件正文:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.email_description = tk.Text(self.email_frame, height=3, width=40)
        self.email_description.configure(undo=True, autoseparators=True, maxundo=-1)
        RightClickMenu(self.email_description, "text")
        self.email_description.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)
        email_scrollbar = ttk.Scrollbar(self.email_frame, command=self.email_description.yview)
        email_scrollbar.grid(row=2, column=2, sticky="ns")
        self.email_description.config(yscrollcommand=email_scrollbar.set)

        ttk.Label(self.email_frame, text="邮件附件:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.email_attach_var = tk.StringVar()
        self.email_attach_entry = ttk.Entry(self.email_frame, textvariable=self.email_attach_var, width=40)
        RightClickMenu(self.email_attach_entry)
        self.email_attach_entry.grid(row=3, column=1, sticky="ew", padx=5, pady=5)

        # 预设提醒列表
        preset_section = ttk.LabelFrame(main_frame, text="预设提醒（双击应用）")
        preset_section.pack(fill=tk.X, padx=5, pady=5)

        preset_frame = ttk.Frame(preset_section)
        preset_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(preset_frame, text="常规事件:").grid(row=0, column=0, sticky="w")
        self.preset_reminders_listbox = tk.Listbox(preset_frame, height=3, width=30)
        self.preset_reminders_listbox.grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.preset_reminders_listbox.bind("<Double-1>", lambda e: self.apply_preset_reminder(False))

        ttk.Label(preset_frame, text="全天事件:").grid(row=0, column=1, sticky="w")
        self.preset_allday_reminders_listbox = tk.Listbox(preset_frame, height=3, width=30)
        self.preset_allday_reminders_listbox.grid(row=1, column=1, sticky="w", padx=5, pady=5)
        self.preset_allday_reminders_listbox.bind("<Double-1>", lambda e: self.apply_preset_reminder(True))

        # 初始化控件状态
        self.on_reminder_type_change()
        self.toggle_reminder_trigger_type()

        # 加载预设提醒
        self.load_preset_reminders()

    def create_advanced_tab(self):
        frame = ttk.LabelFrame(self.advanced_tab, text="高级设置")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Label(frame, text="分类:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.categories_var = tk.StringVar()
        categories_entry = ttk.Entry(frame, textvariable=self.categories_var, width=30)
        categories_entry.grid(row=0, column=1, sticky="we", padx=5)
        RightClickMenu(categories_entry)

        ttk.Label(frame, text="优先级:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.priority_var = tk.IntVar(value=5)
        priority_frame = ttk.Frame(frame)
        priority_frame.grid(row=1, column=1, sticky="w", padx=5)
        
        # 使用 tk.Scale 替代 ttk.Scale 以获得更好的整数控制和回显 (1:1 还原)
        self.priority_scale = tk.Scale(priority_frame, from_=0, to=9, variable=self.priority_var, 
                                      orient=tk.HORIZONTAL, length=150, showvalue=0,
                                      command=lambda v: self.priority_label.config(text=f" {int(float(v))} "))
        self.priority_scale.grid(row=0, column=0, sticky="w")
        
        self.priority_label = ttk.Label(priority_frame, text=" 5 ", width=3, relief=tk.RIDGE, anchor="center")
        self.priority_label.grid(row=0, column=1, padx=5)
        ttk.Label(priority_frame, text="(0=最低, 9=最高)").grid(row=0, column=2, padx=5)

        ttk.Label(frame, text="透明度:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.transparency_var = tk.StringVar(value="忙碌")
        ttk.Combobox(frame, textvariable=self.transparency_var, values=["忙碌", "空闲"], state="readonly").grid(row=2, column=1, sticky="w", padx=5)

        ttk.Label(frame, text="组织者:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        self.organizer_var = tk.StringVar()
        organizer_entry = ttk.Entry(frame, textvariable=self.organizer_var, width=40)
        organizer_entry.grid(row=3, column=1, sticky="we", padx=5)
        RightClickMenu(organizer_entry)

        ttk.Label(frame, text="序列号:").grid(row=4, column=0, sticky="w", padx=5, pady=5)
        self.sequence_var = tk.StringVar(value="0")
        sequence_entry = ttk.Entry(frame, textvariable=self.sequence_var, width=10)
        sequence_entry.grid(row=4, column=1, sticky="w", padx=5)
        RightClickMenu(sequence_entry)

        ttk.Label(frame, text="URL:").grid(row=5, column=0, sticky="w", padx=5, pady=5)
        self.url_var = tk.StringVar()
        url_entry = ttk.Entry(frame, textvariable=self.url_var, width=40)
        url_entry.grid(row=5, column=1, sticky="we", padx=5)
        RightClickMenu(url_entry)

        ttk.Label(frame, text="参与者:").grid(row=6, column=0, sticky="nw", padx=5, pady=5)
        self.attendee_text = tk.Text(frame, height=3, width=40)
        self.attendee_text.grid(row=6, column=1, sticky="nsew", padx=5, pady=5)
        RightClickMenu(self.attendee_text, "text")
        attendee_scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.attendee_text.yview)
        attendee_scrollbar.grid(row=6, column=2, sticky="ns")
        self.attendee_text.config(yscrollcommand=attendee_scrollbar.set)

        # 其他 iCalendar 字段 (防止数据丢失)
        ttk.Label(frame, text="其他字段:").grid(row=7, column=0, sticky="nw", padx=5, pady=5)
        self.other_text = tk.Text(frame, height=4, width=40)
        self.other_text.grid(row=7, column=1, sticky="nsew", padx=5, pady=5)
        RightClickMenu(self.other_text, "text")
        other_scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.other_text.yview)
        other_scrollbar.grid(row=7, column=2, sticky="ns")
        self.other_text.config(yscrollcommand=other_scrollbar.set)

    def get_local_tz_str(self):
        return TimezoneHelper.get_local_timezone_id()

    def set_initial_values(self):
        """1:1 还原数据回显逻辑，支持 DTO 模型"""
        m = self.model
        self.uid_var.set(m.uid)
        self.summary_var.set(m.summary)
        
        # 寻找本地化名称并自动选择 (1:1 还原旧版)
        local_tz_id = self.get_local_tz_str()
        local_display = TimezoneHelper.get_timezone_display_name(local_tz_id)
        
        # 优先匹配带 [本地] 标签的项
        self.start_tz_var.set(local_display)
        self.end_tz_var.set(local_display)

        v = self.initial
        is_edit_mode = 'ical' in v and v['ical']
        self.end_cond_var.set(v.get('end_cond', '永不结束'))
        self.end_count_var.set(v.get('end_count', '5'))
        if 'end_date' in v: self.end_date_entry.set_date(v['end_date'])

        # 新建事件时应用设置中的默认值
        if not is_edit_mode:
            if v.get('status'):
                self.status_var.set(self.STATUS_REV_MAPPING.get(v.get('status'), "已确认"))
            if v.get('priority') is not None:
                p = int(v.get('priority'))
                self.priority_var.set(p)
                self.priority_label.config(text=f" {p} ")
            if v.get('transparency'):
                trans_map = {"OPAQUE": "忙碌", "TRANSPARENT": "空闲"}
                self.transparency_var.set(trans_map.get(v.get('transparency'), "忙碌"))
            if v.get('allday'):
                self.allday_var.set(True)
            if v.get('force_reminder'):
                self.force_reminder_var.set(True)
            if v.get('repeat'):
                self.repeat_var.set(v.get('repeat'))
            if v.get('version'):
                self.version_var.set(v.get('version'))
            if v.get('sync_timezone') is not None:
                self.sync_tz_var.set(v.get('sync_timezone'))

        if is_edit_mode:
            try:
                ical = vobject.readOne(v['ical'])
                ev = ical.vevent
                if hasattr(ev, 'summary'): self.summary_var.set(decode_ical_value(ev.summary.value))
                if hasattr(ev, 'location'): self.location_var.set(decode_ical_value(ev.location.value))
                if hasattr(ev, 'description'): self.description_text.insert("1.0", decode_ical_value(ev.description.value))
                if hasattr(ev, 'categories'): self.categories_var.set(decode_ical_value(",".join(ev.categories.value) if hasattr(ev.categories, 'value') else ev.categories.value))
                if hasattr(ev, 'priority'):
                    p = int(ev.priority.value)
                    self.priority_var.set(p)
                    self.priority_label.config(text=f" {p} ")
                if hasattr(ev, 'organizer'): self.organizer_var.set(decode_ical_value(ev.organizer.value))

                if hasattr(ev, 'status'):
                    self.status_var.set(self.STATUS_REV_MAPPING.get(ev.status.value, "已确认"))

                if hasattr(ev, 'url'):
                    self.url_var.set(decode_ical_value(ev.url.value))
                
                if hasattr(ev, 'sequence'):
                    self.sequence_var.set(str(ev.sequence.value))
                
                # 填充参与者 (优化去重逻辑)
                self.attendee_text.delete("1.0", tk.END)
                attendee_values = set()
                if hasattr(ev, 'attendee_list'):
                    for a in ev.attendee_list:
                        val = decode_ical_value(a.value)
                        if val not in attendee_values:
                            attendee_values.add(val)
                elif hasattr(ev, 'attendee'):
                    val = decode_ical_value(ev.attendee.value)
                    attendee_values.add(val)
                
                if attendee_values:
                    self.attendee_text.insert("1.0", "\n".join(sorted(list(attendee_values))))

                # 处理其他扩展字段 (防止数据丢失)
                others = []
                standard = ['UID', 'SUMMARY', 'LOCATION', 'DESCRIPTION', 'STATUS', 'DTSTART', 'DTEND', 'RRULE', 
                            'VALARM', 'CATEGORIES', 'PRIORITY', 'TRANSP', 'ORGANIZER', 'SEQUENCE', 'URL', 'ATTENDEE', 
                            'VERSION', 'PRODID', 'X-ALLDAY']

                for child in ev.contents.values():
                    for item in child:
                        name = item.name.upper()
                        if name not in standard:
                            others.append(f"{name}: {item.value}")

                self.other_text.insert(tk.END, "\n".join(others))

                # 时间解析还原
                if hasattr(ev, 'dtstart'):
                    dt = ev.dtstart.value
                    if isinstance(dt, datetime):
                        self.start_date.set_date(dt.date())
                        self.start_hour.set(f"{dt.hour:02d}")
                        self.start_minute.set(f"{dt.minute:02d}")
                        if 'TZID' in ev.dtstart.params:
                            tzid = ev.dtstart.params['TZID'][0]
                            display = TimezoneHelper.get_timezone_display_name(tzid)
                            self.start_tz_var.set(display)
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
                            display = TimezoneHelper.get_timezone_display_name(tzid)
                            self.end_tz_var.set(display)
                    else:
                        # 全天事件结束时间通常是非包含的，需减去一天回显
                        self.end_date.set_date(dt - timedelta(days=1))

                # 解析重复规则
                if hasattr(ev, 'rrule'):
                    rrule_str = ev.rrule.value
                    parts = dict(item.split('=') for item in rrule_str.split(';') if '=' in item)
                    freq = parts.get('FREQ')
                    interval = parts.get('INTERVAL', '1')
                    
                    if freq == 'DAILY' and interval == '1': self.repeat_var.set('每天')
                    elif freq == 'WEEKLY' and interval == '1': self.repeat_var.set('每周')
                    elif freq == 'WEEKLY' and interval == '2': self.repeat_var.set('每两周')
                    elif freq == 'MONTHLY' and interval == '1': self.repeat_var.set('每月')
                    elif freq == 'YEARLY' and interval == '1': self.repeat_var.set('每年')
                    else:
                        self.repeat_var.set('自定义')
                        self.custom_repeat_data = {'freq': freq, 'interval': interval}
                    
                    if 'UNTIL' in parts:
                        self.end_cond_var.set('按日期结束')
                        try:
                            until_dt = parser.parse(parts['UNTIL'])
                            self.end_date_entry.set_date(until_dt.date())
                        except: pass
                    elif 'COUNT' in parts:
                        self.end_cond_var.set('按次数结束')
                        self.end_count_var.set(parts['COUNT'])
                    else:
                        self.end_cond_var.set('永不结束')

                # 解析 VALARM 组件 - 1:1 还原旧版鲁棒遍历逻辑
                self.alarms = []
                # 尝试两种方式以确保最大兼容性
                # 方式 1: 直接遍历 contents
                valarms = ev.contents.get('valarm', [])
                # 方式 2: 使用 getChildrenFallback (针对某些旧版 vobject)
                if not valarms:
                    valarms = [c for c in ev.getChildren() if c.name.upper() == 'VALARM']
                
                for alarm in valarms:
                    alarm_data = {'action': alarm.action.value if hasattr(alarm, 'action') else 'DISPLAY'}
                    trigger = alarm.trigger.value if hasattr(alarm, 'trigger') else None
                    if trigger:
                        alarm_data['trigger'] = trigger
                    # 解析声音/邮件提醒的额外属性
                    if hasattr(alarm, 'attach'):
                        alarm_data['attach'] = alarm.attach.value
                    if hasattr(alarm, 'summary'):
                        alarm_data['summary'] = alarm.summary.value
                    if hasattr(alarm, 'description'):
                        alarm_data['description'] = alarm.description.value
                    if hasattr(alarm, 'attendee'):
                        alarm_data['attendee'] = alarm.attendee.value
                    self.alarms.append(alarm_data)
            except Exception as e:
                logger.error(f"解析 iCalendar 数据失败: {e}")

    def toggle_allday(self):
        """切换全天事件模式"""
        is_allday = self.allday_var.get()
        state = "disabled" if is_allday else "readonly"
        for w in [self.start_hour, self.start_minute, self.end_hour, self.end_minute]: 
            w.config(state=state)
        
        # 全天事件不需要时区，禁用时区选择器和同步勾选框 (1:1 还原旧版加固)
        if is_allday:
            self.start_tz_combo.config(state="disabled")
            self.end_tz_combo.config(state="disabled")
            self.sync_tz_check.config(state="disabled")
            self.toggle_sync_tz()
        else:
            self.start_tz_combo.config(state="readonly")
            self.sync_tz_check.config(state="normal")
            self.toggle_sync_tz()

    def toggle_sync_tz(self):
        """切换时区同步状态"""
        is_allday = self.allday_var.get()
        if is_allday:
            # 如果是全天事件，强制禁用所有时区控件，无视同步勾选
            self.start_tz_combo.config(state="disabled")
            self.end_tz_combo.config(state="disabled")
            return

        if self.sync_tz_var.get():
            self.end_tz_var.set(self.start_tz_var.get())
            self.end_tz_combo.config(state="disabled")
        else:
            self.end_tz_combo.config(state="readonly")

    def _on_start_tz_change(self, *args):
        """当开始时区改变时同步结束时区 - 支持滚轮和点击"""
        if getattr(self, '_loading', False): return
        if not self.allday_var.get() and self.sync_tz_var.get():
            val = self.start_tz_var.get()
            if val != self.end_tz_var.get():
                self.end_tz_var.set(val)

    def _on_tz_wheel(self, event):
        """鼠标滚轮调整时区时，延迟一小段时间确保值已写入变量再同步"""
        if getattr(self, '_loading', False): return
        self.root.after(10, self._on_start_tz_change)

    def on_status_changed(self, *args):
        """状态变更监听 - 已取消禁用时间/提醒，待定只禁用提醒，支持快照恢复"""
        if getattr(self, '_loading', False): return
        status = self.status_var.get()
        
        # 保存快照以供恢复 (1:1 还原旧版逻辑)
        if not hasattr(self, 'original_settings'):
            self.original_settings = {
                'start_date': self.start_date.get_date(),
                'start_hour': self.start_hour.get(),
                'start_minute': self.start_minute.get(),
                'end_date': self.end_date.get_date(),
                'end_hour': self.end_hour.get(),
                'end_minute': self.end_minute.get(),
                'alarms': self.alarms.copy()
            }

        if status == "已取消":
            self.notebook.tab(self.time_tab, state="disabled")
            self.notebook.tab(self.reminder_tab, state="disabled")
        elif status == "待定":
            self.notebook.tab(self.time_tab, state="normal")
            self.notebook.tab(self.reminder_tab, state="disabled")
        else:
            # 切回正常状态时恢复快照
            if hasattr(self, 'original_settings'):
                s = self.original_settings
                self.start_date.set_date(s['start_date'])
                self.start_hour.set(s['start_hour'])
                self.start_minute.set(s['start_minute'])
                self.end_date.set_date(s['end_date'])
                self.end_hour.set(s['end_hour'])
                self.end_minute.set(s['end_minute'])
                self.alarms = s['alarms'].copy()
                self.update_reminder_listbox()
            
            self.notebook.tab(self.time_tab, state="normal")
            self.notebook.tab(self.reminder_tab, state="normal")

    def on_repeat_changed(self, *args):
        if getattr(self, '_loading', False): return
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

    def add_reminder(self):
        """添加提醒对话框"""
        self.reminder_listbox.selection_clear(0, tk.END)
        self._edit_reminder(-1)

    def edit_reminder(self):
        """编辑选中的提醒"""
        s = self.reminder_listbox.curselection()
        if s:
            self._edit_reminder(s[0])
        else:
            messagebox.showwarning("提示", "请先选择要编辑的提醒", parent=self.root)

    def _edit_reminder(self, index):
        """编辑或添加提醒的内部方法"""
        dialog = tk.Toplevel(self.root)
        dialog.title("编辑提醒" if index >= 0 else "添加提醒")
        # dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 提醒类型
        ttk.Label(main_frame, text="提醒类型:").grid(row=0, column=0, sticky="w", pady=5)
        reminder_type = tk.StringVar(value="显示")
        ttk.Combobox(main_frame, textvariable=reminder_type, values=["显示", "声音", "邮件"], state="readonly").grid(row=0, column=1, sticky="w", padx=5, pady=5)

        # 触发方式
        ttk.Label(main_frame, text="触发方式:").grid(row=1, column=0, sticky="w", pady=5)
        trigger_type = tk.StringVar(value="relative")
        ttk.Radiobutton(main_frame, text="提前时间", variable=trigger_type, value="relative").grid(row=1, column=1, sticky="w", padx=5)
        ttk.Radiobutton(main_frame, text="指定时间", variable=trigger_type, value="absolute").grid(row=1, column=2, sticky="w", padx=5)

        # 提前时间
        time_frame = ttk.Frame(main_frame)
        time_frame.grid(row=2, column=0, columnspan=3, sticky="w", padx=5, pady=10)

        # 从数据库加载默认偏移量
        def_days = self.db.get_setting('default_reminder_days', '0') if self.db else "0"
        def_hours = self.db.get_setting('default_reminder_hours', '0') if self.db else "0"
        def_mins = self.db.get_setting('default_reminder_minutes', '15') if self.db else "15"

        days_var = tk.StringVar(value=def_days)
        hours_var = tk.StringVar(value=def_hours)
        minutes_var = tk.StringVar(value=def_mins)

        ttk.Label(time_frame, text="天:").grid(row=0, column=0)
        ttk.Spinbox(time_frame, from_=0, to=365, textvariable=days_var, width=3).grid(row=0, column=1, padx=2)
        ttk.Label(time_frame, text="小时:").grid(row=0, column=2)
        ttk.Spinbox(time_frame, from_=0, to=23, textvariable=hours_var, width=3).grid(row=0, column=3, padx=2)
        ttk.Label(time_frame, text="分钟:").grid(row=0, column=4)
        ttk.Spinbox(time_frame, from_=0, to=59, textvariable=minutes_var, width=3).grid(row=0, column=5, padx=2)

        # 指定时间
        abs_frame = ttk.Frame(main_frame)
        abs_frame.grid(row=3, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        abs_frame.grid_remove()

        abs_date = DateEntry(abs_frame, date_pattern='yyyy-mm-dd', width=12)
        abs_date.grid(row=0, column=0, padx=5)
        abs_hour = ttk.Combobox(abs_frame, width=3, values=[f"{h:02d}" for h in range(24)], state="readonly")
        abs_hour.grid(row=0, column=1, padx=2)
        abs_hour.set("09")
        ttk.Label(abs_frame, text=":").grid(row=0, column=2)
        abs_minute = ttk.Combobox(abs_frame, width=3, values=[f"{m:02d}" for m in range(0, 60, 5)], state="readonly")
        abs_minute.grid(row=0, column=3, padx=5)
        abs_minute.set("00")

        # 时区选择（用于绝对时间触发）
        tz_list = TimezoneHelper.get_localized_timezones()
        abs_tz_var = tk.StringVar()
        abs_tz_combo = ttk.Combobox(abs_frame, textvariable=abs_tz_var, values=tz_list, width=35, state="readonly")
        abs_tz_combo.grid(row=0, column=4, padx=5)
        # 默认选中本地时区
        local_tz = TimezoneHelper.get_local_timezone_id()
        for opt in tz_list:
            if opt.startswith(local_tz):
                abs_tz_var.set(opt)
                break

        def toggle_trigger():
            if trigger_type.get() == "relative":
                time_frame.grid()
                abs_frame.grid_remove()
            else:
                time_frame.grid_remove()
                abs_frame.grid()
        trigger_type.trace("w", lambda *args: toggle_trigger())

        # 添加额外字段到对话框
        extra_frame = ttk.LabelFrame(dialog, text="扩展设置")
        extra_frame.pack(fill=tk.X, padx=10, pady=5)

        audio_attach_entry = ttk.Entry(extra_frame, width=40)
        ttk.Label(extra_frame, text="音频文件:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        audio_attach_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        email_attendee_entry = ttk.Entry(extra_frame, width=40)
        ttk.Label(extra_frame, text="收件人:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        email_attendee_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        email_summary_entry = ttk.Entry(extra_frame, width=40)
        ttk.Label(extra_frame, text="邮件主题:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        email_summary_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        email_description = tk.Text(extra_frame, height=3, width=40)
        ttk.Label(extra_frame, text="邮件正文:").grid(row=3, column=0, sticky="nw", padx=5, pady=5)
        email_description.grid(row=3, column=1, sticky="nsew", padx=5, pady=5)

        # 填充现有数据
        if index >= 0:
            alarm = self.alarms[index]
            action_map = {"DISPLAY": "显示", "AUDIO": "声音", "EMAIL": "邮件"}
            reminder_type.set(action_map.get(alarm.get('action', 'DISPLAY'), '显示'))

            trigger = alarm.get('trigger')
            if isinstance(trigger, datetime):
                trigger_type.set("absolute")
                # 如果是 UTC 时间，转换为本地时间显示
                if trigger.tzinfo and trigger.tzinfo != pytz.UTC:
                    trigger = trigger.astimezone(pytz.UTC)
                local_dt = trigger.astimezone(pytz.timezone(TimezoneHelper.get_local_timezone_id()))
                abs_date.set_date(local_dt.date())
                abs_hour.set(f"{local_dt.hour:02d}")
                abs_minute.set(f"{local_dt.minute:02d}")
                toggle_trigger()
            elif isinstance(trigger, timedelta):
                total_minutes = abs(trigger.total_seconds()) / 60
                days = int(total_minutes // (24 * 60))
                hours = int((total_minutes % (24 * 60)) // 60)
                minutes = int(total_minutes % 60)
                days_var.set(str(days))
                hours_var.set(str(hours))
                minutes_var.set(str(minutes))

            # 填充额外属性
            if alarm.get('attach'):
                audio_attach_entry.insert(0, decode_ical_value(alarm.get('attach')))
            if alarm.get('attendee'):
                email_attendee_entry.insert(0, decode_ical_value(alarm.get('attendee')))
            if alarm.get('summary'):
                email_summary_entry.insert(0, decode_ical_value(alarm.get('summary')))
            if alarm.get('description'):
                email_description.insert("1.0", decode_ical_value(alarm.get('description')))

        def save():
            action_map_rev = {"显示": "DISPLAY", "声音": "AUDIO", "邮件": "EMAIL"}
            alarm_data = {'action': action_map_rev.get(reminder_type.get(), 'DISPLAY')}

            if trigger_type.get() == "relative":
                days = int(days_var.get() or "0")
                hours = int(hours_var.get() or "0")
                minutes = int(minutes_var.get() or "0")
                total_seconds = -(days * 24 * 60 + hours * 60 + minutes) * 60
                alarm_data['trigger'] = timedelta(seconds=total_seconds)
            else:
                try:
                    tz_id = TimezoneHelper.extract_tz_id(abs_tz_var.get())
                    tz = pytz.timezone(tz_id)
                    dt_local = datetime.combine(
                        abs_date.get_date(),
                        datetime.strptime(f"{abs_hour.get()}:{abs_minute.get()}", "%H:%M").time()
                    )
                    # 将用户选择的时区时间转换为 UTC
                    dt_local = tz.localize(dt_local)
                    dt_utc = dt_local.astimezone(pytz.UTC)
                    alarm_data['trigger'] = dt_utc
                except Exception as e:
                    messagebox.showerror("错误", f"日期时间格式不正确: {e}", parent=dialog)
                    return

            # 保存扩展属性
            attach_val = audio_attach_entry.get().strip()
            if attach_val:
                alarm_data['attach'] = attach_val
            attendee_val = email_attendee_entry.get().strip()
            if attendee_val:
                alarm_data['attendee'] = attendee_val
            summary_val = email_summary_entry.get().strip()
            if summary_val:
                alarm_data['summary'] = summary_val
            desc_val = email_description.get("1.0", "end-1c").strip()
            if desc_val:
                alarm_data['description'] = desc_val

            if index >= 0:
                self.alarms[index] = alarm_data
            else:
                self.alarms.append(alarm_data)

            self.update_reminder_listbox()
            dialog.destroy()

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(side=tk.BOTTOM, pady=10)
        ttk.Button(btn_frame, text="确定", command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=dialog.destroy).pack(side=tk.LEFT, padx=5)

    def toggle_reminder_trigger_type(self):
        """切换提醒触发方式"""
        if self.reminder_trigger_type.get() == "relative":
            self.reminder_time_frame.grid()
            self.absolute_trigger_frame.grid_remove()
        else:
            self.reminder_time_frame.grid_remove()
            self.absolute_trigger_frame.grid()

    def on_reminder_type_change(self, *args):
        """提醒类型改变时的处理"""
        reminder_type = self.reminder_type_var.get()
        self.display_frame.grid_remove()
        self.audio_attach_frame.grid_remove()
        self.email_frame.grid_remove()

        if reminder_type == "显示":
            self.display_frame.grid()
        elif reminder_type == "声音":
            self.audio_attach_frame.grid()
        elif reminder_type == "邮件":
            self.email_frame.grid()

    def apply_preset_reminder(self, is_allday=False):
        """应用预设提醒"""
        lb = self.preset_allday_reminders_listbox if is_allday else self.preset_reminders_listbox
        s = lb.curselection()
        if not s:
            lb.selection_set(0)
            s = (0,)
        preset_text = lb.get(s[0])
        if not preset_text:
            return

        mapping = {
            "日程发生时": timedelta(seconds=0), "5分钟前": timedelta(minutes=-5),
            "15分钟前": timedelta(minutes=-15), "30分钟前": timedelta(minutes=-30),
            "1小时前": timedelta(hours=-1), "2小时前": timedelta(hours=-2),
            "1天前": timedelta(days=-1), "2天前": timedelta(days=-2), "7天前": timedelta(days=-7)
        }
        if preset_text in mapping:
            self.alarms.append({'action': 'DISPLAY', 'trigger': mapping[preset_text]})
            self.update_reminder_listbox()

    def load_preset_reminders(self):
        """加载预设提醒列表"""
        presets = ["5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前"]
        allday_presets = ["日程发生时", "1天前", "2天前", "7天前"]

        for p in presets:
            self.preset_reminders_listbox.insert(tk.END, p)
        for p in allday_presets:
            self.preset_allday_reminders_listbox.insert(tk.END, p)

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
            # 保存扩展属性
            if a.get('attach'):
                al.add('attach').value = a['attach']
            if a.get('attendee'):
                al.add('attendee').value = a['attendee']
            if a.get('summary'):
                al.add('summary').value = a['summary']
            if a.get('description'):
                al.add('description').value = a['description']

        if self.categories_var.get(): ev.add('categories').value = self.categories_var.get()
        ev.add('priority').value = str(self.priority_var.get())
        ev.add('transp').value = self.TRANSPARENCY_MAPPING.get(self.transparency_var.get(), "OPAQUE")
        if self.organizer_var.get(): ev.add('organizer').value = str(self.organizer_var.get())

        # 序列号
        try:
            seq = int(self.sequence_var.get() or "0")
            # 如果是编辑现有事件，则增加序列号 (iCalendar 标准做法)
            if self.initial.get('ical'):
                seq += 1
            ev.add('sequence').value = str(seq)
        except: pass

        # URL
        url_val = self.url_var.get().strip()
        if url_val: ev.add('url').value = url_val

        # 参与者
        if hasattr(self, 'attendee_text'):
            attendee_text = self.attendee_text.get("1.0", "end-1c").strip()
            if attendee_text:
                for line in attendee_text.split('\n'):
                    line = line.strip()
                    if line:
                        ev.add('attendee').value = str(line)

        # 处理其他扩展字段 (从 text 框读取)
        if hasattr(self, 'other_text'):
            others = self.other_text.get("1.0", "end-1c").strip().splitlines()
            for line in others:
                if ":" in line:
                    label, val = line.split(":", 1)
                    name = label.strip().lower()
                    # 排除已手动处理的字段
                    if name.upper() not in ['UID', 'SUMMARY', 'LOCATION', 'DESCRIPTION', 'STATUS', 'DTSTART', 'DTEND', 'RRULE', 
                                          'VALARM', 'CATEGORIES', 'PRIORITY', 'TRANSP', 'ORGANIZER', 'SEQUENCE', 'URL', 'ATTENDEE']:
                        try:
                            ev.add(name).value = val.strip()
                        except: pass

        return cal.serialize()

    def show_raw_data(self):
        data = self.generate_ical()
        win = tk.Toplevel(self.root); win.title("原始数据")
        txt = tk.Text(win); txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, data); txt.config(state=tk.DISABLED)

    def ok(self):
        # 验证必填字段
        summary = self.summary_var.get().strip()
        if not summary:
            messagebox.showwarning("提示", "请填写事件标题", parent=self.root)
            return
        
        # 仅在非全天事件时验证时间
        if not self.allday_var.get():
            start_h = self.start_hour.get().strip()
            start_m = self.start_minute.get().strip()
            end_h = self.end_hour.get().strip()
            end_m = self.end_minute.get().strip()
            
            if not start_h or not start_m or not end_h or not end_m:
                messagebox.showwarning("提示", "请填写完整的时间", parent=self.root)
                return
            
            try:
                datetime.strptime(f"{start_h}:{start_m}", "%H:%M")
                datetime.strptime(f"{end_h}:{end_m}", "%H:%M")
            except ValueError:
                messagebox.showwarning("提示", "时间格式不正确", parent=self.root)
                return

        self.raw_ical = self.generate_ical()
        self.result = {'summary': summary}
        self.root.destroy()

    def cancel(self): self.result = None; self.root.destroy()
    def get_raw_ical(self): return self.raw_ical
    def set_start_now(self):
        """设置开始时间为当前日期（仅日期，不填小时分钟）"""
        n = datetime.now(); self.start_date.set_date(n)
    def set_end_now(self):
        """设置结束时间为当前日期+1小时"""
        n = datetime.now() + timedelta(hours=1)
        self.end_date.set_date(n)
        self.end_hour.set(f"{n.hour:02d}")
        self.end_minute.set("00")
