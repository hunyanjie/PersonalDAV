import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ui.dialogs.event_dialog import EventDialog
from ui.dialogs.webdav_import_dialog import WebDAVImportDialog
from ui.dialogs.import_preview_dialog import ImportPreviewDialog
from ui.widgets.right_click_menu import RightClickMenu
from ui.tabs.base_tab import BaseTreeTab
from tkinterdnd2 import DND_FILES

from utils.event_bus import event_bus, EVENT_EVENTS_CHANGED
import os
from datetime import datetime, date, timedelta
from utils.encoding_helper import decode_ical_value


def _extract_categories(ical_data: str) -> str:
    for line in ical_data.splitlines():
        if line.upper().startswith("CATEGORIES"):
            return line.split(":", 1)[-1].strip() if ":" in line else ""
    return ""


class CalendarTab(BaseTreeTab):
    """日历管理标签页"""
    COLUMNS = ("uid", "summary", "start", "end", "categories", "created_at", "updated_at")
    HEADINGS = {
        "uid": "ID",
        "summary": "事件",
        "start": "开始时间",
        "end": "结束时间",
        "categories": "分类",
        "created_at": "添加时间",
        "updated_at": "修改时间"
    }
    DEFAULT_SORT_COL = ""
    DEFAULT_SORT_REV = False

    def __init__(self, parent, event_service, settings_service, app_root):
        self.db = event_service
        self.settings = settings_service
        self.app_root = app_root

        super().__init__(parent)
        self._import_type = 'events'

        self.create_widgets()
        self.refresh_events()

        event_bus.subscribe(EVENT_EVENTS_CHANGED, self.refresh_events)

    def get_column_width(self, col):
        widths = {"uid": 150, "summary": 300, "start": 200, "end": 200, "categories": 120, "created_at": 160, "updated_at": 160}
        return widths.get(col, 100)

    def create_widgets(self):
        self.setup_search_ui(self)

        # 分类筛选
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        ttk.Label(filter_frame, text="分类筛选:").pack(side=tk.LEFT, padx=(0, 5))
        self._cat_filter_var = tk.StringVar(value="全部")
        self._cat_filter_combo = ttk.Combobox(filter_frame, textvariable=self._cat_filter_var,
                                               values=["全部"], state="readonly", width=18)
        self._cat_filter_combo.pack(side=tk.LEFT)
        self._cat_filter_var.trace("w", lambda *a: self._apply_cat_filter())

        ttk.Label(filter_frame, text="  视图:").pack(side=tk.LEFT, padx=(10, 5))
        self._view_var = tk.StringVar(value="议程")
        self._view_combo = ttk.Combobox(filter_frame, textvariable=self._view_var,
                                          values=["议程", "月视图"], state="readonly", width=10)
        self._view_combo.pack(side=tk.LEFT)
        self._view_var.trace("w", self._on_view_changed)

        self._agenda_frame = ttk.LabelFrame(self, text="日历事件列表")
        self._agenda_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        hint_label = ttk.Label(self._agenda_frame, text="操作提示: 1) 点击复选框选择/取消 2) 表头复选框全选 3) 鼠标拖拽多选 4) 双击行编辑", foreground="blue")
        hint_label.pack(fill=tk.X, padx=5, pady=5)

        self.setup_treeview(self._agenda_frame, self.edit_event)
        RightClickMenu(self.tree)

        self._month_frame = ttk.LabelFrame(self, text="月视图")
        cal_top = ttk.Frame(self._month_frame); cal_top.pack(fill=tk.X, padx=5, pady=5)
        nav_f = ttk.Frame(cal_top); nav_f.pack(side=tk.LEFT)
        ttk.Button(nav_f, text="◀", width=3, command=self._month_prev).pack(side=tk.LEFT, padx=1)
        self._year_var = tk.StringVar()
        self._month_var = tk.StringVar()
        current_year = date.today().year
        years = [str(y) for y in range(current_year - 50, current_year + 51)]
        self._year_combo = ttk.Combobox(nav_f, textvariable=self._year_var, values=years, width=6, state="readonly")
        self._year_combo.pack(side=tk.LEFT, padx=2)
        self._month_names = ["1月", "2月", "3月", "4月", "5月", "6月", "7月", "8月", "9月", "10月", "11月", "12月"]
        self._month_combo = ttk.Combobox(nav_f, textvariable=self._month_var, values=self._month_names, width=5, state="readonly")
        self._month_combo.pack(side=tk.LEFT, padx=2)
        self._year_combo.bind("<<ComboboxSelected>>", self._month_combo_changed)
        self._month_combo.bind("<<ComboboxSelected>>", self._month_combo_changed)
        ttk.Button(nav_f, text="▶", width=3, command=self._month_next).pack(side=tk.LEFT, padx=1)
        ttk.Button(cal_top, text="今天", command=self._month_today).pack(side=tk.RIGHT)

        from tkcalendar import Calendar
        self._month_cal = Calendar(self._month_frame, selectmode='day', locale='zh_CN',
                                    date_pattern='yyyy-mm-dd', showweeknumbers=False)
        self._month_cal.pack(fill=tk.X, padx=5, pady=5)
        self._month_cal.bind("<<CalendarSelected>>", self._month_on_select)
        for meth in ('_prev_month', '_next_month', '_prev_year', '_next_year'):
            orig = getattr(self._month_cal, meth)
            def _wrap(m=orig):
                return lambda: [m(), self._sync_month_combos(), self._refresh_month_view()]
            setattr(self._month_cal, meth, _wrap())

        ev_f = ttk.LabelFrame(self._month_frame, text="选定日事件")
        ev_f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ev_scroll = ttk.Scrollbar(ev_f, orient=tk.VERTICAL)
        self._month_events_listbox = tk.Listbox(ev_f, exportselection=False, yscrollcommand=ev_scroll.set)
        ev_scroll.config(command=self._month_events_listbox.yview)
        ev_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._month_events_listbox.pack(fill=tk.BOTH, expand=True)
        self._month_events_listbox.bind("<Double-1>", self._month_edit_event)
        self._month_event_uids = []

        self._btn_frame = ttk.Frame(self)
        self._btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(self._btn_frame, text="添加事件", command=self.add_event).pack(side=tk.LEFT, padx=2)
        ttk.Button(self._btn_frame, text="编辑事件", command=self.edit_event).pack(side=tk.LEFT, padx=2)
        ttk.Button(self._btn_frame, text="删除事件", command=self.delete_event).pack(side=tk.LEFT, padx=2)
        ttk.Button(self._btn_frame, text="查看原始数据", command=self.show_raw).pack(side=tk.LEFT, padx=2)

        import_btn = ttk.Menubutton(self._btn_frame, text="导入数据")
        import_menu = tk.Menu(import_btn, tearoff=0)
        import_menu.add_command(label="从文件导入...", command=self._import_file)
        import_menu.add_command(label="从 URL 导入...", command=self._import_url)
        import_menu.add_command(label="从剪切板导入", command=self._import_clipboard)
        import_menu.add_command(label="粘贴文本导入...", command=self.show_text_import)
        import_menu.add_command(label="WebDAV 导入...", command=self.import_webdav)
        import_menu.add_separator()
        import_menu.add_command(label="预览导入...", command=self.show_import_preview)
        import_btn.config(menu=import_menu)
        import_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(self._btn_frame, text="导出选中", command=self.export_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(self._btn_frame, text="同步", command=self._sync_events).pack(side=tk.LEFT, padx=2)
        ttk.Button(self._btn_frame, text="刷新列表", command=self.refresh_events).pack(side=tk.RIGHT, padx=10)

    def _sync_events(self):
        from services.sync_service import SyncService
        svc = SyncService()
        if not svc.is_configured():
            messagebox.showinfo("提示", "请先在设置中配置 Nextcloud 同步", parent=self)
            return
        from ui.widgets.toast import Toast
        Toast.show(self, "事件同步开始...")
        try:
            pulled, pushed = svc.sync_events()
            self.refresh_events()
            Toast.show(self, f"同步完成: 拉取 {pulled}, 推送 {pushed}")
        except Exception as e:
            messagebox.showerror("同步失败", str(e), parent=self)

    def _month_boundary(self, dt: date = None) -> tuple[str, str]:
        if dt is None:
            dt = self._month_cal.selection_get() or date.today()
        start = date(dt.year, dt.month, 1)
        end = (start + timedelta(days=32)).replace(day=1)
        return start.isoformat(), end.isoformat()

    def _on_view_changed(self, *args):
        view = self._view_var.get()
        if view == "月视图":
            self._agenda_frame.pack_forget()
            self._month_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            self._refresh_month_view()
        else:
            self._month_frame.pack_forget()
            self._agenda_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _sync_month_combos(self):
        self._year_var.set(str(self._month_cal._date.year))
        self._month_var.set(self._month_names[self._month_cal._date.month - 1])

    def _refresh_month_view(self):
        cal_date = self._month_cal.selection_get()
        self._sync_month_combos()
        # Load only this month's events (plus 1-day buffer)
        s, e = self._month_boundary(cal_date)
        raw = self.db.get_list_data_range(s, e)
        self._month_data = raw
        self._month_cal.calevent_remove('all')
        for ev in raw:
            uid, summary, start, end, *_ = ev
            try:
                dt = datetime.fromisoformat(start)
                self._month_cal.calevent_create(dt.date(), (summary or "(无标题)")[:20], 'event')
            except Exception:
                pass
        self._month_cal.tag_config('event', background='#3498db', foreground='white')
        self._month_on_select()

    def _month_prev(self):
        self._month_cal._prev_month()
        self._refresh_month_view()

    def _month_next(self):
        self._month_cal._next_month()
        self._refresh_month_view()

    def _month_today(self):
        self._month_cal.selection_set(date.today())
        self._refresh_month_view()

    def _month_combo_changed(self, event=None):
        try:
            y = int(self._year_var.get())
            m = self._month_names.index(self._month_var.get()) + 1
            self._month_cal.selection_set(date(y, m, 1))
            self._refresh_month_view()
        except Exception:
            pass

    def _month_on_select(self, event=None):
        self._sync_month_combos()
        self._month_events_listbox.delete(0, tk.END)
        self._month_event_uids.clear()
        try:
            cal_date = self._month_cal.selection_get()
        except Exception:
            return
        if not cal_date:
            return
        data = getattr(self, '_month_data', getattr(self, '_all_data', []))
        day_events = []
        for ev in data:
            uid, summary, start, end, *_ = ev
            try:
                dt = datetime.fromisoformat(start)
                if dt.date() == cal_date:
                    day_events.append((dt, uid, summary))
            except Exception:
                pass
        day_events.sort(key=lambda x: x[0])
        for dt, uid, summary in day_events:
            disp = decode_ical_value(summary or "(无标题)")
            self._month_events_listbox.insert(tk.END, f"{dt.strftime('%H:%M')} {disp}")
            self._month_event_uids.append(uid)

    def _month_edit_event(self, event=None):
        sel = self._month_events_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx < len(self._month_event_uids):
            uid = self._month_event_uids[idx]
            self._edit_event_by_uid(uid)

    def _edit_event_by_uid(self, uid):
        data = self.db.get_by_uid(uid)
        if data:
            init = {'uid': uid, 'ical': data}
            dialog = EventDialog(self.app_root, initial=init, db=self.settings)
            if dialog.result:
                self.db.add_event(dialog.get_raw_ical())
                self.refresh_events()

    def refresh_events(self):
        self.cancel_pending()
        if self._view_var.get() == "月视图":
            self._refresh_month_view()
            self._all_raw = self._month_data or []
            self._after_refresh()
            return
        raw = self.db.get_list_data()
        self._all_raw = raw
        self._raw_by_uid = {}
        self._update_cat_filter()
        self.apply_filter(getattr(self, 'search_var', None) and self.search_var.get().lower() or "")
        self._after_refresh()

    def _update_cat_filter(self):
        cats = set()
        for event in self._all_raw:
            uid = event[0]
            ical = self.db.get_by_uid(uid)
            if ical:
                self._raw_by_uid[uid] = ical
                raw_cat = _extract_categories(ical)
                if raw_cat:
                    for c in raw_cat.split(","):
                        c = c.strip()
                        if c:
                            cats.add(c)
        all_vals = ["全部"] + sorted(cats)
        self._cat_filter_combo['values'] = all_vals
        if self._cat_filter_var.get() not in all_vals:
            self._cat_filter_var.set("全部")

    def _apply_cat_filter(self):
        query = getattr(self, 'search_var', None) and self.search_var.get().lower() or ""
        self.apply_filter(query)

    def apply_filter(self, query):
        selected_cat = self._cat_filter_var.get()
        self._all_data = []
        for event in self._all_raw:
            uid, summary, start, end, created_at, updated_at = event
            match = not query or any(query in str(v).lower() for v in event)
            if match:
                ical = self._raw_by_uid.get(uid, "")
                raw_cat = _extract_categories(ical)
                if selected_cat == "全部" or selected_cat in raw_cat.split(","):
                    disp_summary = decode_ical_value(summary) if summary else summary
                    self._all_data.append((" ", uid, disp_summary, start, end, raw_cat, created_at, updated_at))
        self._rerender()
        if self._view_var.get() == "月视图":
            self._refresh_month_view()

    def add_event(self):
        dialog = EventDialog(self.app_root, db=self.settings)
        if dialog.result:
            self.db.add_event(dialog.get_raw_ical())
            self.refresh_events()

    def edit_event(self):
        uids = list(self._selected_uids)
        if not uids: return
        uid = uids[0]
        data = self.db.get_by_uid(uid)
        if data:
            init = {'uid': uid, 'ical': data}
            dialog = EventDialog(self.app_root, initial=init, db=self.settings)
            if dialog.result:
                self.db.add_event(dialog.get_raw_ical())
                self.refresh_events()

    def delete_event(self):
        uids = list(self._selected_uids)
        if not uids: return
        from ui.dialogs.confirm_dialog import ConfirmDialog
        if ConfirmDialog.ask(self, "确认", f"确定删除选中的 {len(uids)} 个事件吗？"):
            for uid in uids:
                self.db.delete(uid)
            self.refresh_events()

    def _on_delete(self):
        self.delete_event()

    def show_raw(self):
        uids = list(self._selected_uids)
        if not uids:
            messagebox.showinfo("提示", "请先选中要查看原始数据的事件", parent=self)
            return
        events = self.db.get_selected_raw(uids)
        if len(uids) == 1:
            data = events[0]
        else:
            data = self.db.combine_raw_events(events)
        if data:
            win = tk.Toplevel(self); win.title("原始数据")
            from utils.window_utils import center_window; center_window(win, self)
            sb_v = ttk.Scrollbar(win, orient=tk.VERTICAL)
            txt = tk.Text(win, wrap=tk.CHAR, yscrollcommand=sb_v.set)
            RightClickMenu(txt, "text", actions=["copy", None, "select_all"])
            sb_v.config(command=txt.yview)
            sb_v.pack(side=tk.RIGHT, fill=tk.Y)
            txt.pack(fill=tk.BOTH, expand=True)
            txt.insert(tk.END, data); txt.config(state=tk.DISABLED)

    def import_webdav(self):
        dialog = WebDAVImportDialog(self, "从 WebDAV 导入日历", self.db.add_event)
        self.wait_window(dialog)

    def _import_add_item(self, raw, force=False, publish=True):
        return self.db.add_event(raw, force=force, publish=publish)

    def _import_refresh_list(self):
        self.refresh_events()

    def _parse_data_to_items(self, data):
        items = []
        if "BEGIN:VEVENT" not in data and "BEGIN:VCALENDAR" not in data:
            return items
        try:
            import vobject
            if "BEGIN:VEVENT" in data and "BEGIN:VCALENDAR" not in data:
                cal = vobject.readOne(data)
                uid = cal.uid.value if hasattr(cal, 'uid') else ""
                title = cal.summary.value if hasattr(cal, 'summary') else "(无标题)"
                existing = self.db.get_by_uid(uid) is not None
                items.append({"uid": uid, "title": title, "raw": data, "is_new": not existing, "has_dup": False})
            else:
                cal = vobject.readOne(data)
                for comp in cal.components():
                    if comp.name == 'VEVENT':
                        raw = comp.serialize()
                        uid = comp.uid.value if hasattr(comp, 'uid') else ""
                        title = comp.summary.value if hasattr(comp, 'summary') else "(无标题)"
                        existing = self.db.get_by_uid(uid) is not None
                        items.append({"uid": uid, "title": title, "raw": raw, "is_new": not existing, "has_dup": False})
        except Exception:
            pass
        return items

    def export_selected(self):
        uids = list(self._selected_uids)
        if not uids:
            messagebox.showinfo("提示", "请先选择要导出的事件", parent=self)
            return
        events = self.db.get_selected_full_raw(uids)

        initial = ""
        if len(uids) == 1:
            summary = ""
            for row in self._all_data:
                if row[1] == uids[0]:
                    summary = row[2]
                    break
            if summary:
                summary = str(summary)
                import re
                summary = re.sub(r'[<>:"/\\|?*]', '_', summary)
                initial = summary

        path = filedialog.asksaveasfilename(
            defaultextension=".ics",
            filetypes=[("iCalendar", "*.ics"), ("所有文件", "*.*")],
            initialfile=initial
        )
        if path:
            if not path.endswith('.ics'):
                path += '.ics'
            data = self.db.combine_raw_events(events)
            with open(path, 'w', encoding='utf-8') as f: f.write(data)
            from ui.widgets.toast import Toast
            Toast.show(self, f"成功导出 {len(events)} 个事件")
