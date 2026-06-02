import tkinter as tk
from tkinter import ttk, messagebox
from ui.tabs.base_tab import BaseTreeTab

MOCK_ITEMS = {
    'contacts': [
        {"uid": "urn:uuid:a001", "title": "张三", "raw": "BEGIN:VCARD\nUID:a001\nFN:张三\nEND:VCARD", "is_new": True, "has_dup": False},
        {"uid": "urn:uuid:a002", "title": "李四", "raw": "BEGIN:VCARD\nUID:a002\nFN:李四\nEND:VCARD", "is_new": True, "has_dup": False},
        {"uid": "urn:uuid:a003", "title": "王五", "raw": "BEGIN:VCARD\nUID:a003\nFN:王五\nEND:VCARD", "is_new": False, "has_dup": False},
        {"uid": "urn:uuid:a004", "title": "赵六", "raw": "BEGIN:VCARD\nUID:a004\nFN:赵六\nEND:VCARD", "is_new": False, "has_dup": False},
        {"uid": "urn:uuid:a005", "title": "孙七", "raw": "BEGIN:VCARD\nUID:a005\nFN:孙七\nEND:VCARD", "is_new": True, "has_dup": False},
        {"uid": "urn:uuid:a006", "title": "周八", "raw": "BEGIN:VCARD\nUID:a006\nFN:周八\nEND:VCARD", "is_new": False, "has_dup": False},
        {"uid": "urn:uuid:a007", "title": "吴九", "raw": "BEGIN:VCARD\nUID:a007\nFN:吴九\nEND:VCARD", "is_new": True, "has_dup": False},
        {"uid": "urn:uuid:a008", "title": "郑十", "raw": "BEGIN:VCARD\nUID:a008\nFN:郑十\nEND:VCARD", "is_new": True, "has_dup": False},
        {"uid": "urn:uuid:DUPE", "title": "钱十一(同UID版本A)", "raw": "BEGIN:VCARD\nUID:DUPE\nFN:钱十一 vA\nTEL:123\nEND:VCARD", "is_new": True, "has_dup": True},
        {"uid": "urn:uuid:DUPE", "title": "钱十一(同UID版本B)", "raw": "BEGIN:VCARD\nUID:DUPE\nFN:钱十一 vB\nEMAIL:test@test.com\nEND:VCARD", "is_new": True, "has_dup": True},
        {"uid": "urn:uuid:TRIPLE", "title": "张三(同UID版本A)", "raw": "BEGIN:VCARD\nUID:TRIPLE\nFN:张三\nTEL:13800000001\nEMAIL:a@test.com\nEND:VCARD", "is_new": True, "has_dup": True},
        {"uid": "urn:uuid:TRIPLE", "title": "张三(同UID版本B)", "raw": "BEGIN:VCARD\nUID:TRIPLE\nFN:张三\nTEL:13900000002\nADR:Beijing\nEND:VCARD", "is_new": True, "has_dup": True},
        {"uid": "urn:uuid:TRIPLE", "title": "张三(同UID版本C)", "raw": "BEGIN:VCARD\nUID:TRIPLE\nFN:张三\nTEL:13700000003\nEMAIL:b@test.com\nADR:Shanghai\nEND:VCARD", "is_new": True, "has_dup": True},
    ],
    'events': [
        {"uid": "mtg-001", "title": "项目周会", "raw": "BEGIN:VEVENT\nUID:mtg-001\nSUMMARY:项目周会\nEND:VEVENT", "is_new": True, "has_dup": False},
        {"uid": "mtg-002", "title": "张三生日", "raw": "BEGIN:VEVENT\nUID:mtg-002\nSUMMARY:张三生日\nEND:VEVENT", "is_new": True, "has_dup": False},
        {"uid": "mtg-003", "title": "季度评审", "raw": "BEGIN:VEVENT\nUID:mtg-003\nSUMMARY:季度评审\nEND:VEVENT", "is_new": False, "has_dup": False},
        {"uid": "mtg-004", "title": "年会", "raw": "BEGIN:VEVENT\nUID:mtg-004\nSUMMARY:年会\nEND:VEVENT", "is_new": False, "has_dup": False},
        {"uid": "mtg-005", "title": "每日站会", "raw": "BEGIN:VEVENT\nUID:mtg-005\nSUMMARY:每日站会\nEND:VEVENT", "is_new": True, "has_dup": False},
        {"uid": "mtg-006", "title": "技术研讨会", "raw": "BEGIN:VEVENT\nUID:mtg-006\nSUMMARY:技术研讨会\nEND:VEVENT", "is_new": True, "has_dup": False},
        {"uid": "mtg-007", "title": "项目截止日期", "raw": "BEGIN:VEVENT\nUID:mtg-007\nSUMMARY:项目截止日期\nEND:VEVENT", "is_new": False, "has_dup": False},
        {"uid": "mtg-008", "title": "新员工培训", "raw": "BEGIN:VEVENT\nUID:mtg-008\nSUMMARY:新员工培训\nEND:VEVENT", "is_new": True, "has_dup": False},
        {"uid": "mtg-009", "title": "培训(同UID版本A)", "raw": "BEGIN:VEVENT\nUID:mtg-009\nSUMMARY:安全培训\nLOCATION:A栋\nEND:VEVENT", "is_new": True, "has_dup": True},
        {"uid": "mtg-009", "title": "培训(同UID版本B)", "raw": "BEGIN:VEVENT\nUID:mtg-009\nSUMMARY:安全培训\nLOCATION:B栋\nEND:VEVENT", "is_new": True, "has_dup": True},
        {"uid": "mtg-010", "title": "评审(同UID版本A)", "raw": "BEGIN:VEVENT\nUID:mtg-010\nSUMMARY:代码评审\nDESCRIPTION:前端代码\nDTSTART:20250101\nEND:VEVENT", "is_new": True, "has_dup": True},
        {"uid": "mtg-010", "title": "评审(同UID版本B)", "raw": "BEGIN:VEVENT\nUID:mtg-010\nSUMMARY:代码评审\nDESCRIPTION:后端代码\nDTSTART:20250102\nEND:VEVENT", "is_new": True, "has_dup": True},
        {"uid": "mtg-010", "title": "评审(同UID版本C)", "raw": "BEGIN:VEVENT\nUID:mtg-010\nSUMMARY:代码评审\nDESCRIPTION:全栈代码\nDTSTART:20250103\nLOCATION:会议室\nEND:VEVENT", "is_new": True, "has_dup": True},
    ]
}


class CompareDialog(tk.Toplevel):
    """重复条目对比对话框 - 左列表 + 左右双栏对比 + 颜色标记差异"""
    def __init__(self, parent, items):
        super().__init__(parent)
        self.title("对比重复条目")
        # self.geometry("1100x650")
        self.transient(parent)
        self.grab_set()
        self.resizable(True, True)
        self.items = items
        self.analysis = self._analyze()
        self._sel_left = 0
        self._sel_right = min(1, len(items) - 1)
        self._build_ui()
        self._update_displays()

    def _analyze(self):
        item_kvs = []
        for it in self.items:
            kvs = {}
            for line in it['raw'].strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                if ':' in line:
                    k, v = line.split(':', 1)
                    kvs[k.strip()] = v.strip()
                else:
                    kvs[f"_ln_{len(kvs)}"] = line
            item_kvs.append(kvs)

        all_keys = set()
        for kvs in item_kvs:
            all_keys.update(kvs.keys())

        META = {'BEGIN', 'END', 'VERSION', 'PRODID', 'UID'}
        key_status = {}
        for key in all_keys:
            vals = [kvs.get(key) for kvs in item_kvs]
            present = [v for v in vals if v is not None]
            if key in META:
                key_status[key] = 'struct'
            elif len(present) == len(self.items) and len(set(present)) == 1:
                key_status[key] = 'common'
            elif len(present) == len(self.items):
                key_status[key] = 'diff'
            else:
                key_status[key] = 'unique'

        annotations = []
        for idx in range(len(self.items)):
            anno = []
            for line in self.items[idx]['raw'].strip().split('\n'):
                line = line.strip()
                if not line:
                    continue
                if ':' in line:
                    k = line.split(':', 1)[0].strip()
                    status = key_status.get(k, 'common')
                else:
                    status = 'common'
                anno.append((line, status))
            annotations.append(anno)
        return annotations

    def _make_text_panel(self, parent, label):
        """创建带双滚动条的文本面板 (grid 布局 + minsize 防挤压)"""
        f = ttk.LabelFrame(parent, text=label)
        inner = ttk.Frame(f)
        inner.pack(fill=tk.BOTH, expand=True)
        inner.grid_columnconfigure(0, weight=1, minsize=30)
        inner.grid_columnconfigure(1, weight=0, minsize=14)
        inner.grid_rowconfigure(0, weight=1, minsize=30)
        inner.grid_rowconfigure(1, weight=0)
        txt = tk.Text(inner, wrap=tk.NONE, font=('Consolas', 10))
        sb_y = ttk.Scrollbar(inner, orient=tk.VERTICAL, command=txt.yview)
        sb_x = ttk.Scrollbar(inner, orient=tk.HORIZONTAL, command=txt.xview)
        txt.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        txt.grid(row=0, column=0, sticky='nsew')
        sb_y.grid(row=0, column=1, sticky='ns')
        sb_x.grid(row=1, column=0, columnspan=2, sticky='ew')
        for tag, cfg in [('common', {'foreground': '#666666'}),
                         ('diff', {'background': '#FFEE88'}),
                         ('unique', {'background': '#BBE8FF'}),
                         ('struct', {'foreground': '#999999', 'font': ('Consolas', 8)})]:
            txt.tag_config(tag, **cfg)
        txt.config(state=tk.DISABLED)
        return f, txt

    def _build_ui(self):
        uid = self.items[0]['uid']
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=10, pady=(10, 0))
        ttk.Label(header, text=f"⚠ 发现 {len(self.items)} 个条目使用了相同的 UID:",
                 font=('', 10, 'bold')).pack(anchor='w')
        ttk.Label(header, text=f"  {uid}", foreground='blue').pack(anchor='w')
        ttk.Label(header, text="左右对比各版本差异，切换下拉菜单或点击左侧列表选择版本。",
                 foreground='gray').pack(anchor='w', pady=(2, 0))

        main_pane = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # === 左侧: 条目列表 ===
        left_panel = ttk.LabelFrame(main_pane, text="重复条目列表 (点击切换左侧)")
        left_inner = ttk.Frame(left_panel)
        left_inner.pack(fill=tk.BOTH, expand=True)
        left_inner.grid_columnconfigure(0, weight=1, minsize=30)
        left_inner.grid_columnconfigure(1, weight=0, minsize=14)
        left_inner.grid_rowconfigure(0, weight=1, minsize=30)
        left_inner.grid_rowconfigure(1, weight=0)
        self.listbox = tk.Listbox(left_inner, width=22, exportselection=False)
        sb_lv = ttk.Scrollbar(left_inner, orient=tk.VERTICAL, command=self.listbox.yview)
        sb_lh = ttk.Scrollbar(left_inner, orient=tk.HORIZONTAL, command=self.listbox.xview)
        self.listbox.configure(yscrollcommand=sb_lv.set, xscrollcommand=sb_lh.set)
        self.listbox.grid(row=0, column=0, sticky='nsew')
        sb_lv.grid(row=0, column=1, sticky='ns')
        sb_lh.grid(row=1, column=0, columnspan=2, sticky='ew')
        for idx, it in enumerate(self.items, 1):
            self.listbox.insert(tk.END, f"#{idx} — {it['title']}")
        self.listbox.bind('<<ListboxSelect>>', self._on_list_select)
        main_pane.add(left_panel, weight=1)

        # === 右侧: 双栏对比区 ===
        right_area = ttk.Frame(main_pane)
        main_pane.add(right_area, weight=5)

        # 选择栏
        sel_bar = ttk.Frame(right_area)
        sel_bar.pack(fill=tk.X, pady=(0, 5))

        labels = [f"#{i+1} {it['title'][:22]}" for i, it in enumerate(self.items)]

        self.left_combo = ttk.Combobox(sel_bar, values=labels, state='readonly', width=26)
        self.left_combo.current(0)
        self.left_combo.pack(side=tk.LEFT)
        self.left_combo.bind('<<ComboboxSelected>>', lambda e: self._on_combo('left'))

        ttk.Label(sel_bar, text="  vs  ", font=('', 9, 'bold')).pack(side=tk.LEFT)

        self.right_combo = ttk.Combobox(sel_bar, values=labels, state='readonly', width=26)
        self.right_combo.current(self._sel_right)
        self.right_combo.pack(side=tk.LEFT)
        self.right_combo.bind('<<ComboboxSelected>>', lambda e: self._on_combo('right'))

        ttk.Button(sel_bar, text="⇄ 交换", command=self._swap).pack(side=tk.LEFT, padx=8)

        # 双栏文本
        compare_pane = ttk.PanedWindow(right_area, orient=tk.HORIZONTAL)
        compare_pane.pack(fill=tk.BOTH, expand=True)

        left_label = f"左侧 — {self.items[0]['title']}"
        self.left_panel, self.left_text = self._make_text_panel(compare_pane, left_label)
        compare_pane.add(self.left_panel, weight=1)

        right_label = f"右侧 — {self.items[self._sel_right]['title']}"
        self.right_panel, self.right_text = self._make_text_panel(compare_pane, right_label)
        compare_pane.add(self.right_panel, weight=1)

        # 图例 + 关闭
        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(bottom, text="图例:  ", font=('', 9, 'bold')).pack(side=tk.LEFT)
        for bg, label in [('#BBE8FF', '仅此条目有'), ('#FFEE88', '内容有差异'),
                          ('#666666', '完全相同'), ('#999999', '结构行')]:
            lbl = tk.Label(bottom, text="  ", bg=bg, width=2, borderwidth=1, relief=tk.SOLID)
            lbl.pack(side=tk.LEFT, padx=(0, 3))
            ttk.Label(bottom, text=label).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(bottom, text="关闭", command=self.destroy).pack(side=tk.RIGHT)

    # === 事件处理 ===
    def _on_list_select(self, event):
        sel = self.listbox.curselection()
        if sel:
            idx = sel[0]
            self._sel_left = idx
            self.left_combo.current(idx)
            self._update_display('left')

    def _on_combo(self, side):
        if side == 'left':
            self._sel_left = self.left_combo.current()
        else:
            self._sel_right = self.right_combo.current()
        self._update_display(side)

    def _swap(self):
        self._sel_left, self._sel_right = self._sel_right, self._sel_left
        self.left_combo.current(self._sel_left)
        self.right_combo.current(self._sel_right)
        self._update_displays()

    def _update_displays(self):
        self._update_display('left')
        self._update_display('right')

    def _update_display(self, side):
        if side == 'left':
            txt, idx, panel = self.left_text, self._sel_left, self.left_panel
        else:
            txt, idx, panel = self.right_text, self._sel_right, self.right_panel
        panel.configure(text=f"{'左侧' if side == 'left' else '右侧'} — {self.items[idx]['title']}")
        txt.config(state=tk.NORMAL)
        txt.delete('1.0', tk.END)
        for line, status in self.analysis[idx]:
            txt.insert(tk.END, line + '\n', status)
        txt.config(state=tk.DISABLED)


class ImportPreviewFrame(BaseTreeTab):
    COLUMNS = ("selected", "uid", "title", "status")
    HEADINGS = {"selected": "✓", "uid": "ID", "title": "标题/姓名", "status": "状态"}

    def __init__(self, parent, items, on_change=None):
        super().__init__(parent)
        self.items = items
        self.on_change = on_change
        self._build_tree()

    def get_column_width(self, col):
        widths = {"selected": 30, "uid": 200, "title": 260, "status": 160}
        return widths.get(col, 100)

    def _build_tree(self):
        f = ttk.LabelFrame(self, text="操作提示: 点击✓勾选/取消 | 表头✓全选 | 双击行查看详情 | 右键切换覆盖/重置UID")
        f.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.setup_treeview(f, on_edit_callback=lambda: None)
        self.tree.bind('<Double-1>', self._on_double_click)
        self.tree.bind('<Button-3>', self._on_right_click)

    def _populate(self):
        for idx, it in enumerate(self.items):
            self._set_default_action(it)
            default = self._default_checked(it)
            sel = "✓" if default else " "
            iid = self.tree.insert("", tk.END, values=(sel, it['uid'], it['title'], self._status_text(it)))
            if sel == "✓":
                self.tree.selection_add(iid)

    def _set_default_action(self, it):
        """根据冲突类型设置默认操作"""
        if it.get('has_dup'):
            it['_action'] = 'new_uid' if it.get('_dup_idx', 0) > 0 else 'overwrite'
        elif not it.get('is_new', True):
            it['_action'] = 'overwrite'
        else:
            it['_action'] = 'new'

    def _default_checked(self, it):
        if it.get('_dup_idx', 0) > 0 or it.get('_action') == 'new_uid':
            return False
        return it['is_new']

    def _status_text(self, it):
        action = it.get('_action', 'new')
        if action == 'new':
            return "新条目"
        label = "重复" if it.get('has_dup') else "已存在"
        if action == 'overwrite':
            return f"{label}(覆盖)"
        return f"{label}(重置)"

    def selected_items(self):
        result = []
        for iid in self.tree.get_children():
            if iid in self.tree.selection():
                idx = list(self.tree.get_children()).index(iid)
                if idx < len(self.items):
                    result.append(self.items[idx])
        return result

    def select_recommended(self):
        self.tree.selection_set([])
        for iid in self.tree.get_children():
            idx = list(self.tree.get_children()).index(iid)
            if idx < len(self.items) and self._default_checked(self.items[idx]):
                self.tree.selection_add(iid)
        self._sync_all_checkboxes()

    def _sync_all_checkboxes(self):
        self._update_checkboxes(list(self.tree.selection()))

    def _on_double_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        idx = list(self.tree.get_children()).index(iid)
        if idx >= len(self.items):
            return
        it = self.items[idx]
        # 重复条目（导入内同UID）
        if it.get('has_dup'):
            dups = [x for x in self.items if x['uid'] == it['uid']]
            if len(dups) > 1:
                CompareDialog(self.winfo_toplevel(), dups)
                return
        # 与数据库已有条目对比
        uid = it['uid']
        if uid and uid != '?':
            from services.event_service import EventService
            existing_raw = EventService().get_by_uid(uid)
            if existing_raw is not None:
                cmp_items = [
                    {"uid": uid, "title": f"{it['title']} (导入)", "raw": it['raw']},
                    {"uid": uid, "title": f"{it['title']} (数据库)", "raw": existing_raw},
                ]
                CompareDialog(self.winfo_toplevel(), cmp_items)
                return
            from services.contact_service import ContactService
            existing_raw = ContactService().get_by_uid(uid)
            if existing_raw is not None:
                cmp_items = [
                    {"uid": uid, "title": f"{it['title']} (导入)", "raw": it['raw']},
                    {"uid": uid, "title": f"{it['title']} (数据库)", "raw": existing_raw},
                ]
                CompareDialog(self.winfo_toplevel(), cmp_items)
                return
        from ui.dialogs.text_import_dialog import show_raw_dialog
        show_raw_dialog(self.winfo_toplevel(), it['title'], it['raw'])

    def _on_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        idx = list(self.tree.get_children()).index(iid)
        if idx >= len(self.items):
            return
        it = self.items[idx]
        if it.get('_action') == 'new':
            return
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="覆盖更新 (保留原UID)", command=lambda: self._set_action(it, iid, 'overwrite'))
        menu.add_command(label="重置UID (作为新条目)", command=lambda: self._set_action(it, iid, 'new_uid'))
        menu.tk_popup(event.x_root, event.y_root)
        menu.grab_release()

    def _set_action(self, it, iid, action):
        it['_action'] = action
        vals = list(self.tree.item(iid, 'values'))
        vals[3] = self._status_text(it)
        self.tree.item(iid, values=vals)
        if self.on_change:
            self.on_change()

    def _on_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)

        if region == "heading" and column == "#1":
            self.toggle_all_selection()
            return "break"
        if region == "heading":
            return "break"

        if column == "#1" and item:
            if item in self.tree.selection():
                self.tree.selection_remove(item)
                self._set_item_checkbox(item, " ")
            else:
                self.tree.selection_add(item)
                self._set_item_checkbox(item, "✓")
            if self.on_change:
                self.on_change()
            return "break"

        return "break"

    def toggle_all_selection(self):
        all_items = self.tree.get_children()
        if not all_items:
            return
        all_sel = all(i in self.tree.selection() for i in all_items)
        new_sel = [] if all_sel else all_items
        self.tree.selection_set(new_sel)
        self._sync_all_checkboxes()
        if self.on_change:
            self.on_change()

    def select_all(self, event=None):
        self.tree.selection_set(self.tree.get_children())
        self._sync_all_checkboxes()
        if self.on_change:
            self.on_change()
        return "break"


class ImportPreviewDialog(tk.Toplevel):
    def __init__(self, parent, import_type, on_import_callback=None, items=None):
        super().__init__(parent)
        self.title(f"导入预览 - {import_type}")
        # self.geometry("900x650")
        self.transient(parent)
        self.grab_set()
        self.on_import_callback = on_import_callback

        if items is None:
            items = MOCK_ITEMS.get(import_type, MOCK_ITEMS['contacts'])
        self.items = self._prepare_items(items)

        self.frame = ImportPreviewFrame(self, items, on_change=self._update_count)
        self.frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))
        self.frame._populate()

        self._build_bottom()
        self._update_count()

    def _prepare_items(self, raw_items):
        items = []
        uid_count = {}
        for it in raw_items:
            uid = it['uid']
            uid_count[uid] = uid_count.get(uid, 0) + 1
            items.append({**it, '_dup_idx': 0})
        for it in items:
            if uid_count[it['uid']] > 1:
                it['has_dup'] = True
        dup_cnt = {uid: 0 for uid in uid_count if uid_count[uid] > 1}
        for it in items:
            if it['has_dup']:
                it['_dup_idx'] = dup_cnt[it['uid']]
                dup_cnt[it['uid']] += 1
        return items

    def _build_bottom(self):
        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=10, pady=10)

        self.sel_count = tk.StringVar(value="共 0 条，已选 0 条")
        ttk.Label(bottom, textvariable=self.sel_count).pack(side=tk.LEFT)

        self.overwrite_var = tk.BooleanVar(value=False)
        self.overwrite_var.trace("w", lambda *a: self._on_overwrite_toggle())
        ttk.Checkbutton(bottom, text="覆盖已存在条目", variable=self.overwrite_var).pack(side=tk.LEFT, padx=20)

        btn_f = ttk.Frame(bottom)
        btn_f.pack(side=tk.RIGHT)
        ttk.Button(btn_f, text="选择推荐", command=self._select_recommended).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="全选", command=self._select_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="全不选", command=self._deselect_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_f, text="导入选中", command=self._do_import).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_f, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=2)

    def _update_count(self):
        sel_count = len(self.frame.tree.selection())
        total = len(self.tree.get_children()) if hasattr(self, 'tree') and self.tree else len(self.items)
        self.sel_count.set(f"共 {len(self.items)} 条，已选 {sel_count} 条")

    @property
    def tree(self):
        return self.frame.tree if hasattr(self.frame, 'tree') else None

    def _on_overwrite_toggle(self):
        if self.overwrite_var.get():
            for iid in self.tree.get_children():
                idx = list(self.tree.get_children()).index(iid)
                if idx < len(self.items) and not self.items[idx]['is_new']:
                    self.tree.selection_add(iid)
                    self.frame._set_item_checkbox(iid, "✓")
        else:
            for iid in self.tree.get_children():
                idx = list(self.tree.get_children()).index(iid)
                if idx < len(self.items) and not self.items[idx]['is_new']:
                    self.tree.selection_remove(iid)
                    self.frame._set_item_checkbox(iid, " ")
        self._update_count()

    def _select_recommended(self):
        self.frame.select_recommended()
        self._update_count()

    def _select_all(self):
        self.frame.select_all()
        self._update_count()

    def _deselect_all(self):
        self.tree.selection_set([])
        self.frame._sync_all_checkboxes()
        self._update_count()

    def _do_import(self):
        selected = self.frame.selected_items()
        if not selected:
            messagebox.showinfo("提示", "请选择要导入的条目", parent=self)
            return
        if self.on_import_callback:
            self.on_import_callback(selected)
        self.destroy()
