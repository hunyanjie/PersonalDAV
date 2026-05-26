import tkinter as tk
from tkinter import ttk, messagebox
import uuid
import vobject
from tkcalendar import DateEntry, Calendar
from ui.widgets.right_click_menu import RightClickMenu
from utils.encoding_helper import smart_quoted_printable_encode, should_encode

class ContactDialog(tk.Toplevel):
    """添加/编辑联系人对话框 - 1:1 深度还原 vCard 逻辑与 UX 优化"""
    
    FIELD_MAP = {
        'ORG': '组织/公司',
        'TITLE': '职位',
        'URL': '网址',
        'ADR': '地址',
        'X-PHONETIC-FIRST-NAME': '名字拼音',
        'X-PHONETIC-LAST-NAME': '姓氏拼音'
    }
    REV_FIELD_MAP = {v: k for k, v in FIELD_MAP.items()}

    def __init__(self, parent, initial=None, vcard=None):
        super().__init__(parent)
        self.title("添加/编辑联系人")
        self.geometry("600x650")
        self.transient(parent)
        self.grab_set()

        self.result = None
        self.initial = initial or {}
        self.vcard = vcard

        self.create_widgets()
        self.set_initial_values()

        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.wait_window(self)

    def create_widgets(self):
        f = ttk.Frame(self); f.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 基础字段
        ttk.Label(f, text="UID:").grid(row=0, column=0, sticky="w")
        self.uid_entry = ttk.Entry(f, width=40); self.uid_entry.grid(row=0, column=1, pady=5, sticky="we")
        RightClickMenu(self.uid_entry)

        ttk.Label(f, text="姓名*:").grid(row=1, column=0, sticky="w")
        self.name_entry = ttk.Entry(f, width=40); self.name_entry.grid(row=1, column=1, pady=5, sticky="we")
        RightClickMenu(self.name_entry)

        ttk.Label(f, text="邮箱:").grid(row=2, column=0, sticky="w")
        self.email_entry = ttk.Entry(f, width=40); self.email_entry.grid(row=2, column=1, pady=5, sticky="we")
        ttk.Label(f, text="(多个用分号分隔)", foreground="gray").grid(row=2, column=2, padx=5)
        RightClickMenu(self.email_entry)

        ttk.Label(f, text="电话:").grid(row=3, column=0, sticky="w")
        self.phone_entry = ttk.Entry(f, width=40); self.phone_entry.grid(row=3, column=1, pady=5, sticky="we")
        ttk.Label(f, text="(多个用分号分隔)", foreground="gray").grid(row=3, column=2, padx=5)
        RightClickMenu(self.phone_entry)

        # 生日字段 UX 优化：支持留空
        ttk.Label(f, text="生日:").grid(row=4, column=0, sticky="w")
        b_f = ttk.Frame(f); b_f.grid(row=4, column=1, sticky="w", pady=5)
        self.birthday_var = tk.StringVar()
        self.birthday_entry = ttk.Entry(b_f, textvariable=self.birthday_var, width=15)
        self.birthday_entry.pack(side=tk.LEFT)
        ttk.Button(b_f, text="📅", width=3, command=self.pick_date).pack(side=tk.LEFT, padx=5)
        ttk.Button(b_f, text="清除", width=5, command=lambda: self.birthday_var.set("")).pack(side=tk.LEFT)

        ttk.Label(f, text="备注:").grid(row=5, column=0, sticky="w")
        self.note_entry = ttk.Entry(f, width=40); self.note_entry.grid(row=5, column=1, pady=5, sticky="we")
        RightClickMenu(self.note_entry)

        # 扩展字段
        ttk.Label(f, text="其他 vCard 字段:").grid(row=6, column=0, sticky="nw")
        self.other_text = tk.Text(f, height=12, width=50); self.other_text.grid(row=6, column=1, pady=5, sticky="nsew")
        RightClickMenu(self.other_text, "text")
        ttk.Label(f, text="(格式: 标签: 内容)", foreground="gray").grid(row=7, column=1, sticky="w")

        btn_f = ttk.Frame(self); btn_f.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_f, text="确定", command=self.ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_f, text="取消", command=self.cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_f, text="原始数据", command=self.show_raw).pack(side=tk.LEFT, padx=5)

    def pick_date(self):
        w = tk.Toplevel(self); w.title("选择日期"); w.grab_set()
        cal = Calendar(w, date_pattern='yyyy-mm-dd')
        cal.pack(padx=10, pady=10)
        ttk.Button(w, text="确定", command=lambda: [self.birthday_var.set(cal.get_date()), w.destroy()]).pack(pady=5)

    def set_initial_values(self):
        self.uid_entry.insert(0, self.initial.get('uid', f"contact-{uuid.uuid4().hex}"))
        self.name_entry.insert(0, self.initial.get('name', ''))
        self.email_entry.insert(0, self.initial.get('email', ''))
        self.phone_entry.insert(0, self.initial.get('phone', ''))
        
        if self.vcard:
            others = []
            standard = ['UID', 'FN', 'N', 'EMAIL', 'TEL', 'VERSION', 'PHOTO', 'BDAY', 'NOTE']
            for child in self.vcard.getChildren():
                name = child.name.upper()
                if name not in standard:
                    label = self.FIELD_MAP.get(name, name)
                    others.append(f"{label}: {child.value}")
                if name == 'NOTE':
                    self.note_entry.delete(0, tk.END)
                    self.note_entry.insert(0, child.value)
                if name == 'BDAY':
                    self.birthday_var.set(child.value)
            self.other_text.insert(tk.END, "\n".join(others))

    def show_raw(self):
        if not self.vcard: return
        w = tk.Toplevel(self); w.title("vCard 源码")
        t = tk.Text(w); t.pack(fill=tk.BOTH, expand=True)
        t.insert(tk.END, self.vcard.serialize()); t.config(state=tk.DISABLED)

    def encode_text(self, text):
        if not text: return ""
        if not should_encode(text): return text
        import quopri
        return f"ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:{quopri.encodestring(text.encode('utf-8')).decode('utf-8')}"

    def ok(self):
        if not self.name_entry.get(): messagebox.showerror("错误", "姓名不能为空"); return
        
        v = vobject.vCard()
        v.add('fn').value = self.name_entry.get()
        v.add('uid').value = self.uid_entry.get()
        
        # 1:1 还原多项处理
        for e in self.email_entry.get().split(';'):
            if e.strip(): v.add('email').value = e.strip()
        for p in self.phone_entry.get().split(';'):
            if p.strip(): v.add('tel').value = p.strip()
            
        if self.note_entry.get(): v.add('note').value = self.note_entry.get()
        if self.birthday_var.get(): v.add('bday').value = self.birthday_var.get()
        
        # 处理扩展字段回写
        others = self.other_text.get("1.0", "end-1c").strip().splitlines()
        for line in others:
            if ":" in line:
                label, val = line.split(":", 1)
                key = self.REV_FIELD_MAP.get(label.strip(), label.strip().upper())
                if key not in ['UID', 'FN', 'N', 'EMAIL', 'TEL', 'BDAY', 'NOTE']:
                    try: v.add(key.lower()).value = val.strip()
                    except: pass

        self.result = {'vcard': v.serialize(), 'name': v.fn.value}
        self.destroy()

    def cancel(self): self.result = None; self.destroy()
