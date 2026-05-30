import tkinter as tk
from tkinter import ttk, messagebox
import uuid
import vobject
from tkcalendar import Calendar
from ui.widgets.right_click_menu import RightClickMenu
from utils.encoding_helper import should_encode
from models.constants import STANDARD_VCARD_FIELDS
import quopri


class ContactDialog(tk.Toplevel):
    """添加/编辑联系人对话框"""

    FIELD_MAP = {
        'ORG': '组织/公司',
        'TITLE': '职位',
        'URL': '网址',
        'ADR': '地址',
        'X-PHONETIC-FIRST-NAME': '名字拼音',
        'X-PHONETIC-LAST-NAME': '姓氏拼音'
    }
    REV_FIELD_MAP = {v: k for k, v in FIELD_MAP.items()}

    def __init__(self, parent, initial=None, vcard=None, raw_vcard=None):
        super().__init__(parent)
        self.title("添加/编辑联系人")
        self.geometry("650x750")
        self.transient(parent)
        self.grab_set()

        self.result = None
        self.initial = initial or {}
        self.vcard = vcard
        self.raw_vcard_data = raw_vcard

        self.create_widgets()
        self.set_initial_values()

        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.wait_window(self)

    def create_widgets(self):
        f = ttk.Frame(self); f.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 基础字段
        ttk.Label(f, text="UID:").grid(row=0, column=0, sticky="w", pady=3)
        self.uid_entry = ttk.Entry(f, width=40, exportselection=False); self.uid_entry.grid(row=0, column=1, columnspan=2, pady=3, sticky="we")
        RightClickMenu(self.uid_entry)

        ttk.Label(f, text="姓名*:").grid(row=1, column=0, sticky="w", pady=3)
        self.name_entry = ttk.Entry(f, width=40, exportselection=False); self.name_entry.grid(row=1, column=1, columnspan=2, pady=3, sticky="we")
        RightClickMenu(self.name_entry)

        # 拼音字段
        ttk.Label(f, text="名字拼音:").grid(row=2, column=0, sticky="w", pady=3)
        self.first_phonetic_entry = ttk.Entry(f, width=20, exportselection=False); self.first_phonetic_entry.grid(row=2, column=1, sticky="w", pady=3)
        RightClickMenu(self.first_phonetic_entry)

        ttk.Label(f, text="姓氏拼音:").grid(row=2, column=2, sticky="w", padx=(10,0), pady=3)
        self.last_phonetic_entry = ttk.Entry(f, width=20, exportselection=False); self.last_phonetic_entry.grid(row=2, column=3, sticky="we", pady=3)
        RightClickMenu(self.last_phonetic_entry)

        ttk.Label(f, text="邮箱:").grid(row=3, column=0, sticky="w", pady=3)
        self.email_entry = ttk.Entry(f, width=40, exportselection=False); self.email_entry.grid(row=3, column=1, columnspan=3, pady=3, sticky="we")
        ttk.Label(f, text="(多个用分号分隔)", foreground="gray").grid(row=4, column=1, sticky="w")
        RightClickMenu(self.email_entry)

        ttk.Label(f, text="电话:").grid(row=5, column=0, sticky="w", pady=3)
        self.phone_entry = ttk.Entry(f, width=40, exportselection=False); self.phone_entry.grid(row=5, column=1, columnspan=3, pady=3, sticky="we")
        ttk.Label(f, text="(多个用分号分隔)", foreground="gray").grid(row=6, column=1, sticky="w")
        RightClickMenu(self.phone_entry)

        # 组织/公司
        ttk.Label(f, text="组织/公司:").grid(row=7, column=0, sticky="w", pady=3)
        self.org_entry = ttk.Entry(f, width=40, exportselection=False); self.org_entry.grid(row=7, column=1, columnspan=3, pady=3, sticky="we")
        RightClickMenu(self.org_entry)

        # 职位
        ttk.Label(f, text="职位:").grid(row=8, column=0, sticky="w", pady=3)
        self.title_entry = ttk.Entry(f, width=40, exportselection=False); self.title_entry.grid(row=8, column=1, columnspan=3, pady=3, sticky="we")
        RightClickMenu(self.title_entry)

        # 网址
        ttk.Label(f, text="网址:").grid(row=9, column=0, sticky="w", pady=3)
        self.url_entry = ttk.Entry(f, width=40, exportselection=False); self.url_entry.grid(row=9, column=1, columnspan=3, pady=3, sticky="we")
        RightClickMenu(self.url_entry)

        # 地址
        ttk.Label(f, text="地址:").grid(row=10, column=0, sticky="nw", pady=3)
        self.adr_text = tk.Text(f, height=3, width=40, exportselection=False); self.adr_text.grid(row=10, column=1, columnspan=3, pady=3, sticky="nsew")
        RightClickMenu(self.adr_text, "text")

        # 生日
        ttk.Label(f, text="生日:").grid(row=11, column=0, sticky="w", pady=3)
        b_f = ttk.Frame(f); b_f.grid(row=11, column=1, columnspan=2, sticky="w", pady=3)
        self.birthday_var = tk.StringVar()
        self.birthday_entry = ttk.Entry(b_f, textvariable=self.birthday_var, width=15, exportselection=False)
        self.birthday_entry.pack(side=tk.LEFT)
        ttk.Button(b_f, text="选择", width=6, command=self.pick_date).pack(side=tk.LEFT, padx=5)
        ttk.Button(b_f, text="清除", width=6, command=lambda: self.birthday_var.set("")).pack(side=tk.LEFT)

        # 备注
        ttk.Label(f, text="备注:").grid(row=12, column=0, sticky="nw", pady=3)
        self.note_text = tk.Text(f, height=4, width=40, exportselection=False); self.note_text.grid(row=12, column=1, columnspan=3, pady=3, sticky="nsew")
        RightClickMenu(self.note_text, "text")

        # 其他 vCard 字段
        sep = ttk.Separator(f, orient='horizontal'); sep.grid(row=13, column=0, columnspan=4, sticky='ew', pady=10)
        ttk.Label(f, text="其他 vCard 字段:").grid(row=14, column=0, sticky="nw", pady=3)
        self.other_text = tk.Text(f, height=6, width=40, exportselection=False); self.other_text.grid(row=14, column=1, columnspan=3, pady=3, sticky="nsew")
        RightClickMenu(self.other_text, "text")
        ttk.Label(f, text="(格式: 标签: 内容，如: X-CUSTOM: value)", foreground="gray").grid(row=15, column=1, columnspan=3, sticky="w")

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
        self.preserved_photo = None

        if self.vcard:
            # 清除 initial 填充的简化值，从 vcard 重新读取完整数据
            self.email_entry.delete(0, tk.END)
            self.phone_entry.delete(0, tk.END)
            
            emails = []
            phones = []
            others = []
            standard = STANDARD_VCARD_FIELDS

            for child in self.vcard.getChildren():
                name = child.name.upper()

                # 处理标准字段
                if name == 'PHOTO':
                    self.preserved_photo = child
                elif name == 'EMAIL':
                    emails.append(child.value)
                elif name == 'TEL':
                    phones.append(child.value)
                elif name == 'ORG':
                    # ORG 提供一个列表
                    val = child.value[0] if isinstance(child.value, list) else child.value
                    self.org_entry.insert(0, val)
                elif name == 'TITLE':
                    self.title_entry.insert(0, child.value)
                elif name == 'URL':
                    self.url_entry.insert(0, child.value)
                elif name == 'ADR':
                    # 地址对象字符串表示
                    self.adr_text.insert("1.0", str(child.value))
                elif name == 'X-PHONETIC-FIRST-NAME':
                    self.first_phonetic_entry.insert(0, child.value)
                elif name == 'X-PHONETIC-LAST-NAME':
                    self.last_phonetic_entry.insert(0, child.value)
                elif name == 'NOTE':
                    self.note_text.insert("1.0", child.value)
                elif name == 'BDAY':
                    self.birthday_var.set(child.value)
                elif name not in standard:
                    label = self.FIELD_MAP.get(name, name)
                    others.append(f"{label}: {child.value}")

            self.email_entry.insert(0, ";".join(emails))
            self.phone_entry.insert(0, ";".join(phones))
            self.other_text.insert(tk.END, "\n".join(others))
        else:
            # 仅在非 vcard 模式下使用简化 initial 数据
            self.email_entry.insert(0, self.initial.get('email', ''))
            self.phone_entry.insert(0, self.initial.get('phone', ''))

    def show_raw(self):
        if not self.vcard and not self.raw_vcard_data: return
        w = tk.Toplevel(self); w.title("vCard 源码")
        scroll_h = ttk.Scrollbar(w, orient=tk.HORIZONTAL)
        scroll_v = ttk.Scrollbar(w, orient=tk.VERTICAL)
        t = tk.Text(w, wrap=tk.NONE, xscrollcommand=scroll_h.set, yscrollcommand=scroll_v.set)
        RightClickMenu(t, "text")
        scroll_h.config(command=t.xview); scroll_v.config(command=t.yview)
        scroll_h.pack(side=tk.BOTTOM, fill=tk.X)
        scroll_v.pack(side=tk.RIGHT, fill=tk.Y)
        t.pack(fill=tk.BOTH, expand=True)
        content = self.vcard.serialize() if self.vcard else self.raw_vcard_data
        t.insert(tk.END, content); t.config(state=tk.DISABLED)

    def encode_text(self, text):
        if not text: return ""
        if not should_encode(text): return text
        return f"ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:{quopri.encodestring(text.encode('utf-8')).decode('utf-8')}"

    def ok(self):
        if not self.name_entry.get(): messagebox.showerror("错误", "姓名不能为空"); return

        v = vobject.vCard()
        v.add('fn').value = self.name_entry.get()
        v.add('uid').value = self.uid_entry.get()

        # 处理姓名各部分
        n = v.add('n')
        parts = self.name_entry.get().split()
        n.value = vobject.vcard.Name(given=' '.join(parts[1:]) if len(parts) > 1 else '',
                                       family=parts[0] if parts else '')

        # 处理多邮箱
        for e in self.email_entry.get().split(';'):
            if e.strip(): v.add('email').value = e.strip()
        # 处理多电话
        for p in self.phone_entry.get().split(';'):
            if p.strip(): v.add('tel').value = p.strip()

        # 组织/公司
        if self.org_entry.get(): v.add('org').value = [self.org_entry.get()]
        # 职位
        if self.title_entry.get(): v.add('title').value = self.title_entry.get()
        # 网址
        if self.url_entry.get(): v.add('url').value = self.url_entry.get()
        # 地址
        if self.adr_text.get("1.0", "end-1c").strip():
            adr = v.add('adr')
            adr.value = vobject.vcard.Address(self.adr_text.get("1.0", "end-1c").strip())
        # 拼音
        if self.first_phonetic_entry.get():
            v.add('x-phonetic-first-name').value = self.first_phonetic_entry.get()
        if self.last_phonetic_entry.get():
            v.add('x-phonetic-last-name').value = self.last_phonetic_entry.get()
        # 备注
        if self.note_text.get("1.0", "end-1c").strip():
            v.add('note').value = self.note_text.get("1.0", "end-1c").strip()
        # 生日
        if self.birthday_var.get(): v.add('bday').value = self.birthday_var.get()
        
        # 恢复保留的照片
        if self.preserved_photo:
            v.add(self.preserved_photo)

        # 处理其他扩展字段
        others = self.other_text.get("1.0", "end-1c").strip().splitlines()
        for line in others:
            if ":" in line:
                label, val = line.split(":", 1)
                key = self.REV_FIELD_MAP.get(label.strip(), label.strip().upper())
                if key not in STANDARD_VCARD_FIELDS + ['X-PHONETIC-FIRST-NAME', 'X-PHONETIC-LAST-NAME']:
                    try: v.add(key.lower()).value = val.strip()
                    except: pass

        self.result = {'vcard': v.serialize(), 'name': v.fn.value}
        self.destroy()

    def cancel(self): self.result = None; self.destroy()
