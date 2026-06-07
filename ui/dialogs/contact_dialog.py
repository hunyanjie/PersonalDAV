import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import uuid
import vobject
from tkcalendar import Calendar
from ui.widgets.right_click_menu import RightClickMenu
from utils.encoding_helper import should_encode
from models.constants import STANDARD_VCARD_FIELDS
from ui.widgets.enhanced_tooltip import EnhancedTooltip
import quopri
import base64
import io
import os
from PIL import Image, ImageTk


class ContactDialog(tk.Toplevel):
    """添加/编辑联系人对话框"""

    def __init__(self, parent, initial=None, vcard=None, raw_vcard=None):
        super().__init__(parent)
        self.title("添加/编辑联系人")
        # self.geometry("650x750")
        self.transient(parent)
        self.grab_set()

        self.result = None
        self.initial = initial or {}
        self.vcard = vcard
        self.raw_vcard_data = raw_vcard
        self.other_fields = []

        self.create_widgets()
        self.set_initial_values()
        from utils.window_utils import center_window
        center_window(self, parent)

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
        EnhancedTooltip(self.name_entry, "必填。联系人显示名称")
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
        EnhancedTooltip(self.email_entry, "多个邮箱请用分号(;)分隔")
        RightClickMenu(self.email_entry)

        ttk.Label(f, text="电话:").grid(row=5, column=0, sticky="w", pady=3)
        self.phone_entry = ttk.Entry(f, width=40, exportselection=False); self.phone_entry.grid(row=5, column=1, columnspan=3, pady=3, sticky="we")
        ttk.Label(f, text="(多个用分号分隔)", foreground="gray").grid(row=6, column=1, sticky="w")
        EnhancedTooltip(self.phone_entry, "多个电话请用分号(;)分隔")
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

        # 分组
        ttk.Label(f, text="分组:").grid(row=12, column=0, sticky="w", pady=3)
        self.groups_entry = ttk.Entry(f, width=40, exportselection=False)
        self.groups_entry.grid(row=12, column=1, columnspan=3, pady=3, sticky="we")
        EnhancedTooltip(self.groups_entry, "多个分组请用分号(;)分隔")
        RightClickMenu(self.groups_entry)

        # 备注
        ttk.Label(f, text="备注:").grid(row=13, column=0, sticky="nw", pady=3)
        self.note_text = tk.Text(f, height=4, width=40, exportselection=False); self.note_text.grid(row=13, column=1, columnspan=3, pady=3, sticky="nsew")
        RightClickMenu(self.note_text, "text")

        # 其他 vCard 字段
        sep = ttk.Separator(f, orient='horizontal'); sep.grid(row=14, column=0, columnspan=4, sticky='ew', pady=10)
        ttk.Label(f, text="其他 vCard 字段:").grid(row=15, column=0, sticky="nw", pady=3)
        other_frame = ttk.Frame(f)
        other_frame.grid(row=15, column=1, columnspan=3, sticky="nsew", pady=3)
        form_f = ttk.Frame(other_frame); form_f.pack(fill=tk.X)
        ttk.Label(form_f, text="键:").pack(side=tk.LEFT)
        self.other_key_var = tk.StringVar()
        ttk.Entry(form_f, textvariable=self.other_key_var, width=14).pack(side=tk.LEFT, padx=2)
        ttk.Label(form_f, text="值:").pack(side=tk.LEFT)
        self.other_val_var = tk.StringVar()
        ttk.Entry(form_f, textvariable=self.other_val_var, width=25).pack(side=tk.LEFT, padx=2)
        ttk.Button(form_f, text="增加", width=8, command=self._other_add).pack(side=tk.LEFT, padx=1)
        ttk.Button(form_f, text="修改", width=8, command=self._other_update).pack(side=tk.LEFT, padx=1)
        ttk.Button(form_f, text="删除", width=8, command=self._other_delete).pack(side=tk.LEFT, padx=1)
        tree_f = ttk.Frame(other_frame); tree_f.pack(fill=tk.BOTH, expand=True, pady=2)
        self.other_tree = ttk.Treeview(tree_f, columns=('key', 'value'), show="headings", height=5, selectmode='extended')
        self.other_tree.heading('key', text='键', command=lambda: self._other_sort('key'))
        self.other_tree.heading('value', text='值', command=lambda: self._other_sort('value'))
        self.other_tree.column('key', width=120); self.other_tree.column('value', width=300)
        tv_scroll = ttk.Scrollbar(tree_f, orient="vertical", command=self.other_tree.yview)
        self.other_tree.configure(yscrollcommand=tv_scroll.set)
        self.other_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); tv_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.other_tree.bind("<Double-1>", lambda e: self._other_edit())
        self.other_tree.bind("<Button-3>", self._other_popup)
        # 头像
        photo_f = ttk.LabelFrame(f, text="头像", width=180)
        photo_f.grid(row=0, column=4, rowspan=13, padx=(10, 0), pady=3, sticky="n")
        photo_f.grid_propagate(False)
        self.photo_preview = ttk.Label(photo_f, text="无头像", anchor=tk.CENTER)
        self.photo_preview.pack(padx=5, pady=(10, 5))
        self._photo_image = None
        self._photo_bytes = None
        ttk.Button(photo_f, text="选择照片", command=self._select_photo).pack(pady=2)
        ttk.Button(photo_f, text="清除照片", command=self._clear_photo).pack(pady=2)
        ttk.Label(photo_f, text="支持 JPG/PNG，自动缩放", foreground="gray", wraplength=150).pack(pady=(5, 0))

        f.grid_rowconfigure(15, weight=1); f.grid_columnconfigure(1, weight=1)

        btn_f = ttk.Frame(self); btn_f.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        ttk.Button(btn_f, text="确定", command=self.ok).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_f, text="取消", command=self.cancel).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_f, text="原始数据", command=self.show_raw).pack(side=tk.LEFT, padx=5)

    def pick_date(self):
        w = tk.Toplevel(self); w.title("选择日期"); w.grab_set()
        cal = Calendar(w, date_pattern='yyyy-mm-dd')
        cal.pack(padx=10, pady=10)
        ttk.Button(w, text="确定", command=lambda: [self.birthday_var.set(cal.get_date()), w.destroy()]).pack(pady=5)

    def _select_photo(self):
        path = filedialog.askopenfilename(
            title="选择头像图片",
            filetypes=[("图片文件", "*.jpg *.jpeg *.png *.gif *.bmp")]
        )
        if not path:
            return
        try:
            size = os.path.getsize(path)
            if size > 2 * 1024 * 1024:
                if not messagebox.askyesno("提示", f"图片大小为 {size/1024/1024:.1f}MB，"
                                            f"将自动缩放为缩略图，建议使用更小的图片。\n\n是否继续？",
                                            parent=self):
                    return
            img = Image.open(path)
            if img.width * img.height > 2000 * 2000:
                img.thumbnail((1000, 1000), Image.LANCZOS)
            self._set_photo_image(img)
        except Exception as e:
            messagebox.showerror("错误", f"无法加载图片:\n{e}", parent=self)

    def _clear_photo(self):
        self._photo_image = None
        self._photo_bytes = None
        self.preserved_photo = None
        self.photo_preview.config(image="", text="无头像")

    def _set_photo_image(self, img):
        img.thumbnail((160, 160), Image.LANCZOS)
        self._photo_image = ImageTk.PhotoImage(img)
        self.photo_preview.config(image=self._photo_image, text="")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        self._photo_bytes = buf.getvalue()

    def _load_photo_from_vcard(self):
        self._photo_bytes = None
        if not self.preserved_photo:
            return
        self.after_idle(self._process_photo_async)

    def _process_photo_async(self):
        if not self.preserved_photo:
            return
        try:
            val = self.preserved_photo.value
            if isinstance(val, str):
                raw = base64.b64decode(val)
            else:
                raw = val
            if len(raw) > 5 * 1024 * 1024:
                return
            img = Image.open(io.BytesIO(raw))
            if img.width * img.height > 2000 * 2000:
                img.thumbnail((1000, 1000), Image.LANCZOS)
            self._set_photo_image(img)
            self.preserved_photo.value = self._photo_bytes
        except Exception:
            pass

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
            standard = STANDARD_VCARD_FIELDS

            for child in self.vcard.getChildren():
                name = child.name.upper()

                # 处理标准字段
                if name == 'PHOTO':
                    self.preserved_photo = child
                    self._load_photo_from_vcard()
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
                elif name == 'CATEGORIES':
                    val = child.value
                    if isinstance(val, list):
                        self.groups_entry.insert(0, ";".join(val))
                    else:
                        self.groups_entry.insert(0, val.replace(',', ';'))
                elif name not in standard:
                    self.other_fields.append({"key": name, "value": child.value})

            self.email_entry.insert(0, ";".join(emails))
            self.phone_entry.insert(0, ";".join(phones))
            self._other_refresh()
        else:
            # 仅在非 vcard 模式下使用简化 initial 数据
            self.email_entry.insert(0, self.initial.get('email', ''))
            self.phone_entry.insert(0, self.initial.get('phone', ''))

    def show_raw(self):
        if not self.vcard and not self.raw_vcard_data: return
        w = tk.Toplevel(self); w.title("vCard 源码")
        scroll_v = ttk.Scrollbar(w, orient=tk.VERTICAL)
        t = tk.Text(w, wrap=tk.CHAR, yscrollcommand=scroll_v.set)
        RightClickMenu(t, "text", actions=["copy", None, "select_all"])
        scroll_v.config(command=t.yview)
        scroll_v.pack(side=tk.RIGHT, fill=tk.Y)
        t.pack(fill=tk.BOTH, expand=True)
        if self.raw_vcard_data:
            content = self.raw_vcard_data
        else:
            vobject.vcard.wacky_apple_photo_serialize = False
            content = self.vcard.serialize()
            vobject.vcard.wacky_apple_photo_serialize = True
        t.insert(tk.END, content)
        t.config(state=tk.DISABLED)

    def _other_add(self):
        key = self.other_key_var.get().strip()
        value = self.other_val_var.get().strip()
        if not key:
            messagebox.showwarning("提示", "键不能为空", parent=self)
            return
        self.other_fields.append({"key": key.upper(), "value": value})
        self._other_refresh()

    def _other_update(self):
        sel = self.other_tree.selection()
        if len(sel) != 1:
            messagebox.showinfo("提示", "请选择一个字段", parent=self)
            return
        idx = self.other_tree.index(sel[0])
        key = self.other_key_var.get().strip()
        value = self.other_val_var.get().strip()
        if not key:
            messagebox.showwarning("提示", "键不能为空", parent=self)
            return
        self.other_fields[idx] = {"key": key.upper(), "value": value}
        self._other_refresh()

    def _other_edit(self):
        sel = self.other_tree.selection()
        if len(sel) != 1:
            messagebox.showinfo("提示", "请选择一个字段", parent=self)
            return
        idx = self.other_tree.index(sel[0])
        self.other_key_var.set(self.other_fields[idx]['key'])
        self.other_val_var.set(self.other_fields[idx]['value'])

    def _other_delete(self):
        sel = self.other_tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请选择要删除的字段", parent=self)
            return
        if not messagebox.askyesno("确认", f"确定删除选中的 {len(sel)} 个字段?", parent=self):
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
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="编辑", command=self._other_edit, state=tk.NORMAL if len(sel) == 1 else tk.DISABLED)
        menu.add_command(label="删除", command=self._other_delete)
        menu.add_command(label="重复", command=self._other_duplicate)
        menu.post(e.x_root, e.y_root)

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
        # 分组
        if self.groups_entry.get():
            cats = [g.strip() for g in self.groups_entry.get().split(';') if g.strip()]
            v.add('categories').value = cats
        
        # 照片
        if self._photo_bytes:
            v.add('photo').value = self._photo_bytes
            v.photo.encoding_param = 'b'
            v.photo.type_param = 'PNG'
        elif self.preserved_photo:
            v.add(self.preserved_photo)

        # 处理其他扩展字段
        for field in self.other_fields:
            k, val = field.get('key', '').strip(), field.get('value', '').strip()
            if k and k.upper() not in STANDARD_VCARD_FIELDS + ['X-PHONETIC-FIRST-NAME', 'X-PHONETIC-LAST-NAME']:
                try: v.add(k.lower()).value = val
                except: pass

        vobject.vcard.wacky_apple_photo_serialize = False
        self.result = {'vcard': v.serialize(), 'name': v.fn.value}
        vobject.vcard.wacky_apple_photo_serialize = True
        self.destroy()

    def cancel(self): self.result = None; self.destroy()
