import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ui.dialogs.contact_dialog import ContactDialog
from ui.dialogs.webdav_import_dialog import WebDAVImportDialog
from ui.widgets.right_click_menu import RightClickMenu
from tkinterdnd2 import DND_FILES
import os
import vobject
from utils.logger import logger

from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED
from services.import_service import TextImportManager, FileSource, UrlSource, ClipboardSource

from ui.widgets.treeview_scroller import TreeviewScroller

class ContactsTab(ttk.Frame):
    """联系人管理标签页 - 1:1 还原并架构增强"""
    def __init__(self, parent, contact_service, app_root):
        super().__init__(parent)
        self.db = contact_service 
        self.app_root = app_root
        self.import_manager = TextImportManager(contact_service)
        self.contact_sort_col = ''
        self.contact_sort_rev = False
        
        self.create_widgets()
        self.setup_dnd()
        self.refresh_contacts()
        
        # 订阅数据变更事件，实现自动刷新
        event_bus.subscribe(EVENT_CONTACTS_CHANGED, self.refresh_contacts)

    def create_widgets(self):
        # 列表框架
        list_frame = ttk.LabelFrame(self, text="联系人列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 操作提示
        hint_label = ttk.Label(list_frame, text="操作提示: 1) 点击复选框选择/取消 2) 表头复选框全选 3) 鼠标拖拽多选 4) 双击行编辑", foreground="blue")
        hint_label.pack(fill=tk.X, padx=5, pady=5)

        # Treeview 配置
        columns = ("selected", "uid", "name", "email", "phone")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
        
        self.tree.heading("selected", text="✓", command=self.toggle_all_selection)
        self.tree.heading("uid", text="ID", command=lambda: self.sort_tree("uid"))
        self.tree.heading("name", text="姓名", command=lambda: self.sort_tree("name"))
        self.tree.heading("email", text="邮箱", command=lambda: self.sort_tree("email"))
        self.tree.heading("phone", text="电话", command=lambda: self.sort_tree("phone"))

        self.tree.column("selected", width=30, anchor=tk.CENTER)
        self.tree.column("uid", width=100)
        self.tree.column("name", width=150)
        self.tree.column("email", width=200)
        self.tree.column("phone", width=150)

        sb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=sb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        # 绑定事件
        self.tree.bind('<ButtonPress-1>', self.on_click)
        self.tree.bind('<B1-Motion>', self.on_drag)
        self.tree.bind('<ButtonRelease-1>', self.on_release)
        self.tree.bind('<Double-1>', lambda e: self.edit_contact())
        self.tree.bind('<Motion>', self.on_motion)
        self.tree.bind("<Control-a>", self.select_all)
        self.tree.bind("<<TreeviewEdit>>", lambda e: self.edit_contact())
        self.tree.bind("<<TreeviewDelete>>", lambda e: self.delete_contact())
        self.tree.bind("<<TreeviewShowRaw>>", lambda e: self.show_raw())

        # 右键菜单
        RightClickMenu(self.tree)

        # 按钮栏增强
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(btn_frame, text="添加联系人", command=self.add_contact).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="编辑联系人", command=self.edit_contact).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除联系人", command=self.delete_contact).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="查看原始数据", command=self.show_raw).pack(side=tk.LEFT, padx=2)
        
        # 导入菜单
        import_btn = ttk.Menubutton(btn_frame, text="导入数据")
        import_menu = tk.Menu(import_btn, tearoff=0)
        import_menu.add_command(label="从文件导入...", command=lambda: self.import_manager.perform_import(FileSource([("vCard", "*.vcf")])))
        import_menu.add_command(label="从 URL 导入...", command=lambda: self.import_manager.perform_import(UrlSource()))
        import_menu.add_command(label="从剪切板导入", command=lambda: self.import_manager.perform_import(ClipboardSource(self.app_root)))
        import_menu.add_command(label="粘贴文本导入...", command=self.show_text_import)
        import_menu.add_command(label="WebDAV 导入...", command=self.import_webdav)
        import_btn.config(menu=import_menu)
        import_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(btn_frame, text="导出选中", command=self.export_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="刷新列表", command=self.refresh_contacts).pack(side=tk.RIGHT, padx=10)

        # 初始化拖拽变量
        self.drag_start = None
        self.drag_item = None
        self.dragging = False
        self.last_selected = None

    def setup_dnd(self):
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.on_drop)

    def on_drop(self, event):
        files = self.tk.splitlist(event.data)
        for f in files:
            if f.lower().endswith('.vcf'):
                with open(f, 'r', encoding='utf-8') as file:
                    self.db.add_contact(file.read())
        self.refresh_contacts()

    def refresh_contacts(self):
        """刷新联系人列表，支持多邮箱多电话显示"""
        selected_uids = {self.tree.item(i)['values'][1] for i in self.tree.selection() if self.tree.exists(i)}
        for item in self.tree.get_children(): self.tree.delete(item)
        
        for contact in self.db.get_contacts_list():
            # contact 格式为 (uid, full_name, emails, phones)
            uid, name, emails, phones = contact
            sel = "✓" if uid in selected_uids else " "
            # 将分号替换为分号+空格以提升 Treeview 可读性
            disp_emails = emails.replace(";", "; ") if emails else ""
            disp_phones = phones.replace(";", "; ") if phones else ""
            
            item_id = self.tree.insert("", tk.END, values=(sel, uid, name, disp_emails, disp_phones))
            if sel == "✓": self.tree.selection_add(item_id)

    def sort_tree(self, col):
        if self.contact_sort_col == col: self.contact_sort_rev = not self.contact_sort_rev
        else: self.contact_sort_col = col; self.contact_sort_rev = False
        
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        data.sort(reverse=self.contact_sort_rev)
        for idx, (_, k) in enumerate(data): self.tree.move(k, '', idx)

    def toggle_all_selection(self):
        all_items = self.tree.get_children()
        all_sel = all(i in self.tree.selection() for i in all_items)
        new_sel = [] if all_sel else all_items
        self.tree.selection_set(new_sel)
        for i in all_items:
            vals = list(self.tree.item(i, 'values'))
            vals[0] = " " if all_sel else "✓"
            self.tree.item(i, values=vals)

    def on_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        item = self.tree.identify_row(event.y)
        column = self.tree.identify_column(event.x)
        self.drag_start = (event.x, event.y); self.drag_item = item; self.dragging = False

        if region == "heading" and column == "#1": self.toggle_all_selection(); return "break"
        if region == "heading": return

        if event.state & 0x0001: # Shift
            if not item: return "break"
            all_items = list(self.tree.get_children())
            start_idx = all_items.index(self.last_selected or all_items[0])
            end_idx = all_items.index(item)
            selected = all_items[min(start_idx, end_idx):max(start_idx, end_idx)+1]
            self.tree.selection_set(selected)
            for i in all_items:
                v = list(self.tree.item(i, 'values'))
                v[0] = "✓" if i in selected else " "
                self.tree.item(i, values=v)
            return "break"

        if column == "#1" and item:
            cur = self.tree.selection()
            if item in cur: self.tree.selection_remove(item); state = " "
            else: self.tree.selection_add(item); state = "✓"
            v = list(self.tree.item(item, 'values')); v[0] = state; self.tree.item(item, values=v)
            self.last_selected = item
            return "break"

        if item:
            self.tree.selection_set([item])
            for i in self.tree.get_children():
                v = list(self.tree.item(i, 'values')); v[0] = "✓" if i == item else " "; self.tree.item(i, values=v)
            self.last_selected = item
            return "break"

    def on_drag(self, event):
        self.dragging = True
        TreeviewScroller.handle_drag_scroll(self.tree, event)

        if not self.drag_item: return
        item = self.tree.identify_row(event.y)
        if not item: return

        all_items = list(self.tree.get_children())
        start_idx = self.tree.index(self.drag_item)
        curr_idx = self.tree.index(item)
        selected = all_items[min(start_idx, curr_idx):max(start_idx, curr_idx)+1]
        self.tree.selection_set(selected)
        for i in all_items:
            v = list(self.tree.item(i, 'values'))
            v[0] = "✓" if i in selected else " "
            self.tree.item(i, values=v)

    def on_release(self, event):
        self.drag_start = None; self.drag_item = None; self.dragging = False

    def on_motion(self, event):
        """处理自动滚动逻辑 - 对齐旧版 10% 阈值并平滑化"""
        TreeviewScroller.handle_drag_scroll(self.tree, event)

    def select_all(self, event):
        items = self.tree.get_children()
        self.tree.selection_set(items)
        for i in items:
            v = list(self.tree.item(i, 'values')); v[0] = "✓"; self.tree.item(i, values=v)
        return "break"

    def add_contact(self):
        dialog = ContactDialog(self.app_root)
        if dialog.result:
            self.db.add_contact(dialog.result['vcard'])
            self.refresh_contacts()

    def edit_contact(self):
        sel = self.tree.selection()
        if not sel: return
        uid = self.tree.item(sel[0])['values'][1]
        data = self.db.get_contact(uid)
        if data:
            v = vobject.readOne(data)
            init = {'uid': uid, 'name': v.fn.value if hasattr(v, 'fn') else '', 'email': getattr(v, 'email', None).value if hasattr(v, 'email') else '', 'phone': getattr(v, 'tel', None).value if hasattr(v, 'tel') else ''}
            dialog = ContactDialog(self.app_root, initial=init, vcard=v)
            if dialog.result:
                self.db.add_contact(dialog.result['vcard'])
                self.refresh_contacts()

    def delete_contact(self):
        sel = self.tree.selection()
        if not sel: return
        if messagebox.askyesno("确认", f"确定删除选中的 {len(sel)} 个联系人吗？"):
            for i in sel: self.db.delete_contact(self.tree.item(i)['values'][1])
            self.refresh_contacts()

    def show_raw(self):
        sel = self.tree.selection()
        if not sel: return
        uid = self.tree.item(sel[0])['values'][1]
        data = self.db.get_contact(uid)
        if data:
            win = tk.Toplevel(self); win.title("原始数据")
            txt = tk.Text(win); txt.pack(fill=tk.BOTH, expand=True)
            txt.insert(tk.END, data); txt.config(state=tk.DISABLED)

    def import_webdav(self):
        dialog = WebDAVImportDialog(self, "从 WebDAV 导入联系人", self.db.add_contact)
        self.wait_window(dialog)

    def show_text_import(self):
        from ui.dialogs.text_import_dialog import TextImportDialog
        dialog = TextImportDialog(self.app_root, "粘贴 vCard 文本导入", self.db.add_contact)
        self.wait_window(dialog)

    def export_selected(self):
        sel = self.tree.selection()
        if not sel: return
        uids = [self.tree.item(i)['values'][1] for i in sel]
        vcards = self.db.get_selected_vcards(uids)
        path = filedialog.asksaveasfilename(defaultextension=".vcf")
        if path:
            with open(path, 'w', encoding='utf-8') as f: f.write("\n".join(vcards))
            messagebox.showinfo("成功", f"成功导出 {len(vcards)} 个联系人")
