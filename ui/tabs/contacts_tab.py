import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ui.dialogs.contact_dialog import ContactDialog
from ui.dialogs.webdav_import_dialog import WebDAVImportDialog
from ui.widgets.right_click_menu import RightClickMenu
from ui.tabs.base_tab import BaseTreeTab
from tkinterdnd2 import DND_FILES
import vobject
import re

from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED
from utils.logger import logger
import os


class ContactsTab(BaseTreeTab):
    """联系人管理标签页"""
    COLUMNS = ("selected", "uid", "name", "email", "phone", "groups", "created_at", "updated_at")
    HEADINGS = {
        "selected": "✓",
        "uid": "ID",
        "name": "姓名",
        "email": "邮箱",
        "phone": "电话",
        "groups": "分组",
        "created_at": "添加时间",
        "updated_at": "修改时间"
    }

    def __init__(self, parent, contact_service, app_root):
        self.db = contact_service
        self.app_root = app_root

        super().__init__(parent)
        self._import_type = 'contacts'

        self.create_widgets()
        self.refresh_contacts()

        # 订阅数据变更事件
        event_bus.subscribe(EVENT_CONTACTS_CHANGED, self.refresh_contacts)

    def get_column_width(self, col):
        widths = {"selected": 30, "uid": 100, "name": 150, "email": 200, "phone": 150, "groups": 120, "created_at": 160, "updated_at": 160}
        return widths.get(col, 100)

    def create_widgets(self):
        # 搜索栏 (放在列表框架上方)
        self.setup_search_ui(self)

        # 分组筛选
        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        ttk.Label(filter_frame, text="分组筛选:").pack(side=tk.LEFT, padx=(0, 5))
        self._group_filter_var = tk.StringVar(value="全部")
        self._group_filter_combo = ttk.Combobox(filter_frame, textvariable=self._group_filter_var,
                                                  values=["全部"], state="readonly", width=18)
        self._group_filter_combo.pack(side=tk.LEFT)
        self._group_filter_var.trace("w", lambda *a: self._apply_group_filter())

        # 列表框架
        list_frame = ttk.LabelFrame(self, text="联系人列表")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # 操作提示
        hint_label = ttk.Label(list_frame, text="操作提示: 1) 点击复选框选择/取消 2) 表头复选框全选 3) 鼠标拖拽多选 4) 双击行编辑", foreground="blue")
        hint_label.pack(fill=tk.X, padx=5, pady=5)

        # 初始化 Treeview
        self.setup_treeview(list_frame, self.edit_contact)

        # 右键菜单
        RightClickMenu(self.tree)

        # 按钮栏
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(btn_frame, text="添加联系人", command=self.add_contact).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="编辑联系人", command=self.edit_contact).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="删除联系人", command=self.delete_contact).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="查看原始数据", command=self.show_raw).pack(side=tk.LEFT, padx=2)

        # 导入菜单
        import_btn = ttk.Menubutton(btn_frame, text="导入数据")
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

        ttk.Button(btn_frame, text="导出选中", command=self.export_selected).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_frame, text="刷新列表", command=self.refresh_contacts).pack(side=tk.RIGHT, padx=10)

    def refresh_contacts(self):
        """刷新联系人列表"""
        selected_uids = {self.tree.item(i)['values'][1] for i in self.tree.selection() if self.tree.exists(i)}
        self._all_data = self.db.get_list_data()
        self._update_group_filter()
        self.apply_filter(getattr(self, 'search_var', None) and self.search_var.get().lower() or "")
        self._after_refresh()

    def _update_group_filter(self):
        groups = set()
        for c in self._all_data:
            uid, name, emails, phones, gs, created_at, updated_at = c
            if gs:
                for g in gs.split(';'):
                    if g.strip():
                        groups.add(g.strip())
        all_vals = ["全部"] + sorted(groups)
        self._group_filter_combo['values'] = all_vals
        if self._group_filter_var.get() not in all_vals:
            self._group_filter_var.set("全部")

    def _apply_group_filter(self):
        query = getattr(self, 'search_var', None) and self.search_var.get().lower() or ""
        self.apply_filter(query)

    def apply_filter(self, query):
        """执行过滤显示"""
        selected_uids = {self.tree.item(i)['values'][1] for i in self.tree.selection() if self.tree.exists(i)}
        for item in self.tree.get_children(): self.tree.delete(item)

        selected_group = self._group_filter_var.get()
        for contact in self._all_data:
            uid, name, emails, phones, gs, created_at, updated_at = contact
            match = not query or any(query in str(v).lower() for v in contact)
            
            if match and (selected_group == "全部" or (gs and selected_group in gs.split(';'))):
                sel = "✓" if uid in selected_uids else " "
                disp_emails = emails.replace(";", "; ") if emails else ""
                disp_phones = phones.replace(";", "; ") if phones else ""

                item_id = self.tree.insert("", tk.END, values=(sel, uid, name, disp_emails, disp_phones, gs, created_at, updated_at))
                if sel == "✓": self.tree.selection_add(item_id)

    def add_contact(self):
        dialog = ContactDialog(self.app_root)
        if dialog.result:
            self.db.add_contact(dialog.result['vcard'])
            self.refresh_contacts()

    def edit_contact(self):
        sel = self.tree.selection()
        if not sel: return
        uid = self.tree.item(sel[0])['values'][1]
        data = self.db.get_by_uid(uid)
        if data:
            try:
                v = vobject.readOne(data)
                init = {
                    'uid': uid,
                    'name': v.fn.value if hasattr(v, 'fn') else '',
                    'email': getattr(v, 'email', None).value if hasattr(v, 'email') else '',
                    'phone': getattr(v, 'tel', None).value if hasattr(v, 'tel') else ''
                }
                dialog = ContactDialog(self.app_root, initial=init, vcard=v)
            except Exception:
                logger.warning(f"vCard 解析失败，尝试手动恢复字段: {uid}")
                from utils.vcard_parser import RobustVCardParser
                parsed = RobustVCardParser.manual_parse(data)
                if parsed:
                    init = {
                        'uid': parsed.get('uid', uid),
                        'name': parsed.get('full_name', ''),
                        'email': parsed.get('email', ''),
                        'phone': parsed.get('phone', '')
                    }
                else:
                    init = {'uid': uid}
                dialog = ContactDialog(self.app_root, initial=init, raw_vcard=data)
            if dialog.result:
                self.db.add_contact(dialog.result['vcard'])
                self.refresh_contacts()

    def delete_contact(self):
        sel = self.tree.selection()
        if not sel: return
        uids = []
        for i in sel:
            try:
                uids.append(self.tree.item(i)['values'][1])
            except:
                continue
        if not uids: return
        if messagebox.askyesno("确认", f"确定删除选中的 {len(uids)} 个联系人吗？"):
            for uid in uids:
                self.db.delete(uid)
            self.refresh_contacts()
    
    def _on_delete(self):
        """处理删除事件（来自右键菜单或Delete键）"""
        self.delete_contact()

    def show_raw(self):
        sel = self.tree.selection()
        if not sel: return
        uids = [self.tree.item(i)['values'][1] for i in sel]
        raws = self.db.get_selected_raw(uids)
        data = ''.join(raws) if len(sel) > 1 else raws[0]
        if data:
            win = tk.Toplevel(self); win.title("原始数据")
            sb_h = ttk.Scrollbar(win, orient=tk.HORIZONTAL)
            sb_v = ttk.Scrollbar(win, orient=tk.VERTICAL)
            txt = tk.Text(win, wrap=tk.NONE, xscrollcommand=sb_h.set, yscrollcommand=sb_v.set)
            RightClickMenu(txt, "text", actions=["copy", None, "select_all"])
            sb_h.config(command=txt.xview); sb_v.config(command=txt.yview)
            sb_h.pack(side=tk.BOTTOM, fill=tk.X)
            sb_v.pack(side=tk.RIGHT, fill=tk.Y)
            txt.pack(fill=tk.BOTH, expand=True)
            txt.insert(tk.END, data); txt.config(state=tk.DISABLED)

    def import_webdav(self):
        dialog = WebDAVImportDialog(self, "从 WebDAV 导入联系人", self.db.add_contact)
        self.wait_window(dialog)

    def _import_add_item(self, raw, force=False, publish=True):
        return self.db.add_contact(raw, force=force, publish=publish)

    def _import_refresh_list(self):
        self.refresh_contacts()

    def _parse_data_to_items(self, data):
        """将原始 vCard 数据解析为 item 列表，供 ImportPreviewDialog 使用"""
        items = []
        if "BEGIN:VCARD" not in data:
            return items
        vcards = re.findall(r'BEGIN:VCARD.*?END:VCARD', data, re.DOTALL | re.IGNORECASE)
        for v in vcards:
            try:
                vobj = vobject.readOne(v)
                uid = vobj.uid.value if hasattr(vobj, 'uid') else ""
                fn = vobj.fn.value if hasattr(vobj, 'fn') else "(无姓名)"
                existing = self.db.get_by_uid(uid) is not None
                items.append({"uid": uid, "title": fn, "raw": v, "is_new": not existing, "has_dup": False})
            except:
                items.append({"uid": "?", "title": "(解析失败)", "raw": v, "is_new": True, "has_dup": False})
        return items

    def export_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("提示", "请先选择要导出的联系人", parent=self)
            return
        uids = [self.tree.item(i)['values'][1] for i in sel]
        vcards = self.db.get_selected_raw(uids)

        # 单选时预填文件名
        initial = ""
        if len(sel) == 1:
            name = self.tree.item(sel[0])['values'][2]  # 姓名列
            if name:
                # 清理文件名中的非法字符
                import re
                name = re.sub(r'[<>:"/\\|?*]', '_', name)
                initial = name

        path = filedialog.asksaveasfilename(
            defaultextension=".vcf",
            filetypes=[("vCard", "*.vcf"), ("所有文件", "*.*")],
            initialfile=initial
        )
        if path:
            if not path.endswith('.vcf'):
                path += '.vcf'
            # vCard 组件末尾已有换行符，直接连接
            content = "".join(vcards)
            with open(path, 'w', encoding='utf-8') as f: f.write(content)
            from ui.widgets.toast import Toast
            Toast.show(self, f"成功导出 {len(vcards)} 个联系人")
