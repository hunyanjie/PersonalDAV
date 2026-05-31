import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ui.dialogs.contact_dialog import ContactDialog
from ui.dialogs.webdav_import_dialog import WebDAVImportDialog
from ui.dialogs.import_preview_dialog import ImportPreviewDialog
from ui.widgets.right_click_menu import RightClickMenu
from ui.tabs.base_tab import BaseTreeTab
from tkinterdnd2 import DND_FILES
import vobject

from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED
from utils.logger import logger
import os


class ContactsTab(BaseTreeTab):
    """联系人管理标签页"""
    COLUMNS = ("selected", "uid", "name", "email", "phone", "created_at", "updated_at")
    HEADINGS = {
        "selected": "✓",
        "uid": "ID",
        "name": "姓名",
        "email": "邮箱",
        "phone": "电话",
        "created_at": "添加时间",
        "updated_at": "修改时间"
    }

    def __init__(self, parent, contact_service, app_root):
        self.db = contact_service
        self.app_root = app_root

        super().__init__(parent)

        self.create_widgets()
        self.refresh_contacts()

        # 订阅数据变更事件
        event_bus.subscribe(EVENT_CONTACTS_CHANGED, self.refresh_contacts)

    def get_column_width(self, col):
        widths = {"selected": 30, "uid": 100, "name": 150, "email": 200, "phone": 150, "created_at": 160, "updated_at": 160}
        return widths.get(col, 100)

    def create_widgets(self):
        # 搜索栏 (放在列表框架上方)
        self.setup_search_ui(self)

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
        self.apply_filter(getattr(self, 'search_var', None) and self.search_var.get().lower() or "")
        self._after_refresh()

    def apply_filter(self, query):
        """执行过滤显示"""
        selected_uids = {self.tree.item(i)['values'][1] for i in self.tree.selection() if self.tree.exists(i)}
        for item in self.tree.get_children(): self.tree.delete(item)

        for contact in self._all_data:
            uid, name, emails, phones, created_at, updated_at = contact
            match = not query or any(query in str(v).lower() for v in contact)
            
            if match:
                sel = "✓" if uid in selected_uids else " "
                disp_emails = emails.replace(";", "; ") if emails else ""
                disp_phones = phones.replace(";", "; ") if phones else ""

                item_id = self.tree.insert("", tk.END, values=(sel, uid, name, disp_emails, disp_phones, created_at, updated_at))
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

    def show_text_import(self):
        from ui.dialogs.text_import_dialog import TextImportDialog
        dialog = TextImportDialog(self.app_root, "粘贴 vCard 文本导入")
        self.wait_window(dialog)
        data = dialog.result
        if not data:
            return
        items = self._parse_data_to_items(data)
        if not items:
            messagebox.showinfo("提示", "未识别到有效 vCard 数据", parent=self)
            return
        dlg = ImportPreviewDialog(self, "contacts",
            on_import_callback=lambda sel: self._import_selected(sel, "文本粘贴"),
            items=items)
        self.wait_window(dlg)

    def show_import_preview(self):
        dialog = ImportPreviewDialog(self, "contacts")
        self.wait_window(dialog)

    # === 文件/URL/剪切板导入 (先预览后导入) ===

    def _parse_data_to_items(self, data):
        """将原始 vCard 数据解析为 item 列表，供 ImportPreviewDialog 使用"""
        items = []
        if "BEGIN:VCARD" not in data:
            return items
        import re
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

    def _import_selected(self, items, source):
        """将预览对话框中选择的 items 导入（带进度窗口）"""
        from ui.widgets.progress_window import ProgressWindow
        import threading, uuid, re
        win = ProgressWindow(self, f"正在从 {source} 导入...")
        def run():
            total = len(items)
            stats = {'new': 0, 'updated': 0, 'unchanged': 0, 'failed': 0}
            for idx, it in enumerate(items):
                action = it.get('_action', 'new')
                if action == 'new_uid':
                    new_uid = str(uuid.uuid4())
                    raw = re.sub(r'^UID:.*$', f'UID:{new_uid}', it['raw'], count=1, flags=re.MULTILINE | re.IGNORECASE)
                    _, op = self.db.add_contact(raw, publish=False)
                    if op == "inserted":
                        stats['new'] += 1
                        msg = f"新增(重置UID): {it['title']}"
                    else:
                        stats['failed'] += 1
                        msg = f"失败(重置UID): {it['title']}"
                else:
                    _, op = self.db.add_contact(it['raw'], force=True, publish=False)
                    if op == "inserted":
                        stats['new'] += 1
                        msg = f"新增: {it['title']}"
                    elif op == "updated":
                        stats['updated'] += 1
                        msg = f"更新: {it['title']}"
                    elif op == "unchanged":
                        stats['unchanged'] += 1
                        msg = None
                    else:
                        stats['failed'] += 1
                        msg = f"失败: {it['title']}"
                pct = (idx + 1) / total * 100
                s = dict(stats)
                win.after(0, lambda m=msg, p=pct, st=s: (
                    win.log(m) if m else None,
                    win.update_progress(p),
                    win.stat_vars['new'].set(st['new']),
                    win.stat_vars['updated'].set(st['updated']),
                    win.stat_vars['unchanged'].set(st['unchanged']),
                    win.stat_vars['failed'].set(st['failed'])))
            win.after(0, lambda: (
                win.update_status("导入完成"),
                win.set_finished(),
                self.refresh_contacts()))
        threading.Thread(target=run, daemon=True).start()

    def _import_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("联系人文件", "*.vcf *.vcs"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = f.read()
            items = self._parse_data_to_items(data)
            if not items:
                messagebox.showinfo("提示", "未识别到有效 vCard 数据", parent=self)
                return
            dialog = ImportPreviewDialog(self, "contacts",
                on_import_callback=lambda sel: self._import_selected(sel, os.path.basename(path)),
                items=items)
            self.wait_window(dialog)
        except Exception as e:
            messagebox.showerror("错误", f"读取文件失败: {e}", parent=self)

    def _import_url(self):
        from tkinter import simpledialog
        url = simpledialog.askstring("URL 导入", "请输入 VCF 文件的 URL:", parent=self)
        if not url:
            return
        from ui.widgets.progress_window import ProgressWindow
        import threading, requests
        win = ProgressWindow(self, "正在从 URL 下载...")
        def run():
            try:
                resp = requests.get(url, timeout=10)
                resp.raise_for_status()
                data = resp.text
                win.after(0, win.destroy)
                items = self._parse_data_to_items(data)
                if not items:
                    win.after(0, lambda: messagebox.showinfo("提示", "未识别到有效 vCard 数据", parent=self))
                    return
                win.after(0, lambda: ImportPreviewDialog(self, "contacts",
                    on_import_callback=lambda sel: self._import_selected(sel, "URL"),
                    items=items))
            except Exception as e:
                win.after(0, lambda: [win.destroy(), messagebox.showerror("错误", f"下载失败: {e}", parent=self)])
        threading.Thread(target=run, daemon=True).start()

    def _import_clipboard(self):
        try:
            data = self.app_root.clipboard_get()
            if not data.strip():
                messagebox.showinfo("提示", "剪切板为空", parent=self); return
            items = self._parse_data_to_items(data)
            if not items:
                messagebox.showinfo("提示", "未识别到有效 vCard 数据", parent=self)
                return
            dialog = ImportPreviewDialog(self, "contacts",
                on_import_callback=lambda sel: self._import_selected(sel, "剪切板"),
                items=items)
            self.wait_window(dialog)
        except:
            messagebox.showinfo("提示", "无法读取剪切板内容", parent=self)

    def _import_data(self, data, source):
        """通用直接导入（跳过预览），由 show_text_import 等调用"""
        from ui.widgets.progress_window import ProgressWindow
        import threading
        win = ProgressWindow(self, f"正在从 {source} 导入...")
        def run():
            stats = {'new': 0, 'updated': 0, 'unchanged': 0, 'failed': 0}
            try:
                if "BEGIN:VCARD" in data:
                    import re
                    vcards = re.findall(r'BEGIN:VCARD.*?END:VCARD', data, re.DOTALL | re.IGNORECASE)
                    for v in vcards:
                        _, op = self.db.add_contact(v, publish=False)
                        if op == "inserted": stats['new'] += 1
                        elif op == "updated": stats['updated'] += 1
                        elif op == "unchanged": stats['unchanged'] += 1
                        else: stats['failed'] += 1
                else:
                    win.after(0, lambda: win.log("错误: 未检测到 vCard 数据"))
            except Exception as e:
                win.after(0, lambda: win.log(f"错误: {e}"))
            win.after(0, lambda: [
                win.stat_vars['new'].set(stats['new']),
                win.stat_vars['updated'].set(stats['updated']),
                win.stat_vars['unchanged'].set(stats['unchanged']),
                win.stat_vars['failed'].set(stats['failed']),
                win.update_status("导入完成"),
                win.set_finished(),
                self.refresh_contacts()])
        threading.Thread(target=run, daemon=True).start()

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
            messagebox.showinfo("成功", f"成功导出 {len(vcards)} 个联系人")
