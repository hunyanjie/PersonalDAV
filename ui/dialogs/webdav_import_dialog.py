import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import uuid
import tempfile
from network.dav_client import WebDAVImportLogic
from ui.widgets.progress_window import ProgressWindow
from ui.widgets.right_click_menu import RightClickMenu

class WebDAVImportDialog(tk.Toplevel):
    """WebDAV 导入配置对话框 - 1:1 还原原版高级设置"""
    def __init__(self, parent, title, on_import_callback):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.grab_set()
        self.on_import_callback = on_import_callback
        
        self.default_options = {
            'webdav_timeout': 30,
            'webdav_verbose': False,
            'disable_check': False,
            'verify_ssl': True,
            'chunk_size': 65536,
            'proxy_hostname': None,
            'proxy_login': None,
            'proxy_password': None,
            'cert_path': None,
            'key_path': None
        }
        
        self.create_widgets()

    def create_widgets(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        basic_frame = ttk.Frame(notebook); notebook.add(basic_frame, text='基本设置')
        advanced_frame = ttk.Frame(notebook); notebook.add(advanced_frame, text='高级设置')

        # --- 基本设置 ---
        f = ttk.Frame(basic_frame); f.pack(fill=tk.BOTH, padx=10, pady=10)
        ttk.Label(f, text='服务器地址:').grid(row=0, column=0, sticky="w", pady=5)
        self.url_entry = ttk.Entry(f, width=40); self.url_entry.grid(row=0, column=1, pady=5)
        RightClickMenu(self.url_entry)

        ttk.Label(f, text='用户名:').grid(row=1, column=0, sticky="w", pady=5)
        self.username_entry = ttk.Entry(f, width=40); self.username_entry.grid(row=1, column=1, pady=5)
        RightClickMenu(self.username_entry)

        ttk.Label(f, text='密码:').grid(row=2, column=0, sticky="w", pady=5)
        self.password_entry = ttk.Entry(f, width=40, show='*'); self.password_entry.grid(row=2, column=1, pady=5)
        RightClickMenu(self.password_entry)

        ttk.Label(f, text='路径:').grid(row=3, column=0, sticky="w", pady=5)
        self.path_entry = ttk.Entry(f, width=40); self.path_entry.insert(0, '/'); self.path_entry.grid(row=3, column=1, pady=5)
        RightClickMenu(self.path_entry)

        # --- 高级设置 ---
        self._create_advanced_settings(advanced_frame)

        # 底部按钮
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=10)
        ttk.Button(btn_frame, text='导入', command=self.start_import).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text='测试连接', command=self.test_connection).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text='取消', command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def _create_advanced_settings(self, parent):
        main_f = ttk.Frame(parent); main_f.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 连接设置 - 1:1 还原 main_old.py:756-835
        conn_f = ttk.LabelFrame(main_f, text='连接与限速')
        conn_f.pack(fill=tk.X, pady=5)
        
        ttk.Label(conn_f, text='超时(秒):').grid(row=0, column=0, sticky="w", padx=5)
        self.timeout_entry = ttk.Entry(conn_f, width=10); self.timeout_entry.insert(0, '30'); self.timeout_entry.grid(row=0, column=1, pady=2)
        
        self.ssl_verify_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(conn_f, text='验证SSL证书', variable=self.ssl_verify_var).grid(row=0, column=2, padx=10)

        ttk.Label(conn_f, text='下载限速(KB/s):').grid(row=1, column=0, sticky="w", padx=5)
        self.recv_speed_entry = ttk.Entry(conn_f, width=10); self.recv_speed_entry.grid(row=1, column=1, pady=2)
        
        ttk.Label(conn_f, text='上传限速(KB/s):').grid(row=1, column=2, sticky="w", padx=5)
        self.send_speed_entry = ttk.Entry(conn_f, width=10); self.send_speed_entry.grid(row=1, column=3, pady=2)
        
        ttk.Label(conn_f, text='块大小(KB):').grid(row=2, column=0, sticky="w", padx=5)
        self.chunk_size_entry = ttk.Entry(conn_f, width=10); self.chunk_size_entry.insert(0, '64'); self.chunk_size_entry.grid(row=2, column=1, pady=2)
        
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(conn_f, text='详细模式', variable=self.verbose_var).grid(row=2, column=2, padx=10)

        self.disable_check_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(conn_f, text='禁用远程资源检查', variable=self.disable_check_var).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=2)

        # 代理设置
        proxy_f = ttk.LabelFrame(main_f, text='代理设置')
        proxy_f.pack(fill=tk.X, pady=5)
        ttk.Label(proxy_f, text='代理地址:').grid(row=0, column=0, sticky="w", padx=5)
        self.proxy_host_entry = ttk.Entry(proxy_f, width=30); self.proxy_host_entry.grid(row=0, column=1, columnspan=2, pady=2)
        ttk.Label(proxy_f, text='用户名:').grid(row=1, column=0, sticky="w", padx=5)
        self.proxy_user_entry = ttk.Entry(proxy_f, width=12); self.proxy_user_entry.grid(row=1, column=1, pady=2)
        ttk.Label(proxy_f, text='密码:').grid(row=1, column=2, sticky="w", padx=5)
        self.proxy_pass_entry = ttk.Entry(proxy_f, width=12, show='*'); self.proxy_pass_entry.grid(row=1, column=3, pady=2)

        # 证书设置
        cert_f = ttk.LabelFrame(main_f, text='证书设置')
        cert_f.pack(fill=tk.X, pady=5)
        ttk.Label(cert_f, text='证书路径:').grid(row=0, column=0, sticky="w", padx=5)
        self.cert_path_entry = ttk.Entry(cert_f, width=30); self.cert_path_entry.grid(row=0, column=1, pady=2)
        ttk.Button(cert_f, text='浏览', command=lambda: self._browse_file(self.cert_path_entry)).grid(row=0, column=2)
        ttk.Label(cert_f, text='私钥路径:').grid(row=1, column=0, sticky="w", padx=5)
        self.key_path_entry = ttk.Entry(cert_f, width=30); self.key_path_entry.grid(row=1, column=1, pady=2)
        ttk.Button(cert_f, text='浏览', command=lambda: self._browse_file(self.key_path_entry)).grid(row=1, column=2)

    def _browse_file(self, entry):
        p = filedialog.askopenfilename()
        if p: entry.delete(0, tk.END); entry.insert(0, p)

    def _collect_options(self):
        opts = {
            'webdav_hostname': self.url_entry.get().strip(),
            'webdav_login': self.username_entry.get().strip(),
            'webdav_password': self.password_entry.get().strip(),
            'webdav_root': self.path_entry.get().strip() or '/',
            'webdav_timeout': int(self.timeout_entry.get() or 30),
            'verify_ssl': self.ssl_verify_var.get(),
            'webdav_verbose': self.verbose_var.get(),
            'disable_check': self.disable_check_var.get(),
            'chunk_size': int(self.chunk_size_entry.get() or 64) * 1024
        }
        if self.recv_speed_entry.get(): opts['recv_speed'] = int(self.recv_speed_entry.get()) * 1024
        if self.send_speed_entry.get(): opts['send_speed'] = int(self.send_speed_entry.get()) * 1024
        if self.proxy_host_entry.get():
            opts['proxy_hostname'] = self.proxy_host_entry.get()
            opts['proxy_login'] = self.proxy_user_entry.get()
            opts['proxy_password'] = self.proxy_pass_entry.get()
        if self.cert_path_entry.get(): opts['cert_path'] = self.cert_path_entry.get()
        if self.key_path_entry.get(): opts['key_path'] = self.key_path_entry.get()
        return opts

    def test_connection(self):
        try:
            opts = self._collect_options()
            logic = WebDAVImportLogic(opts)
            success, msg = logic.test_connection()
            if success: messagebox.showinfo("成功", msg, parent=self)
            else: messagebox.showerror("失败", msg, parent=self)
        except Exception as e: messagebox.showerror("错误", str(e), parent=self)

    def start_import(self):
        opts = self._collect_options()
        if not opts['webdav_hostname']: messagebox.showerror('错误', '请输入服务器地址', parent=self); return
        progress_win = ProgressWindow(self, "WebDAV 导入进度")
        logic = WebDAVImportLogic(opts); progress_win.cancel_callback = logic.cancel
        threading.Thread(target=self._import_task, args=(logic, progress_win), daemon=True).start()

    def _import_task(self, logic, progress_win):
        try:
            progress_win.log("正在获取文件列表...")
            files = logic.list_files()
            target_files = [f for f in files if f.lower().endswith(('.vcf', '.ics'))]
            if not target_files: progress_win.log("未找到目标文件"); progress_win.set_finished(); return
            
            total = len(target_files); success_count = 0
            for i, filename in enumerate(target_files):
                if logic.cancel_event.is_set(): break
                progress_win.update_status(f"处理 {i+1}/{total}: {filename}")
                progress_win.update_progress((i/total)*100)
                temp_file = os.path.join(tempfile.gettempdir(), f"dav_import_{uuid.uuid4().hex}")
                
                # 定义文件下载进度回调
                def make_progress_cb(fname):
                    def cb(current, total_bytes):
                        if total_bytes > 0:
                            pct = (current / total_bytes) * 100
                            progress_win.log(f"  下载 {fname}: {pct:.1f}%")
                    return cb
                
                if logic.download_file(
                    f"{logic.options['webdav_hostname']}{filename}", 
                    temp_file,
                    progress_callback=make_progress_cb(filename)
                ):
                    with open(temp_file, 'r', encoding='utf-8') as tf:
                        # 调用回调并获取详细操作类型
                        result = self.on_import_callback(tf.read())
                        # 处理返回结果：可能是元组(uid, op_type)或简单布尔值
                        if isinstance(result, tuple) and len(result) >= 2:
                            res_uid, op_type = result[0], result[1]
                        else:
                            res_uid, op_type = result, "inserted" if result else None
                        
                        if res_uid:
                            success_count += 1
                            if hasattr(progress_win, 'stat_vars'):
                                if op_type == "inserted": progress_win.stat_vars['new'].set(progress_win.stat_vars['new'].get()+1)
                                elif op_type == "updated": progress_win.stat_vars['updated'].set(progress_win.stat_vars['updated'].get()+1)
                                elif op_type == "unchanged": progress_win.stat_vars['unchanged'].set(progress_win.stat_vars['unchanged'].get()+1)
                        else:
                            if hasattr(progress_win, 'stat_vars'):
                                progress_win.stat_vars['failed'].set(progress_win.stat_vars['failed'].get()+1)
                    # 清理临时文件
                    try:
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                    except:
                        pass
                else:
                    if hasattr(progress_win, 'stat_vars'):
                        progress_win.stat_vars['failed'].set(progress_win.stat_vars['failed'].get()+1)
                    
            progress_win.update_progress(100); progress_win.update_status(f"完成! 成功导入 {success_count}/{total} 个文件")
            progress_win.set_finished()
        except Exception as e: 
            progress_win.log(f"发生错误: {str(e)}")
            import traceback
            progress_win.log(traceback.format_exc())
            progress_win.set_finished()
