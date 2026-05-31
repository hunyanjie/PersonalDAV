import requests
import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Callable
from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED, EVENT_EVENTS_CHANGED
from utils.logger import logger
import threading
import queue

class ImportSource(ABC):
    """导入来源接口 (Strategy Pattern)"""
    @abstractmethod
    def get_data(self) -> str | None:
        pass

class FileSource(ImportSource):
    """从文件导入"""
    def __init__(self, filetypes):
        self.filetypes = filetypes

    def get_data(self) -> str | None:
        path = filedialog.askopenfilename(filetypes=self.filetypes)
        if path:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        return None

class UrlSource(ImportSource):
    """从 URL 导入"""
    def get_data(self) -> str | None:
        url = simpledialog.askstring("URL 导入", "请输入 VCF/ICS 文件的 URL:")
        if url:
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                return response.text
            except Exception as e:
                from tkinter import messagebox
                messagebox.showerror("错误", f"下载失败: {str(e)}")
        return None

class ClipboardSource(ImportSource):
    """从剪切板导入"""
    def __init__(self, root):
        self.root = root

    def get_data(self) -> str | None:
        try:
            return self.root.clipboard_get()
        except:
            return None

class ImportTask:
    """导入任务封装"""
    def __init__(self, data: str, source_type: str, service, callback: Optional[Callable] = None):
        self.data = data
        self.source_type = source_type
        self.service = service
        self.callback = callback
        self.result = None
        self.error = None

class QueuedImportManager:
    """队列式导入管理器 - 支持批量导入和取消"""
    def __init__(self, service, import_type: str = 'contacts'):
        self.service = service
        self.import_type = import_type  # 'contacts' 或 'events'
        self.queue = queue.Queue()
        self.in_progress = False
        self.cancel_requested = False
        self._worker_thread = None
        self._progress_callback = None
        
    def set_progress_callback(self, callback: Callable):
        """设置进度回调函数"""
        self._progress_callback = callback
        
    def add_task(self, data: str, source: str = "未知") -> 'QueuedImportManager':
        """添加导入任务到队列"""
        task = ImportTask(data, source, self.service, self._on_task_complete)
        self.queue.put(task)
        logger.info(f"导入任务已加入队列: 来源={source}")
        return self
    
    def _on_task_complete(self, task: ImportTask):
        """单个任务完成回调"""
        if self._progress_callback:
            self._progress_callback(task)
    
    def start(self):
        """启动导入处理线程"""
        if self._worker_thread and self._worker_thread.is_alive():
            return
        self.cancel_requested = False
        self._worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self._worker_thread.start()
    
    def _process_queue(self):
        """处理导入队列"""
        self.in_progress = True
        total = self.queue.qsize()
        processed = 0
        success = 0
        failed = 0
        
        try:
            while not self.queue.empty() and not self.cancel_requested:
                try:
                    task = self.queue.get_nowait()
                    if self._process_task(task):
                        success += 1
                    else:
                        failed += 1
                    processed += 1
                    
                    if self._progress_callback:
                        self._progress_callback({
                            'current': processed,
                            'total': total,
                            'success': success,
                            'failed': failed,
                            'task': task
                        })
                except queue.Empty:
                    break
        finally:
            self.in_progress = False
            # 发布事件通知数据变更
            if self.import_type == 'contacts':
                event_bus.publish(EVENT_CONTACTS_CHANGED)
            else:
                event_bus.publish(EVENT_EVENTS_CHANGED)
            logger.info(f"导入队列处理完成: 成功={success}, 失败={failed}")
    
    def _process_task(self, task: ImportTask) -> bool:
        """处理单个导入任务"""
        try:
            data = task.data
            if "BEGIN:VCARD" in data:
                import re
                vcards = re.findall(r'BEGIN:VCARD.*?END:VCARD', data, re.DOTALL | re.IGNORECASE)
                for v in vcards:
                    if self.cancel_requested:
                        break
                    self.service.add_contact(v)
                task.result = f"导入 {len(vcards)} 个联系人"
                return True
            elif "BEGIN:VEVENT" in data or "BEGIN:VCALENDAR" in data:
                if "BEGIN:VEVENT" in data and "BEGIN:VCALENDAR" not in data:
                    self.service.add_event(data)
                else:
                    import vobject
                    cal = vobject.readOne(data)
                    count = 0
                    for component in cal.components():
                        if component.name == 'VEVENT':
                            if self.cancel_requested:
                                break
                            self.service.add_event(component.serialize())
                            count += 1
                    task.result = f"导入 {count} 个事件"
                return True
            else:
                task.error = "无法识别的数据格式"
                return False
        except Exception as e:
            task.error = str(e)
            logger.error(f"导入任务失败: {e}")
            return False
    
    def cancel(self):
        """取消导入操作"""
        self.cancel_requested = True
        # 清空队列
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
            except queue.Empty:
                break
        logger.info("导入操作已取消")
    
    def is_running(self) -> bool:
        """检查是否正在处理"""
        return self.in_progress


class TextImportManager:
    """导入管理器 - 兼容旧版接口，内部使用队列"""
    def __init__(self, service, import_type: str = 'contacts'):
        self.service = service
        self.import_type = import_type
        self._queued_manager = QueuedImportManager(service, import_type)

    def perform_import(self, source: ImportSource):
        """执行导入 - 兼容旧版接口"""
        data = source.get_data()
        if data:
            self._queued_manager.add_task(data).start()
            
    def perform_import_sync(self, source: ImportSource) -> Tuple[int, int]:
        """同步执行导入，返回 (成功数, 失败数)"""
        data = source.get_data()
        if not data:
            return 0, 0
            
        success = 0
        failed = 0
        
        try:
            if "BEGIN:VCARD" in data:
                import re
                vcards = re.findall(r'BEGIN:VCARD.*?END:VCARD', data, re.DOTALL | re.IGNORECASE)
                for v in vcards:
                    try:
                        self.service.add_contact(v)
                        success += 1
                    except:
                        failed += 1
            elif "BEGIN:VEVENT" in data or "BEGIN:VCALENDAR" in data:
                if "BEGIN:VEVENT" in data and "BEGIN:VCALENDAR" not in data:
                    self.service.add_event(data)
                    success = 1
                else:
                    import vobject
                    cal = vobject.readOne(data)
                    for component in cal.components():
                        if component.name == 'VEVENT':
                            try:
                                self.service.add_event(component.serialize())
                                success += 1
                            except:
                                failed += 1
        except Exception as e:
            logger.error(f"导入失败: {e}")
            failed += 1
            
        # 发布事件通知数据变更
        if self.import_type == 'contacts':
            event_bus.publish(EVENT_CONTACTS_CHANGED)
        else:
            event_bus.publish(EVENT_EVENTS_CHANGED)
            
        return success, failed
