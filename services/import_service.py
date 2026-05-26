import requests
import tkinter as tk
from tkinter import filedialog, simpledialog
from abc import ABC, abstractmethod

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

class TextImportManager:
    """导入管理器"""
    def __init__(self, service):
        self.service = service

    def perform_import(self, source: ImportSource):
        data = source.get_data()
        if data:
            # 这里可以进行更复杂的批量解析逻辑
            # 目前简单调用 add_contact/add_event
            # 实际中可能包含多条记录，需要 split
            if "BEGIN:VCARD" in data:
                import re
                vcards = re.findall(r'BEGIN:VCARD.*?END:VCARD', data, re.DOTALL | re.IGNORECASE)
                for v in vcards:
                    self.service.add_contact(v)
            elif "BEGIN:VEVENT" in data or "BEGIN:VCALENDAR" in data:
                # 处理日历
                if "BEGIN:VEVENT" in data and "BEGIN:VCALENDAR" not in data:
                    self.service.add_event(data)
                else:
                    import vobject
                    cal = vobject.readOne(data)
                    for component in cal.components():
                        if component.name == 'VEVENT':
                            self.service.add_event(component.serialize())
