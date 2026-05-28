import os
import uuid
import tempfile
import threading
from webdav3.client import Client
from utils.logger import logger

class WebDAVImportLogic:
    """WebDAV 导入业务逻辑 - 1:1 还原原版连接逻辑"""
    
    def __init__(self, options):
        self.options = options
        self.client = Client(options)
        self.cancel_event = threading.Event()
        self.active_downloads = []
        self.lock = threading.Lock()

    def test_connection(self):
        """测试连接"""
        try:
            # 简单的列表操作测试连接
            self.client.list(self.options.get('webdav_root', '/'))
            return True, "成功连接到WebDAV服务器"
        except Exception as e:
            return False, str(e)

    def list_files(self):
        """获取文件列表"""
        return self.client.list(self.options.get('webdav_root', '/'))

    def download_file(self, remote_path, local_path, progress_callback=None):
        """下载单个文件 - 支持进度回调与限速
        
        Args:
            remote_path: 远程文件路径
            local_path: 本地保存路径
            progress_callback: 可选的进度回调函数(current, total) -> bool
        """
        import time
        last_time = time.time()
        last_bytes = 0
        recv_speed = self.options.get('recv_speed') # bytes/s

        def internal_callback(current, total):
            nonlocal last_time, last_bytes
            if self.cancel_event.is_set():
                raise Exception('下载被用户取消')
            
            # 速率限制逻辑 (1:1 还原旧版缺失功能)
            if recv_speed and recv_speed > 0:
                elapsed = time.time() - last_time
                if elapsed > 0:
                    current_bytes = current - last_bytes
                    expected_time = current_bytes / recv_speed
                    if elapsed < expected_time:
                        time.sleep(expected_time - elapsed)
                last_time = time.time()
                last_bytes = current

            # 调用外部进度回调
            if progress_callback:
                try:
                    progress_callback(current, total)
                except Exception as e:
                    logger.warning(f"进度回调错误: {e}")
            return True

        with self.lock:
            if self.cancel_event.is_set():
                return False
            self.active_downloads.append(local_path)

        try:
            self.client.download_sync(
                remote_path=remote_path,
                local_path=local_path,
                callback=internal_callback
            )
            return True
        except Exception as e:
            if self.cancel_event.is_set():
                logger.info(f"下载已取消: {remote_path}")
            else:
                logger.error(f"下载失败 {remote_path}: {str(e)}")
            return False
        finally:
            with self.lock:
                if local_path in self.active_downloads:
                    self.active_downloads.remove(local_path)

    def cancel(self):
        """取消所有下载"""
        self.cancel_event.set()
        with self.lock:
            for path in self.active_downloads:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except:
                    pass
            self.active_downloads.clear()
