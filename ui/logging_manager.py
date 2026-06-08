import logging
from logging.handlers import RotatingFileHandler
from utils.logger import GUIHandler, logger


class LoggingManager:
    """日志管理 — 从 DAVServerApp 提取"""

    def __init__(self, settings_service, log_queue):
        self.settings_service = settings_service
        self.log_queue = log_queue
        self.file_handler = None

    def setup(self):
        gui_handler = GUIHandler(self.log_queue)
        logger.addHandler(gui_handler)
        self._setup_file_logging()

    def _setup_file_logging(self):
        enable_file = self.settings_service.get_setting("enable_log_file", "False") == "True"
        if self.file_handler:
            logger.removeHandler(self.file_handler)
            self.file_handler = None
        if enable_file:
            log_file = self.settings_service.get_setting("log_file_path", "data/log/dav_server.log")
            from utils.path_helper import resolve_data_path
            log_file = resolve_data_path(log_file)
            log_level = self.settings_service.get_setting("log_level", "INFO")
            try:
                self.file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
                self.file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
                self.file_handler.setLevel(getattr(logging, log_level, logging.INFO))
                logger.addHandler(self.file_handler)
                logger.info(f"日志文件已启用，路径: {log_file}，级别: {log_level}")
            except Exception as e:
                logger.warning(f"无法创建日志文件: {e}")

    def reconfigure(self):
        self._setup_file_logging()

    def process_queue(self, server_tab):
        import queue
        try:
            while not self.log_queue.empty():
                levelno, msg = self.log_queue.get_nowait()
                server_tab.log_message(msg, levelno)
        except queue.Empty:
            pass
