import logging
import queue
from logging.handlers import RotatingFileHandler
from config import SOFTWARE_NAME, DEFAULT_LOG_FILE, DEFAULT_LOG_LEVEL

class GUIHandler(logging.Handler):
    log_queue: queue.Queue

    def __init__(self, log_queue: queue.Queue) -> None:
        super().__init__()
        self.log_queue = log_queue
        self.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S'))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            formatted_message = self.format(record)
            self.log_queue.put((record.levelno, formatted_message))
        except Exception:
            self.handleError(record)

def setup_logger(name: str = __name__, level: int | None = None, log_file: str | None = None) -> logging.Logger:
    """配置日志记录器，支持文件滚动"""
    logger = logging.getLogger(name)

    if level is None:
        level = DEFAULT_LOG_LEVEL

    logger.setLevel(level)

    # 清除可能已有的处理器
    if logger.hasHandlers():
        logger.handlers.clear()

    # 禁用向上传播到根日志器，防止重复输出
    logger.propagate = False

    # 创建滚动文件处理器 (每个 10MB，保留 5 个)
    if log_file:
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger

# 创建全局 logger 实例
logger = setup_logger(SOFTWARE_NAME)
