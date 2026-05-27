import logging
import queue
from logging.handlers import RotatingFileHandler
from config import DEFAULT_LOG_FILE, DEFAULT_LOG_LEVEL

class GUIHandler(logging.Handler):
    """自定义日志处理器，将日志发送到GUI队列"""

    def __init__(self, log_queue):
        super().__init__()
        self.log_queue = log_queue
        # 设置格式化器 - 添加时间戳
        self.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%H:%M:%S'))

    def emit(self, record):
        try:
            # 使用格式化器格式化日志消息
            formatted_message = self.format(record)
            # 将格式化后的日志添加到队列
            self.log_queue.put(formatted_message)
        except Exception:
            self.handleError(record)

def setup_logger(name=__name__, level=None, log_file=None):
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
logger = setup_logger("PrivateDAV")
