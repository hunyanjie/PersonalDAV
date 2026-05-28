import sqlite3
import threading
from contextlib import contextmanager
from utils.logger import logger
from config import DEFAULT_DB_PATH

class Database:
    """数据库管理类 (单例模式)"""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path=DEFAULT_DB_PATH):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(Database, cls).__new__(cls)
                    cls._instance._initialize(db_path)
        return cls._instance

    def _initialize(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA busy_timeout = 5000;")
        self.create_tables()

    @contextmanager
    def transaction(self):
        """事务上下文管理器"""
        with self._lock:
            try:
                yield self.conn.cursor()
                self.conn.commit()
            except Exception as e:
                self.conn.rollback()
                logger.error(f"数据库事务失败: {str(e)}")
                raise

    def create_tables(self):
        """初始化数据库表"""
        c = self.conn.cursor()
        # 联系人表
        c.execute('''CREATE TABLE IF NOT EXISTS contacts
                     (id INTEGER PRIMARY KEY,
                      uid TEXT UNIQUE,
                      full_name TEXT,
                      email TEXT,
                      phone TEXT,
                      vcard TEXT)''')
        # 事件表
        c.execute('''CREATE TABLE IF NOT EXISTS events
                     (id INTEGER PRIMARY KEY,
                      uid TEXT UNIQUE,
                      summary TEXT,
                      dtstart TEXT,
                      dtend TEXT,
                      ical TEXT)''')
        # 设置表
        c.execute('''CREATE TABLE IF NOT EXISTS settings
                     (key TEXT PRIMARY KEY,
                      value TEXT)''')
        self.conn.commit()

    def execute(self, query, params=None):
        """执行 SQL 查询"""
        with self._lock:
            try:
                c = self.conn.cursor()
                if params:
                    c.execute(query, params)
                else:
                    c.execute(query)
                self.conn.commit()
                return c
            except Exception as e:
                self.conn.rollback()
                logger.error(f"数据库操作失败: {str(e)}")
                raise

    def query(self, query, params=None):
        """查询并返回结果"""
        with self._lock:
            c = self.conn.cursor()
            if params:
                c.execute(query, params)
            else:
                c.execute(query)
            return c.fetchall()

    def query_one(self, query, params=None):
        """查询并返回单条结果"""
        with self._lock:
            c = self.conn.cursor()
            if params:
                c.execute(query, params)
            else:
                c.execute(query)
            return c.fetchone()

    def count_contacts(self):
        """统计联系人数量"""
        res = self.query_one("SELECT COUNT(*) FROM contacts")
        return res[0] if res else 0

    def count_events(self):
        """统计事件数量"""
        res = self.query_one("SELECT COUNT(*) FROM events")
        return res[0] if res else 0

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None
