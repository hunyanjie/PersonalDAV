import sqlite3
import threading
import json
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
        return cls._instance

    def __init__(self, db_path=DEFAULT_DB_PATH):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA busy_timeout = 5000;")
        self.conn.execute("PRAGMA journal_mode = WAL;")  # 开启 WAL 模式提高并发性能
        self.conn.execute("PRAGMA synchronous = NORMAL;") # 配合 WAL 提高写入速度
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
                      vcard TEXT,
                      created_at TEXT,
                      updated_at TEXT)''')
        # 事件表
        c.execute('''CREATE TABLE IF NOT EXISTS events
                     (id INTEGER PRIMARY KEY,
                      uid TEXT UNIQUE,
                      summary TEXT,
                      dtstart TEXT,
                      dtend TEXT,
                      ical TEXT,
                      created_at TEXT,
                      updated_at TEXT)''')
        # 设置表
        c.execute('''CREATE TABLE IF NOT EXISTS settings
                     (key TEXT PRIMARY KEY,
                      value TEXT)''')
        # 鉴权日志表
        c.execute('''CREATE TABLE IF NOT EXISTS auth_logs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      timestamp TEXT,
                      ip TEXT,
                      success INTEGER,
                      method TEXT,
                      detail TEXT)''')
        
        # 迁移: 为已有数据库添加时间戳列
        for table in ['contacts', 'events']:
            for col in ['created_at', 'updated_at']:
                try: c.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")
                except: pass

        # 远程连接表（FTP/FTPS/SFTP 保存的连接）
        c.execute('''CREATE TABLE IF NOT EXISTS remote_connections
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      protocol TEXT,
                      server TEXT,
                      port INTEGER,
                      username TEXT,
                      password TEXT,
                      encoding TEXT,
                      label TEXT,
                      created_at TEXT)''')

        # 迁移: 联系人分组
        try: c.execute("ALTER TABLE contacts ADD COLUMN groups TEXT")
        except: pass

        # 初始数据填充 (仅在表为空时)
        c.execute("SELECT COUNT(*) FROM settings")
        if c.fetchone()[0] == 0:
            initial_settings = [
                ('preset_reminders', "5分钟前;15分钟前;30分钟前;1小时前;2小时前;1天前"),
                ('preset_allday_reminders', "日程发生时;1天前;2天前;7天前"),
                ('default_reminders', "15分钟前"),
                ('default_allday_reminders', "当天上午9点"),
                ('custom_default_reminders', json.dumps({'action': 'AUDIO', 'trigger': {'type': 'td', 'seconds': -1800}, 'description': '半小时前提示音', 'attach': 'default_alarm.wav'}, ensure_ascii=False)),
                ('auto_save_port', "True"),
                ('default_port', "8000"),
                ('default_status', "CONFIRMED"),
                ('default_version', "2.0"),
                ('default_duration', "60"),
                ('default_priority', "5"),
                ('default_transparency', "OPAQUE"),
                ('default_sync_timezone', "True"),
                ('default_repeat', "不重复"),
                ('default_end_cond', "永不结束"),
                ('default_end_count', "5"),
                ('ssl_enabled', "False"),
                ('ssl_certfile', ""),
                ('ssl_keyfile', "")
            ]

            c.executemany("INSERT INTO settings (key, value) VALUES (?, ?)", initial_settings)
            
        self.conn.commit()
            
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

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None

    def reopen(self):
        """关闭旧连接并重新打开（用于恢复备份后）"""
        if self.conn:
            self.conn.close()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA busy_timeout = 5000;")
        self.conn.execute("PRAGMA journal_mode = WAL;")
        self.conn.execute("PRAGMA synchronous = NORMAL;")
        self.create_tables()

    @classmethod
    def reset(cls):
        """重置单例（仅用于测试）"""
        with cls._lock:
            if cls._instance and cls._instance.conn:
                cls._instance.conn.close()
            cls._instance = None
