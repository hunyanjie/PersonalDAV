import os
import hashlib
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
    _vacuum_in_progress = False

    def __new__(cls, db_path=DEFAULT_DB_PATH):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(Database, cls).__new__(cls)
        return cls._instance

    _checkpoint_interval = 60  # seconds
    _checkpoint_timer: threading.Timer | None = None

    def __init__(self, db_path=DEFAULT_DB_PATH):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        if os.path.isfile(db_path):
            try:
                bak = db_path + ".bak"
                if not os.path.isfile(bak) or os.path.getmtime(db_path) > os.path.getmtime(bak):
                    import shutil
                    shutil.copy2(db_path, bak)
            except Exception as e:
                logger.warning(f"数据库自动备份失败: {e}")
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA busy_timeout = 5000;")
        self.conn.execute("PRAGMA journal_mode = WAL;")
        self.conn.execute("PRAGMA synchronous = NORMAL;")
        self.conn.execute("PRAGMA auto_vacuum = INCREMENTAL;")
        self.create_tables()
        self._vacuum_if_needed()
        self._start_wal_checkpoint()

    def _vacuum_if_needed(self):
        try:
            page_count = self.query_one("PRAGMA page_count")[0]
            freelist = self.query_one("PRAGMA freelist_count")[0]
            if freelist > page_count * 0.5 and freelist > 100:
                self.execute("VACUUM")
                new_pages = self.query_one("PRAGMA page_count")[0]
                logger.info(f"数据库自动压缩完成: {page_count} -> {new_pages} 页 (释放 {page_count - new_pages} 页)")
        except Exception:
            pass

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
                except Exception: pass

        # 迁移: 为 auth_logs 添加哈希链列
        for col in ['prev_hash', 'hash']:
            try: c.execute(f"ALTER TABLE auth_logs ADD COLUMN {col} TEXT DEFAULT ''")
            except Exception: pass
        # 回填现有行的哈希链
        missing = c.execute("SELECT COUNT(*) FROM auth_logs WHERE hash IS NULL OR hash = ''").fetchone()[0]
        if missing:
            existing = c.execute("SELECT id, timestamp, ip, success, method, detail FROM auth_logs ORDER BY id ASC").fetchall()
            prev = "0"
            for row in existing:
                data = f"{prev}|{row[1]}|{row[2]}|{row[3]}|{row[4] or ''}|{row[5] or ''}"
                h = hashlib.sha256(data.encode('utf-8')).hexdigest()
                c.execute("UPDATE auth_logs SET prev_hash=?, hash=? WHERE id=?", (prev, h, row[0]))
                prev = h
            logger.info(f"已回填 {missing} 条审计日志的哈希链")

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
        except Exception: pass

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

    def _start_wal_checkpoint(self):
        self._do_wal_checkpoint()  # immediate first checkpoint
        self._schedule_wal_checkpoint()

    def _schedule_wal_checkpoint(self):
        self._checkpoint_timer = threading.Timer(self._checkpoint_interval, self._do_wal_checkpoint)
        self._checkpoint_timer.daemon = True
        self._checkpoint_timer.start()

    def _do_wal_checkpoint(self):
        try:
            with self._lock:
                self.conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        except Exception:
            pass
        finally:
            self._schedule_wal_checkpoint()

    def _stop_wal_checkpoint(self):
        if self._checkpoint_timer:
            self._checkpoint_timer.cancel()
            self._checkpoint_timer = None

    def vacuum_full(self) -> int | None:
        """完整 VACUUM 重写数据库，释放所有空闲空间。返回释放的字节数，失败返回 None。

        安全说明：SQLite VACUUM 创建临时文件 → 复制数据 → 原子替换原文件。
        若中途崩溃或断电，原文件不受影响。
        """
        if self._vacuum_in_progress:
            logger.warning("数据库压缩已在运行中，忽略重复请求")
            return None
        self._vacuum_in_progress = True
        try:
            with self._lock:
                c = self.conn.cursor()
                c.execute("PRAGMA page_count")
                old_pages = c.fetchone()[0]
                c.execute("PRAGMA page_size")
                page_size = c.fetchone()[0]
                c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                c.execute("VACUUM")
                c.execute("PRAGMA page_count")
                new_pages = c.fetchone()[0]
            saved = (old_pages - new_pages) * page_size
            logger.info(f"数据库压缩完成: {old_pages} -> {new_pages} 页, 释放 {saved / 1024:.1f} KB")
            return saved
        except Exception as e:
            logger.error(f"数据库压缩失败: {e}")
            return None
        finally:
            self._vacuum_in_progress = False

    def close(self):
        """关闭数据库连接"""
        self._stop_wal_checkpoint()
        if self.conn:
            self.conn.close()
            self.conn = None

    def reopen(self):
        """关闭旧连接并重新打开（用于恢复备份后）"""
        self._stop_wal_checkpoint()
        if self.conn:
            self.conn.close()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA busy_timeout = 5000;")
        self.conn.execute("PRAGMA journal_mode = WAL;")
        self.conn.execute("PRAGMA synchronous = NORMAL;")
        self.create_tables()
        self._start_wal_checkpoint()

    @classmethod
    def reset(cls):
        """重置单例（仅用于测试）"""
        with cls._lock:
            if cls._instance:
                cls._instance._stop_wal_checkpoint()
                if cls._instance.conn:
                    cls._instance.conn.close()
            cls._instance = None
