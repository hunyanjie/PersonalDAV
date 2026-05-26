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

    def get_contact(self, uid):
        """获取单个联系人 vCard"""
        result = self.query_one("SELECT vcard FROM contacts WHERE uid=?", (uid,))
        return result[0] if result else None

    def get_contacts(self):
        """获取所有联系人简要信息"""
        return self.query("SELECT uid, full_name, email, phone FROM contacts")

    def get_all_contacts(self):
        """获取所有联系人 vCard 列表"""
        return [row[0] for row in self.query("SELECT vcard FROM contacts")]

    def get_selected_contacts(self, uids):
        """获取选中的联系人数据"""
        if not uids: return []
        placeholders = ','.join(['?'] * len(uids))
        return [row[0] for row in self.query(f"SELECT vcard FROM contacts WHERE uid IN ({placeholders})", uids)]

    def delete_contact(self, uid):
        """删除联系人"""
        self.execute("DELETE FROM contacts WHERE uid=?", (uid,))
        return True

    def get_event(self, uid):
        """获取单个事件 iCal"""
        result = self.query_one("SELECT ical FROM events WHERE uid=?", (uid,))
        return result[0] if result else None

    def get_events(self):
        """获取所有事件简要信息"""
        return self.query("SELECT uid, summary, dtstart, dtend FROM events")

    def get_all_events(self):
        """获取所有事件的序列化组件列表"""
        ical_list = [row[0] for row in self.query("SELECT ical FROM events")]
        events = []
        for row_ical in ical_list:
            try:
                import vobject
                cal = vobject.readOne(row_ical)
                for component in cal.components():
                    if component.name == 'VEVENT':
                        events.append(component.serialize())
            except Exception as e:
                logger.error(f"解析事件失败: {str(e)}")
        return events

    def get_selected_events(self, uids):
        """获取选中的事件数据"""
        if not uids: return []
        placeholders = ','.join(['?'] * len(uids))
        return [row[0] for row in self.query(f"SELECT ical FROM events WHERE uid IN ({placeholders})", uids)]

    def delete_event(self, uid):
        """删除事件"""
        self.execute("DELETE FROM events WHERE uid=?", (uid,))
        return True

    def count_contacts(self):
        """统计联系人数量"""
        return self.query_one("SELECT COUNT(*) FROM contacts")[0]

    def count_events(self):
        """统计事件数量"""
        return self.query_one("SELECT COUNT(*) FROM events")[0]

    def close(self):
        """关闭数据库连接"""
        if self.conn:
            self.conn.close()
            self.conn = None
