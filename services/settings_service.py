from database.db_manager import Database

class SettingsService:
    """系统设置业务逻辑 - 单例模式"""
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(SettingsService, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        self.db = Database()

    def get_setting(self, key, default=None):
        """获取设置值"""
        result = self.db.query_one('SELECT value FROM settings WHERE key=?', (key,))
        return result[0] if result else default

    def set_setting(self, key, value):
        """保存设置值"""
        self.db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, str(value)))

    def get_all_settings(self):
        """获取所有设置项"""
        return dict(self.db.query("SELECT key, value FROM settings"))
