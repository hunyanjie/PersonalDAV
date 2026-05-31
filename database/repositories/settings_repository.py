from typing import Optional, Dict
from database.db_manager import Database

class SettingsRepository:
    def __init__(self):
        self.db = Database()

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        result = self.db.query_one('SELECT value FROM settings WHERE key=?', (key,))
        return result[0] if result else default

    def set(self, key: str, value: str):
        self.db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))

    def get_all(self) -> Dict[str, str]:
        return dict(self.db.query("SELECT key, value FROM settings"))

    def delete_all(self):
        self.db.execute("DELETE FROM settings")
