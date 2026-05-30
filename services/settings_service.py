from database.repositories.settings_repository import SettingsRepository

class SettingsService:
    """系统设置业务逻辑 - 单例模式"""
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(SettingsService, cls).__new__(cls)
            cls._instance._repo = SettingsRepository()
        return cls._instance

    def get_setting(self, key, default=None):
        return self._repo.get(key, default)

    def set_setting(self, key, value):
        self._repo.set(key, str(value))

    def get_all_settings(self):
        return self._repo.get_all()

    def reset_all(self):
        self._repo.delete_all()
