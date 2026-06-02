from typing import Any
from database.repositories.settings_repository import SettingsRepository

class SettingsService:
    _instance: "SettingsService | None" = None
    _repo: SettingsRepository

    def __new__(cls) -> "SettingsService":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._repo = SettingsRepository()
        return cls._instance

    def get_setting(self, key: str, default: Any = None) -> Any:
        return self._repo.get(key, default)

    def set_setting(self, key: str, value: Any) -> None:
        self._repo.set(key, str(value))

    def get_all_settings(self) -> dict[str, str]:
        return self._repo.get_all()

    def reset_all(self) -> None:
        self._repo.delete_all()
