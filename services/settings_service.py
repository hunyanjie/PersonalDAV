import time
import threading
from typing import Any
from database.repositories.settings_repository import SettingsRepository


class SettingsService:
    _instance: "SettingsService | None" = None
    _repo: SettingsRepository = None

    _cache: dict[str, tuple[Any, float]] = {}
    _cache_lock = threading.Lock()
    _cache_ttl = 5.0

    def __new__(cls) -> "SettingsService":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._repo = SettingsRepository()
        return cls._instance

    def get_setting(self, key: str, default: Any = None) -> Any:
        now = time.time()
        with self._cache_lock:
            if key in self._cache:
                val, expires = self._cache[key]
                if now < expires:
                    return val
        val = self._repo.get(key, default)
        with self._cache_lock:
            self._cache[key] = (val, now + self._cache_ttl)
        return val

    def set_setting(self, key: str, value: Any) -> None:
        self._repo.set(key, str(value))
        with self._cache_lock:
            self._cache[key] = (value, time.time() + self._cache_ttl)

    def get_all_settings(self) -> dict[str, str]:
        return self._repo.get_all()

    def reset_all(self) -> None:
        self._repo.delete_all()
        with self._cache_lock:
            self._cache.clear()
