"""
Backend 抽象层 — 统一服务访问接口，支持本地直连和远程 API 两种模式。

架构：
    Backend (ABC)
      ├── LocalBackend    直接调用现有 Service 层
      └── RemoteBackend   通过 httpx 调用 daemon REST API
"""

from __future__ import annotations

import abc
import time
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from services.contact_service import ContactService
    from services.event_service import EventService
    from services.settings_service import SettingsService


class Backend(abc.ABC):
    """后端抽象 — GUI 通过此接口访问所有业务能力。"""

    @property
    @abc.abstractmethod
    def contact_service(self) -> "ContactService":
        ...

    @property
    @abc.abstractmethod
    def event_service(self) -> "EventService":
        ...

    @property
    @abc.abstractmethod
    def settings_service(self) -> "SettingsService":
        ...

    @abc.abstractmethod
    def health(self) -> dict[str, Any]:
        ...

    @abc.abstractmethod
    def close(self):
        ...


# ── LocalBackend ─────────────────────────────────────────────────


class LocalBackend(Backend):
    """本地直连 — 直接实例化 Service 层。"""

    def __init__(self):
        from services.contact_service import ContactService
        from services.event_service import EventService
        from services.settings_service import SettingsService
        self._contact = ContactService()
        self._event = EventService()
        self._settings = SettingsService()
        self._start_time = time.time()

    @property
    def contact_service(self) -> "ContactService":
        return self._contact

    @property
    def event_service(self) -> "EventService":
        return self._event

    @property
    def settings_service(self) -> "SettingsService":
        return self._settings

    def health(self) -> dict[str, Any]:
        from config import SOFTWARE_VERSION
        return {
            "status": "ok",
            "version": SOFTWARE_VERSION,
            "uptime": time.time() - self._start_time,
            "contacts_count": self._contact.count(),
            "events_count": self._event.count(),
        }

    def close(self):
        from database.db_manager import Database
        Database().close()


# ── RemoteBackend ────────────────────────────────────────────────


class _RemoteSettings:
    """SettingsService 兼容代理 — 通过 REST API 读写设置。"""

    def __init__(self, client: "httpx.Client", prefix: str):
        self._client = client
        self._prefix = prefix

    def get_setting(self, key: str, default: Any = None) -> Any:
        try:
            r = self._client.get(f"{self._prefix}/settings/{key}", timeout=5)
            if r.status_code == 200:
                return r.json().get("value", default)
        except Exception:
            pass
        return default

    def set_setting(self, key: str, value: Any):
        try:
            self._client.put(f"{self._prefix}/settings/{key}",
                             json={"value": value}, timeout=5)
        except Exception:
            pass


class _RemoteContactService:
    """ContactService 兼容代理 — 通过 REST API 操作联系人。"""

    def __init__(self, client: "httpx.Client", prefix: str):
        self._client = client
        self._prefix = prefix

    def get_by_uid(self, uid: str) -> str | None:
        try:
            r = self._client.get(f"{self._prefix}/contacts/{uid}", timeout=5)
            if r.status_code == 200:
                return r.json().get("vcard", "")
        except Exception:
            pass
        return None

    def get_list_data(self) -> list[tuple]:
        return []

    def get_all_raw(self) -> list[str]:
        try:
            r = self._client.get(f"{self._prefix}/contacts", timeout=10)
            if r.status_code == 200:
                return [c["vcard"] for c in r.json() if c.get("vcard")]
        except Exception:
            pass
        return []

    def get_all_items(self):
        try:
            r = self._client.get(f"{self._prefix}/contacts", timeout=10)
            if r.status_code == 200:
                return [(c["uid"], c["vcard"]) for c in r.json() if c.get("uid") and c.get("vcard")]
        except Exception:
            pass
        return []

    def add_contact(self, vcard_data: str, force: bool = False):
        try:
            r = self._client.post(f"{self._prefix}/contacts",
                                  json={"vcard_data": vcard_data}, timeout=10)
            if r.status_code in (200, 201):
                data = r.json()
                return data.get("uid"), data.get("operation", "created")
        except Exception:
            pass
        return None, "error"

    def delete(self, uid: str) -> bool:
        try:
            r = self._client.delete(f"{self._prefix}/contacts/{uid}", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def count(self) -> int:
        try:
            h = self._client.get(f"{self._prefix}/health", timeout=5)
            if h.status_code == 200:
                return h.json().get("contacts_count", 0)
        except Exception:
            pass
        return 0

    def get_etag(self, uid: str) -> str | None:
        return None


class _RemoteEventService:
    """EventService 兼容代理 — 通过 REST API 操作事件。"""

    def __init__(self, client: "httpx.Client", prefix: str):
        self._client = client
        self._prefix = prefix

    def get_by_uid(self, uid: str) -> str | None:
        try:
            r = self._client.get(f"{self._prefix}/events/{uid}", timeout=5)
            if r.status_code == 200:
                return r.json().get("ical", "")
        except Exception:
            pass
        return None

    def get_list_data(self) -> list[tuple]:
        return []

    def get_all_raw(self) -> list[str]:
        try:
            r = self._client.get(f"{self._prefix}/events", timeout=10)
            if r.status_code == 200:
                return [c["ical"] for c in r.json() if c.get("ical")]
        except Exception:
            pass
        return []

    def get_all_items(self):
        try:
            r = self._client.get(f"{self._prefix}/events", timeout=10)
            if r.status_code == 200:
                return [(c["uid"], c["ical"]) for c in r.json() if c.get("uid") and c.get("ical")]
        except Exception:
            pass
        return []

    def add_event(self, ical_data: str, force: bool = False):
        try:
            r = self._client.post(f"{self._prefix}/events",
                                  json={"ical_data": ical_data}, timeout=10)
            if r.status_code in (200, 201):
                data = r.json()
                return data.get("uid"), data.get("operation", "created")
        except Exception:
            pass
        return None, "error"

    def delete(self, uid: str) -> bool:
        try:
            r = self._client.delete(f"{self._prefix}/events/{uid}", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def count(self) -> int:
        try:
            h = self._client.get(f"{self._prefix}/health", timeout=5)
            if h.status_code == 200:
                return h.json().get("events_count", 0)
        except Exception:
            pass
        return 0

    def get_etag(self, uid: str) -> str | None:
        return None

    def get_full_ical(self, uid: str, mode: str = "inline", base_url: str = "") -> str | None:
        return self.get_by_uid(uid)


class RemoteBackend(Backend):
    """远程连接 — 通过 httpx 调用 daemon REST API。"""

    def __init__(self, base_url: str = "http://127.0.0.1:8000", token: str = ""):
        import httpx
        self._base_url = base_url.rstrip("/")
        self._token = token
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=self._base_url, headers=headers)
        prefix = f"{self._base_url}/api"
        self._contact = _RemoteContactService(self._client, prefix)
        self._event = _RemoteEventService(self._client, prefix)
        self._settings = _RemoteSettings(self._client, prefix)

    @property
    def contact_service(self) -> "_RemoteContactService":
        return self._contact

    @property
    def event_service(self) -> "_RemoteEventService":
        return self._event

    @property
    def settings_service(self) -> "_RemoteSettings":
        return self._settings

    def health(self) -> dict[str, Any]:
        try:
            r = self._client.get("/api/health", timeout=5)
            if r.status_code == 200:
                return r.json()
        except Exception:
            pass
        return {"status": "error", "version": "", "uptime": 0, "contacts_count": 0, "events_count": 0}

    def close(self):
        self._client.close()
