import hashlib
from typing import Any
from utils.event_bus import event_bus

class BaseService:
    _bs_initialized: bool
    repo: Any
    _changed_event: str
    _raw_field: str
    _list_fields: tuple[str, ...]

    def __init__(self, repo: Any = None, changed_event: str | None = None,
                 raw_field: str | None = None, list_fields: tuple[str, ...] | None = None) -> None:
        if getattr(self, '_bs_initialized', False):
            return
        if repo is None:
            return
        self._bs_initialized = True
        self.repo = repo
        self._changed_event = changed_event or ""
        self._raw_field = raw_field or ""
        self._list_fields = list_fields or ()

    def get_by_uid(self, uid: str) -> str | None:
        entity = self.repo.get_by_uid(uid)
        return getattr(entity, self._raw_field) if entity else None

    def get_list_data(self) -> list[tuple[Any, ...]]:
        return [tuple(getattr(c, f) for f in self._list_fields) for c in self.repo.get_all()]

    def get_all_raw(self) -> list[str]:
        return [getattr(c, self._raw_field) for c in self.repo.get_all()]

    def get_all_items(self) -> list[tuple[str, str]]:
        return [(getattr(c, 'uid'), getattr(c, self._raw_field)) for c in self.repo.get_all()]

    def get_selected_raw(self, uids: list[str]) -> list[str]:
        return [getattr(c, self._raw_field) for uid in uids if (c := self.repo.get_by_uid(uid))]

    def delete(self, uid: str) -> bool:
        res = self.repo.delete(uid)
        if res:
            event_bus.publish(self._changed_event)
        return res

    def count(self) -> int:
        return self.repo.count()

    def get_etag(self, uid: str) -> str | None:
        raw = self.get_by_uid(uid)
        if raw is None:
            return None
        return f'"{hashlib.md5(raw.encode("utf-8")).hexdigest()}"'
