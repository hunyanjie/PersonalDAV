from typing import List
from utils.event_bus import event_bus

class BaseService:
    def __init__(self, repo=None, changed_event=None, raw_field=None, list_fields=None):
        if getattr(self, '_bs_initialized', False):
            return
        if repo is None:
            return
        self._bs_initialized = True
        self.repo = repo
        self._changed_event = changed_event
        self._raw_field = raw_field
        self._list_fields = list_fields

    def get_by_uid(self, uid: str) -> str | None:
        entity = self.repo.get_by_uid(uid)
        return getattr(entity, self._raw_field) if entity else None

    def get_list_data(self):
        return [tuple(getattr(c, f) for f in self._list_fields) for c in self.repo.get_all()]

    def get_all_raw(self):
        return [getattr(c, self._raw_field) for c in self.repo.get_all()]

    def get_selected_raw(self, uids: list):
        return [getattr(c, self._raw_field) for uid in uids if (c := self.repo.get_by_uid(uid))]

    def delete(self, uid: str):
        res = self.repo.delete(uid)
        if res:
            event_bus.publish(self._changed_event)
        return res

    def count(self) -> int:
        return self.repo.count()
