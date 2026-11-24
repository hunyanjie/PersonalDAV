from typing import Optional, List
from database.repositories.base import BaseRepository
from models.event import EventModel

class EventRepository(BaseRepository[EventModel]):
    # 必须与 events_fts 的索引列保持一致；description/location 包含在 ical 原文中。
    SEARCH_COLUMNS = ['summary', 'ical']

    def search_by_keyword(self, keyword: str, limit: int = 20) -> list[EventModel]:
        return self.search(self.SEARCH_COLUMNS, keyword, limit)

    def search_by_date_range(self, start: str, end: str) -> list[EventModel]:
        return super().search_by_date_range('dtstart', 'dtend', start, end)

    def get_by_dtstart_range(self, start: str, end: str) -> list[EventModel]:
        rows = self.db.query(
            f"SELECT {self._col_str} FROM {self.table} WHERE dtstart >= ? AND dtstart < ? ORDER BY dtstart",
            (start, end)
        )
        return [self._to_model(row) for row in rows]

    def __init__(self):
        super().__init__(
            table='events',
            model_cls=EventModel,
            columns=['uid', 'summary', 'dtstart', 'dtend', 'ical', 'id', 'created_at', 'updated_at'],
            insert_columns=['uid', 'summary', 'dtstart', 'dtend', 'ical', 'created_at', 'updated_at']
        )
