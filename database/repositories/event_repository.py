from typing import Optional, List
from database.repositories.base import BaseRepository
from models.event import EventModel

class EventRepository(BaseRepository[EventModel]):
    SEARCH_COLUMNS = ['summary']

    def search_by_keyword(self, keyword: str, limit: int = 20) -> list[EventModel]:
        return self.search(self.SEARCH_COLUMNS, keyword, limit)

    def search_by_date_range(self, start: str, end: str) -> list[EventModel]:
        return super().search_by_date_range('dtstart', 'dtend', start, end)

    def __init__(self):
        super().__init__(
            table='events',
            model_cls=EventModel,
            columns=['uid', 'summary', 'dtstart', 'dtend', 'ical', 'id', 'created_at', 'updated_at'],
            insert_columns=['uid', 'summary', 'dtstart', 'dtend', 'ical', 'created_at', 'updated_at']
        )
