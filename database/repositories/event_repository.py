from typing import Optional, List
from database.repositories.base import BaseRepository
from models.event import EventModel

class EventRepository(BaseRepository[EventModel]):
    def __init__(self):
        super().__init__(
            table='events',
            model_cls=EventModel,
            columns=['uid', 'summary', 'dtstart', 'dtend', 'ical', 'id', 'created_at', 'updated_at'],
            insert_columns=['uid', 'summary', 'dtstart', 'dtend', 'ical', 'created_at', 'updated_at']
        )
