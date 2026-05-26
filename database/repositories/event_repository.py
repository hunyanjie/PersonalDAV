from database.db_manager import Database
from models.event import EventModel
from typing import List, Optional

class EventRepository:
    """日历事件数据访问层"""
    def __init__(self):
        self.db = Database()

    def add_or_update(self, event: EventModel) -> bool:
        with self.db.transaction() as cursor:
            cursor.execute(
                '''INSERT OR REPLACE INTO events (uid, summary, dtstart, dtend, ical) 
                   VALUES (?, ?, ?, ?, ?)''',
                (event.uid, event.summary, event.dtstart, event.dtend, event.ical)
            )
        return True

    def get_by_uid(self, uid: str) -> Optional[EventModel]:
        row = self.db.query_one("SELECT uid, summary, dtstart, dtend, ical, id FROM events WHERE uid=?", (uid,))
        if row:
            return EventModel(uid=row[0], summary=row[1], dtstart=row[2], dtend=row[3], ical=row[4], id=row[5])
        return None

    def get_all(self) -> List[EventModel]:
        rows = self.db.query("SELECT uid, summary, dtstart, dtend, ical, id FROM events")
        return [EventModel(uid=r[0], summary=r[1], dtstart=r[2], dtend=r[3], ical=r[4], id=r[5]) for r in rows]

    def delete(self, uid: str) -> bool:
        with self.db.transaction() as cursor:
            cursor.execute("DELETE FROM events WHERE uid=?", (uid,))
        return True
