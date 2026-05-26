from dataclasses import dataclass
from typing import Optional

@dataclass
class EventModel:
    """日历事件强类型数据模型"""
    uid: str
    summary: str
    dtstart: str
    dtend: str
    ical: str = ""
    id: Optional[int] = None

    def to_dict(self):
        return {
            "id": self.id,
            "uid": self.uid,
            "summary": self.summary,
            "dtstart": self.dtstart,
            "dtend": self.dtend,
            "ical": self.ical
        }
