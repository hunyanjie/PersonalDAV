import vobject
from database.repositories.event_repository import EventRepository
from models.event import EventModel
from utils.logger import logger
from config import SOFTWARE_NAME, SOFTWARE_VERSION
from utils.event_bus import event_bus, EVENT_EVENTS_CHANGED

class EventService:
    """日历事件业务逻辑 - 引入 Repository 模式、事件总线"""
    def __init__(self):
        self.repo = EventRepository()

    def add_event(self, ical_data: str):
        """添加或更新事件"""
        try:
            ical = vobject.readOne(ical_data)
            ev = ical.vevent
            uid = ev.uid.value
            
            event = EventModel(
                uid=uid,
                summary=ev.summary.value if hasattr(ev, 'summary') else "",
                dtstart=str(ev.dtstart.value) if hasattr(ev, 'dtstart') else "",
                dtend=str(ev.dtend.value) if hasattr(ev, 'dtend') else "",
                ical=ical_data
            )

            existing = self.repo.get_by_uid(uid)
            operation = "inserted"
            if existing:
                operation = "unchanged" if existing.ical == ical_data else "updated"

            if operation != "unchanged":
                self.repo.add_or_update(event)
                event_bus.publish(EVENT_EVENTS_CHANGED)

            return uid, operation
        except Exception as e:
            logger.error(f"Service 添加事件失败: {str(e)}")
            return None, f"Error: {str(e)}"

    def get_event(self, uid: str):
        event = self.repo.get_by_uid(uid)
        return event.ical if event else None

    def get_events_list(self):
        """返回元组列表以兼容 Treeview"""
        return [(e.uid, e.summary, e.dtstart, e.dtend) for e in self.repo.get_all()]

    def get_all_ical_events(self):
        return [e.ical for e in self.repo.get_all()]

    def get_selected_ical_events(self, uids: list):
        return [e.ical for uid in uids if (e := self.repo.get_by_uid(uid))]

    def delete_event(self, uid: str):
        return self.repo.delete(uid)

    def validate_rrule(self, rrule_str: str) -> bool:
        """验证 RRULE 字符串是否合法"""
        if not rrule_str: return True
        try:
            parts = dict(pair.split('=') for pair in rrule_str.split(';') if '=' in pair)
            return 'FREQ' in parts
        except: return False

    def generate_calendar_wrapper(self, vevents_str_list: list) -> str:
        header = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            f"PRODID:-//{SOFTWARE_NAME}//{SOFTWARE_VERSION}ZH-CN"
        ]
        return "\n".join(header + vevents_str_list + ["END:VCALENDAR"])
