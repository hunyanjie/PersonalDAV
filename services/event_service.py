import vobject
from datetime import datetime
from database.repositories.event_repository import EventRepository
from models.event import EventModel
from services.base_service import BaseService
from utils.logger import logger
from config import SOFTWARE_NAME, SOFTWARE_VERSION
from utils.event_bus import event_bus, EVENT_EVENTS_CHANGED

class EventService(BaseService):
    """日历事件业务逻辑 - 单例模式"""
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(EventService, cls).__new__(cls)
            cls._instance.__init__(
                repo=EventRepository(),
                changed_event=EVENT_EVENTS_CHANGED,
                raw_field='ical',
                list_fields=['uid', 'summary', 'dtstart', 'dtend', 'created_at', 'updated_at']
            )
        return cls._instance

    def add_event(self, ical_data: str):
        """添加或更新事件"""
        try:
            ical = vobject.readOne(ical_data)
            ev = ical.vevent
            uid = ev.uid.value

            def to_str(val):
                if hasattr(val, 'isoformat'):
                    return val.isoformat()
                return str(val)

            event = EventModel(
                uid=uid,
                summary=ev.summary.value if hasattr(ev, 'summary') else "",
                dtstart=to_str(ev.dtstart.value) if hasattr(ev, 'dtstart') else "",
                dtend=to_str(ev.dtend.value) if hasattr(ev, 'dtend') else "",
                ical=ical_data
            )

            existing = self.repo.get_by_uid(uid)
            operation = "inserted"
            now = datetime.now().isoformat()
            if existing:
                operation = "unchanged" if existing.ical == ical_data else "updated"
                event.created_at = existing.created_at
                event.updated_at = now
            else:
                event.created_at = now
                event.updated_at = now

            if operation != "unchanged":
                self.repo.add_or_update(event)
                event_bus.publish(EVENT_EVENTS_CHANGED)

            return uid, operation
        except Exception as e:
            logger.error(f"Service 添加事件失败: {str(e)}")
            return None, f"Error: {str(e)}"

    def validate_rrule(self, rrule_str: str) -> bool:
        """验证 RRULE 字符串是否合法"""
        if not rrule_str: return True
        try:
            parts = dict(pair.split('=') for pair in rrule_str.split(';') if '=' in pair)
            return 'FREQ' in parts
        except: return False

    def generate_calendar_wrapper(self, vevents_str_list: list) -> str:
        """将 VEVENT 字符串列表包装成完整的 iCalendar 文件"""
        header = f"BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//{SOFTWARE_NAME}//{SOFTWARE_VERSION}//ZH-CN\n"
        events = "".join(vevent.strip() for vevent in vevents_str_list if vevent.strip()).replace("\r\n", "\n")
        return f"{header}{events}END:VCALENDAR\n"
