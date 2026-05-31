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

    def add_event(self, ical_data: str, force: bool = False, publish: bool = True):
        """添加或更新事件。force=True 时即使内容相同也覆盖更新。"""
        try:
            ical = vobject.readOne(ical_data)
            if ical.name == 'VCALENDAR':
                ev = ical.vevent
            elif ical.name == 'VEVENT':
                ev = ical
            else:
                raise ValueError(f"Unexpected component: {ical.name}")
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
                if force:
                    operation = "updated"
                event.created_at = existing.created_at
                event.updated_at = now
            else:
                event.created_at = now
                event.updated_at = now

            if operation != "unchanged":
                self.repo.add_or_update(event)
                if publish:
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
        events = "\n".join(v.strip() for v in vevents_str_list if v.strip()).replace("\r\n", "\n")
        return f"{header}{events}\nEND:VCALENDAR\n"

    def combine_raw_events(self, raw_list: list) -> str:
        """将多个完整 iCalendar 字符串合并为一个（去除重复的 VCALENDAR 包裹）"""
        inner = []
        for e in raw_list:
            lines = e.strip().splitlines()
            lines = [l for l in lines
                     if l.strip() and 'BEGIN:VCALENDAR' not in l
                     and 'END:VCALENDAR' not in l
                     and not l.startswith('VERSION:')
                     and not l.startswith('PRODID:')]
            chunk = '\n'.join(lines)
            if chunk.strip(): inner.append(chunk)
        return self.generate_calendar_wrapper(inner)
