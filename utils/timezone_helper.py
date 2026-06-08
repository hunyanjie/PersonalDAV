import pytz
import locale
from babel import Locale
import babel.dates
from datetime import datetime
from utils.logger import logger


class TimezoneHelper:
    """时区助手 - 支持自定义显示格式"""

    _display_to_tz: dict = {}
    _tz_to_display: dict = {}
    _format: str = "{offset} - {city} ({tz_id}) {localized}{local_tag}"

    @classmethod
    def set_format(cls, fmt: str):
        cls._format = fmt
        cls._display_to_tz = {}
        cls._tz_to_display = {}

    @classmethod
    def _build_sys_locale(cls):
        try:
            sys_locale = locale.getdefaultlocale()[0]
            return Locale.parse(sys_locale) if sys_locale else Locale.parse('zh_CN')
        except Exception:
            return Locale.parse('zh_CN')

    @classmethod
    def _format_one(cls, tz_id: str, fmt: str, local_tz_id: str, loc) -> str:
        try:
            tz = pytz.timezone(tz_id)
            now = datetime.utcnow()
            offset = tz.utcoffset(now)
            total_seconds = offset.total_seconds()
            hours = int(total_seconds // 3600)
            minutes = int((total_seconds % 3600) // 60)
            sign = '+' if hours >= 0 else '-'
            offset_str = f"UTC{sign}{abs(hours):02d}:{minutes:02d}"

            city_name = tz_id.split('/')[-1].replace('_', ' ') if '/' in tz_id else tz_id
            try:
                localized_name = babel.dates.get_timezone_name(tz_id, locale=loc)
            except Exception:
                localized_name = tz_id

            local_tag = " [本地]" if tz_id == local_tz_id else ""

            return fmt.format(offset=offset_str, city=city_name, tz_id=tz_id,
                              localized=localized_name, local_tag=local_tag)
        except Exception:
            return tz_id

    @classmethod
    def get_localized_timezones(cls, fmt: str = None):
        """获取格式化的时区列表, 按偏移量排序"""
        fmt = fmt or cls._format
        try:
            loc = cls._build_sys_locale()
            now = datetime.utcnow()
            local_tz_id = cls.get_local_timezone_id()
            items = []
            cls._display_to_tz = {}
            cls._tz_to_display = {}

            for tz_id in pytz.common_timezones:
                display = cls._format_one(tz_id, fmt, local_tz_id, loc)
                if display != tz_id:
                    cls._display_to_tz[display] = tz_id
                    cls._tz_to_display[tz_id] = display
                items.append(display)

            items.sort()
            return items
        except Exception as e:
            logger.error(f"获取本地化时区失败: {str(e)}")
            return sorted(pytz.all_timezones)

    @classmethod
    def get_local_timezone_id(cls) -> str:
        try:
            from tzlocal import get_localzone
            return str(get_localzone())
        except Exception:
            return 'Asia/Shanghai'

    @classmethod
    def get_timezone_display_name(cls, tz_id: str) -> str:
        if tz_id in cls._tz_to_display:
            return cls._tz_to_display[tz_id]
        try:
            return cls._format_one(tz_id, cls._format, cls.get_local_timezone_id(), cls._build_sys_locale())
        except Exception:
            return tz_id

    @classmethod
    def extract_tz_id(cls, display: str) -> str:
        if display in cls._display_to_tz:
            return cls._display_to_tz[display]
        if '(' in display and ')' in display:
            start = display.rfind('(') + 1
            end = display.rfind(')')
            tz_id = display[start:end]
            if not tz_id.startswith('UTC'):
                return tz_id
        return display
