import pytz
import locale
from babel import Locale
import babel.dates
from datetime import datetime
from utils.logger import logger

class TimezoneHelper:
    """时区助手 - 处理时区本地化"""

    @staticmethod
    def get_localized_timezones():
        """获取带偏移量的本地化时区列表"""
        try:
            sys_locale = locale.getdefaultlocale()[0]
            loc = Locale.parse(sys_locale) if sys_locale else Locale.parse('zh_CN')

            now = datetime.utcnow()
            local_tz_id = TimezoneHelper.get_local_timezone_id()
            tz_list = []

            for tz_id in pytz.common_timezones:
                try:
                    tz = pytz.timezone(tz_id)
                    offset = tz.utcoffset(now)
                    total_seconds = offset.total_seconds()
                    hours = int(total_seconds // 3600)
                    minutes = int((total_seconds % 3600) // 60)
                    sign = '+' if hours >= 0 else '-'
                    offset_str = f"UTC{sign}{abs(hours):02d}:{minutes:02d}"

                    city_name = tz_id.split('/')[-1].replace('_', ' ') if '/' in tz_id else tz_id
                    try:
                        localized_name = babel.dates.get_timezone_name(tz_id, locale=loc)
                    except:
                        localized_name = tz_id

                    display = f"{offset_str} - {city_name} ({tz_id}) {localized_name}"
                    if tz_id == local_tz_id:
                        display = f"{display} [本地]"
                    tz_list.append(display)
                except:
                    tz_list.append(tz_id)

            # 按偏移量排序
            tz_list.sort()
            return tz_list
        except Exception as e:
            logger.error(f"获取本地化时区失败: {str(e)}")
            return sorted(pytz.all_timezones)

    @staticmethod
    def get_local_timezone_id():
        """获取本地时区ID"""
        try:
            from tzlocal import get_localzone
            return str(get_localzone())
        except:
            return 'Asia/Shanghai' # 默认中国时区

    @staticmethod
    def get_timezone_display_name(tz_id: str):
        """根据时区ID获取完整的显示名称，用于回显匹配"""
        try:
            sys_locale = locale.getdefaultlocale()[0]
            loc = Locale.parse(sys_locale) if sys_locale else Locale.parse('zh_CN')
            
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
            except:
                localized_name = tz_id

            display = f"{offset_str} - {city_name} ({tz_id}) {localized_name}"
            if tz_id == TimezoneHelper.get_local_timezone_id():
                display += " [本地]"
            return display
        except:
            return tz_id

    @staticmethod
    def extract_tz_id(localized_name: str) -> str:
        """从 'UTC+08:00 - Shanghai (Asia/Shanghai) 中国标准时间' 中提取 'Asia/Shanghai'"""
        # 格式: "UTC+08:00 - Shanghai (Asia/Shanghai) 本地化名称 [本地]"
        if '(' in localized_name and ')' in localized_name:
            start = localized_name.rfind('(') + 1
            end = localized_name.rfind(')')
            tz_id = localized_name[start:end]
            # 排除括号内的 UTC 偏移量
            if not tz_id.startswith('UTC'):
                return tz_id
        return localized_name
