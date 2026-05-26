import pytz
import locale
from babel import Locale
import babel.dates
from utils.logger import logger

class TimezoneHelper:
    """时区助手 - 处理时区本地化"""
    
    @staticmethod
    def get_localized_timezones():
        """获取常用时区的本地化列表"""
        try:
            # 获取当前系统的语言设置
            sys_locale = locale.getdefaultlocale()[0]
            loc = Locale.parse(sys_locale) if sys_locale else Locale.parse('zh_CN')
            
            # 使用 common_timezones 过滤掉一些极罕见的
            tz_list = []
            for tz_id in pytz.common_timezones:
                try:
                    name = babel.dates.get_timezone_name(tz_id, locale=loc)
                    tz_list.append(f"{tz_id} ({name})")
                except:
                    tz_list.append(tz_id)
            
            # 排序：将常用的放在前面或按字母排序
            return sorted(tz_list)
        except Exception as e:
            logger.error(f"获取本地化时区失败: {str(e)}")
            return sorted(pytz.all_timezones)

    @staticmethod
    def extract_tz_id(localized_name: str) -> str:
        """从 'Asia/Shanghai (中国标准时间)' 中提取 'Asia/Shanghai'"""
        if " (" in localized_name:
            return localized_name.split(" (")[0]
        return localized_name
