from datetime import timedelta

STANDARD_VCARD_FIELDS = [
    'UID', 'FN', 'N', 'EMAIL', 'TEL', 'VERSION', 'PHOTO',
    'BDAY', 'NOTE', 'ORG', 'TITLE', 'URL', 'ADR'
]

STANDARD_ICAL_FIELDS = [
    'UID', 'SUMMARY', 'LOCATION', 'DESCRIPTION', 'STATUS',
    'DTSTART', 'DTEND', 'RRULE', 'VALARM', 'CATEGORIES',
    'PRIORITY', 'TRANSP', 'ORGANIZER', 'SEQUENCE', 'URL',
    'ATTENDEE', 'VERSION', 'PRODID', 'X-ALLDAY', 'CREATED',
    'DTSTAMP', 'LAST-MODIFIED', 'COMPLETED', 'DUE',
    'EXDATE', 'RDATE', 'EXRULE', 'DURATION', 'RECURRENCE-ID',
    'ATTACH', 'CLASS', 'GEO', 'COMMENT', 'CONTACT',
    'REQUEST-STATUS', 'RELATED-TO', 'RESOURCES',
    'X-FORCE-REMINDER', 'X-SYNC-TZ'
]

# ── 事件对话框共享映射 ──────────────────────────────────────────

STATUS_MAPPING = {"待定": "TENTATIVE", "已确认": "CONFIRMED", "已取消": "CANCELLED"}
STATUS_REV_MAPPING = {v: k for k, v in STATUS_MAPPING.items()}
TRANSPARENCY_MAPPING = {"忙碌": "OPAQUE", "空闲": "TRANSPARENT"}
REPEAT_OPTIONS = ["不重复", "每天", "每周", "每两周", "每月", "每年", "自定义"]
WEEKDAYS = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
WEEKDAYS_RRULE = ["MO", "TU", "WE", "TH", "FR", "SA", "SU"]
END_CONDITIONS = ["永不结束", "按日期结束", "按次数结束"]

# ── 提醒/闹钟映射 ──────────────────────────────────────────

ALARM_ACTION_MAPPING = {"显示": "DISPLAY", "声音": "AUDIO", "邮件": "EMAIL"}
ALARM_ACTION_REV_MAPPING = {"DISPLAY": "显示", "AUDIO": "声音", "EMAIL": "邮件"}

TRANSPARENCY_REV_MAPPING = {"OPAQUE": "忙碌", "TRANSPARENT": "空闲"}

DURATION_QUICK_OPTIONS = ["30分钟", "1小时", "2小时", "半天", "全天"]

FREQ_MAPPING = {"每天": "DAILY", "每周": "WEEKLY", "每两周": "WEEKLY;INTERVAL=2", "每月": "MONTHLY", "每年": "YEARLY"}

PRESET_REMINDERS_DEFAULT = ["5分钟前", "15分钟前", "30分钟前", "1小时前", "2小时前", "1天前"]
PRESET_ALLDAY_REMINDERS_DEFAULT = ["日程发生时", "1天前", "2天前", "7天前"]

# ── 提醒字符串 ←→ timedelta 映射 ─────────────────────────

REMINDER_STRING_MAPPING = {
    "日程发生时": timedelta(0), "发生时": timedelta(0),
    "5分钟前": timedelta(minutes=-5), "15分钟前": timedelta(minutes=-15),
    "30分钟前": timedelta(minutes=-30), "1小时前": timedelta(hours=-1),
    "2小时前": timedelta(hours=-2), "1天前": timedelta(days=-1),
    "2天前": timedelta(days=-2), "7天前": timedelta(days=-7),
    "当天上午9点": timedelta(hours=9), "1天前上午9点": timedelta(days=-1, hours=9),
    "2天前上午9点": timedelta(days=-2, hours=9), "3天前上午9点": timedelta(days=-3, hours=9),
    "5天前上午9点": timedelta(days=-5, hours=9), "7天前上午9点": timedelta(days=-7, hours=9)
}
