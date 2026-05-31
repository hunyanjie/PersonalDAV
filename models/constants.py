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
