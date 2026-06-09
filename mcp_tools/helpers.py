import json
from typing import Any

from services.settings_service import SettingsService
from mcp_tools._state import get_contact_svc, get_event_svc
from utils.logger import logger


def safe_json(data) -> str:
    try:
        return json.dumps(data, ensure_ascii=False)
    except Exception as e:
        logger.exception("JSON 序列化失败")
        return json.dumps({"error": f"serialization failed: {e}"}, ensure_ascii=False)


def check_readonly() -> bool:
    return SettingsService().get_setting("mcp_readonly", "False") == "True"


_SAFETY_MODE_CACHE: dict[str, str] = {}


def check_safety(action: str, confirmed: bool = False) -> str | None:
    """Returns error string if blocked, None if allowed."""
    mode = _SAFETY_MODE_CACHE.get("mcp_safety_mode")
    if mode is None:
        mode = SettingsService().get_setting("mcp_safety_mode", "confirm")
        _SAFETY_MODE_CACHE["mcp_safety_mode"] = mode
    if mode == "allow":
        return None
    if mode == "safe":
        return f"安全模式(safe): {action} 操作已被禁止。请在设置中更改为 confirm 或 allow 模式。"
    if not confirmed:
        return f"确认要求(confirm): {action} 操作需要 confirmed=true 参数才能执行。"
    return None


def make_contact_summary(uid: str) -> dict[str, Any]:
    raw = get_contact_svc().get_by_uid(uid)
    if not raw:
        return {"uid": uid, "error": "not found"}
    try:
        import vobject
        v = vobject.readOne(raw)
        fn = v.fn.value if hasattr(v, 'fn') else ""
        emails = [e.value for e in v.email_list] if hasattr(v, 'email_list') else []
        phones = [t.value for t in v.tel_list] if hasattr(v, 'tel_list') else []
        return {"uid": uid, "full_name": fn, "emails": emails, "phones": phones}
    except Exception:
        return {"uid": uid, "detail": "(parse failed)"}


def make_event_summary(uid: str) -> dict[str, Any]:
    raw = get_event_svc().get_by_uid(uid)
    if not raw:
        return {"uid": uid, "error": "not found"}
    try:
        import vobject
        cal = vobject.readOne(raw)
        ev = cal.vevent if cal.name == 'VCALENDAR' else cal
        summary = ev.summary.value if hasattr(ev, 'summary') else ""
        dtstart = str(ev.dtstart.value) if hasattr(ev, 'dtstart') else ""
        dtend = str(ev.dtend.value) if hasattr(ev, 'dtend') else ""
        return {"uid": uid, "summary": summary, "dtstart": dtstart, "dtend": dtend}
    except Exception:
        return {"uid": uid, "detail": "(parse failed)"}
