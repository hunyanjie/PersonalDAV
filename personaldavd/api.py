"""REST API router — CRUD for contacts, events, system."""

import time, os, shutil, uuid, logging, re
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from config import SOFTWARE_VERSION, SOFTWARE_NAME
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from services.auth_service import AuthService
from services.embeddings import EmbeddingService
from .models import (
    ContactOut, ContactCreate, ContactUpdate,
    EventOut, EventCreate, EventUpdate, HealthOut, AuthTokenOut, AuthTokenRequest,
    ServerConfigOut, AuthLogOut, StatsOut, ErrorOut, SystemLogOut,
)
from .auth import get_current_token
from .logging import LOG_QUEUE
import vobject

api_router = APIRouter(tags=["API 接口"])
_start_time = time.time()
_logger = logging.getLogger("api")


def _vcard_to_contact_out(raw: str) -> ContactOut | None:
    """Convert a vCard string to ContactOut."""
    try:
        uid = full_name = email = phone = groups = address = org = note = photo = ""
        for line in raw.splitlines():
            ul = line.upper()
            if ul.startswith("UID:"):
                uid = line[4:].strip()
            elif ul.startswith("FN:"):
                full_name = line[3:].strip()
            elif ul.startswith("EMAIL"):
                email = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("TEL"):
                phone = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("CATEGORIES"):
                groups = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("ADR"):
                address = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("ORG"):
                org = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("NOTE"):
                note = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("PHOTO"):
                photo = line.split(":", 1)[-1].strip() if ":" in line else ""
        if not uid:
            _logger.error("_vcard_to_contact_out: vCard 缺少 UID 行，无法解析:\n%s", raw[:300])
            return None
        return ContactOut(uid=uid, full_name=full_name, email=email, phone=phone,
                          groups=groups, address=address, org=org, note=note, photo=photo, vcard=raw)
    except Exception as e:
        _logger.error("_vcard_to_contact_out 异常: %s\n原始数据(前300字符): %s", e, raw[:300])
        return None


def _ical_to_event_out(raw: str) -> EventOut | None:
    """Convert an iCal string to EventOut."""
    try:
        uid = summary = dtstart = dtend = description = location = categories = rrule = ""
        all_day = False
        reminders = []
        attachments = []
        in_valarm = False
        current_alarm = {}
        for line in raw.splitlines():
            ul = line.strip().upper()
            if ul == "BEGIN:VALARM":
                in_valarm = True
                current_alarm = {}
                continue
            if ul == "END:VALARM":
                if current_alarm:
                    reminders.append(current_alarm)
                in_valarm = False
                continue
            if in_valarm:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip().upper()
                    current_alarm[k] = v.strip()
                continue
            if ul.startswith("UID:"):
                uid = line.split(":", 1)[-1].strip()
            elif ul.startswith("SUMMARY"):
                summary = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("DTSTART"):
                dtstart = line.split(":", 1)[-1].strip() if ":" in line else ""
                if len(dtstart) <= 8:
                    all_day = True
            elif ul.startswith("DTEND"):
                dtend = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("DESCRIPTION") and not description:
                description = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("LOCATION"):
                location = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("CATEGORIES"):
                categories = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("RRULE"):
                rrule = line.split(":", 1)[-1].strip() if ":" in line else ""
            elif ul.startswith("ATTACH"):
                rest = line.split(":", 1)[-1].strip() if ":" in line else ""
                attachments.append({"raw": rest})
        if not uid:
            _logger.error("_ical_to_event_out: iCal 缺少 UID 行:\n%s", raw[:300])
            return None
        return EventOut(uid=uid, summary=summary, dtstart=dtstart, dtend=dtend,
                        all_day=all_day, description=description, location=location,
                        categories=categories, rrule=rrule, reminders=reminders,
                        attachments=attachments, ical=raw)
    except Exception as e:
        _logger.error("_ical_to_event_out 异常: %s\n原始数据(前300字符): %s", e, raw[:300])
        return None


def _escape_ical_val(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def _format_ical_dt(v: str, all_day: bool = False) -> str:
    """Format a datetime string to iCal format (YYYYMMDD or YYYYMMDDTHHMMSS)."""
    if not v:
        return ""
    s = v.replace("-", "").replace(":", "").replace("T", "")
    if all_day:
        return s[:8]
    if "T" in v or len(s) > 8:
        if len(s) == 10:  # YYYYMMDDHH → YYYYMMDDTHHMMSS
            s = s[:8] + "T" + s[8:] + "00"
        elif len(s) == 12:  # YYYYMMDDHHMM → YYYYMMDDTHHMMSS
            s = s[:8] + "T" + s[8:12] + "00"
        elif len(s) == 14 and not s[8:9] == "T":
            s = s[:8] + "T" + s[8:14]
    return s


def _event_fields_to_ical(fields: EventCreate | EventUpdate, uid: str = "") -> str:
    """Build iCalendar string from structured event fields."""
    ical = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV\r\nBEGIN:VEVENT\r\n"
    if uid:
        ical += f"UID:{uid}\r\n"
    else:
        ical += f"UID:{int(__import__('time').time() * 1000)}@personaldav\r\n"
        ical += "STATUS:CONFIRMED\r\n"

    all_day = getattr(fields, 'all_day', False)
    ds = fields.dtstart if fields.dtstart else ""
    de = fields.dtend if fields.dtend else ""
    if all_day and de:
        try:
            import datetime
            d = datetime.date(int(de[:4]), int(de[5:7]), int(de[7:9]))
            d += datetime.timedelta(days=1)
            de = d.strftime("%Y-%m-%d")
        except Exception:
            pass
    ical += f"DTSTART:{_format_ical_dt(ds, all_day)}\r\n"
    ical += f"DTEND:{_format_ical_dt(de, all_day)}\r\n"
    ical += f"SUMMARY:{_escape_ical_val(fields.summary or '')}\r\n"
    if fields.description:
        ical += f"DESCRIPTION:{_escape_ical_val(fields.description)}\r\n"
    if fields.location:
        ical += f"LOCATION:{_escape_ical_val(fields.location)}\r\n"
    if fields.categories:
        ical += f"CATEGORIES:{_escape_ical_val(fields.categories)}\r\n"
    if fields.rrule:
        ical += f"RRULE:{fields.rrule}\r\n"
    for r in (fields.reminders or []):
        action = r.get("ACTION") or r.get("action") or "DISPLAY"
        trigger = r.get("TRIGGER") or r.get("trigger") or ""
        if not trigger and "trigger_type" in r:
            tv = int(r.get("trigger_value", 15))
            tt = r.get("trigger_type", "before")
            if tt == "after":
                trigger = f"PT{tv}M"
            else:
                d = tv // 1440
                h = (tv % 1440) // 60
                m = tv % 60
                trigger = "-P" + (f"{d}D" if d else "") + ("T" if (h or m) else "") + (f"{h}H" if h else "") + (f"{m}M" if m else "")
                if not d and not h and not m:
                    trigger = "-PT0M"
        if trigger:
            ical += "BEGIN:VALARM\r\n"
            ical += f"ACTION:{action}\r\n"
            ical += f"TRIGGER:{trigger}\r\n"
            ical += "END:VALARM\r\n"
    for a in (fields.attachments or []):
        url = a.get("url") or a.get("raw") or ""
        name = a.get("name", "attachment.bin")
        if url.startswith("data:"):
            _, b64 = url.split(",", 1)
            mime = "application/octet-stream"
            import re as _re
            m = _re.search(r":(.*?);", url)
            if m:
                mime = m.group(1)
            ical += f"ATTACH;VALUE=BINARY;ENCODING=BASE64;FMTTYPE={mime};FILENAME={_escape_ical_val(name)}:{b64}\r\n"
        elif url:
            ical += f"ATTACH:{url}\r\n"
    ical += "END:VEVENT\r\nEND:VCALENDAR\r\n"
    return ical


# ── Health ──────────────────────────────────────────────────────

@api_router.get("/health", response_model=HealthOut, summary="服务器健康检查")
async def health():
    """返回服务器运行状态、版本号、运行时长、联系人/事件数量。"""
    svc = SettingsService()
    cs = ContactService()
    es = EventService()
    return HealthOut(
        status="ok", version=SOFTWARE_VERSION,
        uptime=time.time() - _start_time,
        contacts_count=cs.count(),
        events_count=es.count(),
    )


# ── Auth / Token ────────────────────────────────────────────────

@api_router.post("/auth/token", response_model=AuthTokenOut, summary="获取访问令牌")
async def get_token(body: AuthTokenRequest, request: Request):
    """用管理员密码换取 Bearer Token，后续请求携带此令牌即可通过鉴权。"""
    svc = AuthService()
    client_ip = request.client.host if request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "")
    fp = body.fingerprint

    # 浏览器指纹检查
    if fp and not svc.check_fingerprint(fp):
        svc.log_auth(False, client_ip, "WebUI", "浏览器指纹被拒绝", user_agent=ua, fingerprint=fp)
        raise HTTPException(403, "浏览器指纹被拒绝")

    # IP 本机免密或未设密码时直接放行
    if svc.ip_bypasses_auth(client_ip) or not svc.is_password_required():
        token = svc.get_mcp_token()
        svc.log_auth(True, client_ip, "WebUI", "IP 免密放行", user_agent=ua, fingerprint=fp)
        return AuthTokenOut(token=token, scopes=body.scopes)

    if not svc.verify_password(body.password):
        svc.log_auth(False, client_ip, "WebUI", "密码错误", user_agent=ua, fingerprint=fp)
        raise HTTPException(401, "密码错误")
    token = svc.get_mcp_token()
    if not token:
        svc.log_auth(False, client_ip, "WebUI", "未设置密码无法生成令牌", user_agent=ua, fingerprint=fp)
        raise HTTPException(403, "未设置密码，无法生成令牌")
    svc.log_auth(True, client_ip, "WebUI", "密码登录成功", user_agent=ua, fingerprint=fp)
    return AuthTokenOut(token=token, scopes=body.scopes)


# ── Contacts ────────────────────────────────────────────────────

def _contact_fields_to_vcard(fields: ContactCreate | ContactUpdate, uid: str = "") -> str:
    """Build vCard string from structured contact fields."""
    vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\n"
    if uid:
        vcard += f"UID:{uid}\r\n"
    vcard += f"FN:{fields.full_name}\r\nN:{fields.full_name};;;\r\n"
    if fields.email:
        vcard += f"EMAIL:{fields.email}\r\n"
    if fields.phone:
        vcard += f"TEL:{fields.phone}\r\n"
    if fields.groups:
        vcard += f"CATEGORIES:{fields.groups}\r\n"
    if fields.address:
        vcard += f"ADR:{fields.address}\r\n"
    if fields.org:
        vcard += f"ORG:{fields.org}\r\n"
    if fields.note:
        vcard += f"NOTE:{fields.note}\r\n"
    if fields.photo:
        vcard += f"PHOTO;ENCODING=BASE64;TYPE=JPEG:{fields.photo}\r\n"
    vcard += "END:VCARD\r\n"
    return vcard


def _is_contact_field_set(v: str | None) -> bool:
    return v is not None and v != ""


@api_router.get("/contacts", summary="列出所有联系人")
async def list_contacts(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    token: str = Depends(get_current_token),
):
    """返回联系人的摘要列表（姓名、邮箱、电话、分组），支持分页。"""
    svc = ContactService()
    raw_list, total = svc.get_all_raw_paginated(offset, limit)
    items = [o for r in raw_list if (o := _vcard_to_contact_out(r))]
    return {"items": items, "total": total}


# ── Contacts Search (MUST be before {uid} routes) ───────────

@api_router.get("/contacts/search", summary="搜索联系人")
async def search_contacts(
    q: str = Query("", description="关键词"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    token: str = Depends(get_current_token),
):
    svc = EmbeddingService()
    all_results = svc.search_contacts(q, top_k=100000)
    total = len(all_results)
    items = all_results[offset:offset + limit]
    return {"items": items, "total": total}


# ── Events Search (MUST be before {uid} routes) ─────────────

@api_router.get("/events/search", summary="搜索事件")
async def search_events(
    q: str = Query("", description="关键词"),
    date_from: str = Query("", description="起始时间"),
    date_to: str = Query("", description="结束时间"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    token: str = Depends(get_current_token),
):
    svc = EmbeddingService()
    all_results = svc.search_events(q, date_from=date_from, date_to=date_to, top_k=100000)
    total = len(all_results)
    items = all_results[offset:offset + limit]
    return {"items": items, "total": total}


@api_router.get("/contacts/{uid}", response_model=ContactOut, summary="获取单个联系人")
async def get_contact(uid: str, token: str = Depends(get_current_token)):
    """根据 UID 获取联系人的完整 vCard 数据。"""
    svc = ContactService()
    raw = svc.get_by_uid(uid)
    if not raw:
        _logger.warning("get_contact: UID=%s 不存在", uid)
        raise HTTPException(404, "联系人不存在")
    out = _vcard_to_contact_out(raw)
    if not out:
        _logger.error("get_contact: UID=%s 解析失败, raw前300字符:\n%s", uid, raw[:300])
        raise HTTPException(500, f"解析联系人失败 (UID={uid})")
    return out


@api_router.post("/contacts", response_model=dict, summary="创建联系人")
async def create_contact(body: ContactCreate, token: str = Depends(get_current_token)):
    """通过结构化字段创建联系人，后端自动构建 vCard。"""
    vcard = _contact_fields_to_vcard(body)
    svc = ContactService()
    uid, op = svc.add_contact(vcard)
    if uid is None:
        raise HTTPException(400, f"创建联系人失败: {op}")
    return {"uid": uid, "operation": op}


@api_router.post("/contacts/import", response_model=dict, summary="从 vCard 导入联系人")
async def import_contact(body: dict, token: str = Depends(get_current_token)):
    """传入完整的 vCard 文本创建联系人（用于 .vcf 文件导入）。支持多联系人 VCF。"""
    vcard_data = body.get("vcard_data", "")
    if not vcard_data:
        raise HTTPException(400, "缺少 vcard_data")
    svc = ContactService()
    # 支持多联系人 VCF
    vcards = re.split(r'(?=BEGIN:VCARD)', vcard_data)
    vcards = [v.strip() for v in vcards if v.strip()]
    if len(vcards) > 1:
        results = []
        for v in vcards:
            uid, op = svc.add_contact(v)
            if uid:
                results.append({"uid": uid, "operation": op})
        return {"results": results, "count": len(results)}
    uid, op = svc.add_contact(vcard_data)
    if uid is None:
        raise HTTPException(400, f"导入联系人失败: {op}")
    return {"uid": uid, "operation": op, "count": 1}


@api_router.put("/contacts/{uid}", response_model=dict, summary="更新联系人")
async def update_contact(uid: str, body: ContactUpdate, token: str = Depends(get_current_token)):
    """通过结构化字段更新联系人，后端自动构建 vCard。"""
    svc = ContactService()
    try:
        existing = svc.get_by_uid(uid)
        if not existing:
            raise HTTPException(404, "联系人不存在")
        out = _vcard_to_contact_out(existing)
        merged = ContactCreate(
            full_name=body.full_name if _is_contact_field_set(body.full_name) else (out.full_name if out else ""),
            email=body.email if _is_contact_field_set(body.email) else (out.email if out else ""),
            phone=body.phone if _is_contact_field_set(body.phone) else (out.phone if out else ""),
            groups=body.groups if _is_contact_field_set(body.groups) else (out.groups if out else ""),
            address=body.address if _is_contact_field_set(body.address) else (out.address if out else ""),
            org=body.org if _is_contact_field_set(body.org) else (out.org if out else ""),
            note=body.note if _is_contact_field_set(body.note) else (out.note if out else ""),
            photo=body.photo if _is_contact_field_set(body.photo) else (out.photo if out else ""),
        )
        vcard = _contact_fields_to_vcard(merged, uid=uid)
        new_uid, op = svc.add_contact(vcard, force=True)
        if new_uid is None:
            _logger.error("update_contact uid=%s 失败: %s", uid, op)
            raise HTTPException(400, f"更新联系人失败: {op}")
        return {"uid": new_uid, "operation": op}
    except HTTPException:
        raise
    except Exception as e:
        _logger.error("update_contact uid=%s 异常: %s", uid, e)
        raise HTTPException(500, f"更新联系人异常: {e}")


@api_router.delete("/contacts/{uid}", response_model=dict, summary="删除联系人")
async def delete_contact(uid: str, token: str = Depends(get_current_token)):
    """删除指定 UID 的联系人。"""
    svc = ContactService()
    if not svc.get_by_uid(uid):
        raise HTTPException(404, "联系人不存在")
    ok = svc.delete(uid)
    return {"deleted": ok}


# ── Events ──────────────────────────────────────────────────────

@api_router.get("/events", summary="列出所有事件")
async def list_events(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=1000),
    date_from: str = Query("", description="起始日期 YYYYMMDD"),
    date_to: str = Query("", description="结束日期 YYYYMMDD（不含）"),
    token: str = Depends(get_current_token),
):
    """返回日历事件的摘要列表（标题、起止时间），支持分页和日期范围筛选。"""
    svc = EventService()
    if date_from and date_to:
        raw_list = svc.get_raw_by_dtstart_range(date_from, date_to)
        items = [o for r in raw_list if (o := _ical_to_event_out(r))]
        return {"items": items, "total": len(items)}
    raw_list, total = svc.get_all_raw_paginated(offset, limit)
    items = [o for r in raw_list if (o := _ical_to_event_out(r))]
    return {"items": items, "total": total}


@api_router.get("/events/{uid}", response_model=EventOut, summary="获取单个事件")
async def get_event(uid: str, token: str = Depends(get_current_token)):
    """根据 UID 获取事件的完整 iCalendar 数据。"""
    svc = EventService()
    raw = svc.get_by_uid(uid)
    if not raw:
        _logger.warning("get_event: UID=%s 不存在", uid)
        raise HTTPException(404, "事件不存在")
    out = _ical_to_event_out(raw)
    if not out:
        _logger.error("get_event: UID=%s 解析失败, raw前300字符:\n%s", uid, raw[:300])
        raise HTTPException(500, f"解析事件失败 (UID={uid})")
    return out


def _is_event_field_set(v):
    return v is not None and v != ""


@api_router.post("/events", response_model=dict, summary="创建事件")
async def create_event(body: EventCreate, token: str = Depends(get_current_token)):
    """通过结构化字段创建事件，后端自动构建 iCalendar。"""
    ical = _event_fields_to_ical(body)
    svc = EventService()
    uid, op = svc.add_event(ical)
    if uid is None:
        raise HTTPException(400, f"创建事件失败: {op}")
    return {"uid": uid, "operation": op}


@api_router.get("/events/export", summary="导出事件为 .ics 文件")
async def export_events(
    uids: str = Query("", description="UID列表，逗号分隔；为空时使用 date_from/date_to"),
    date_from: str = Query("", description="起始日期 YYYYMMDD"),
    date_to: str = Query("", description="结束日期 YYYYMMDD"),
    token: str = Depends(get_current_token),
):
    """根据 UID 列表或日期范围导出事件，返回 .ics 文件。"""
    svc = EventService()
    raw_list = []
    if uids:
        uid_list = [u.strip() for u in uids.split(",") if u.strip()]
        for uid in uid_list:
            r = svc.get_by_uid(uid)
            if r:
                raw_list.append(r)
    elif date_from and date_to:
        raw_list = svc.get_raw_by_dtstart_range(date_from, date_to)
    else:
        # fallback: last 365 days
        raw_list, _ = svc.get_all_raw_paginated(0, 1000)
    vevents = "\r\n".join(r.ical for r in raw_list if r and r.ical)
    ics = f"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//PersonalDAV//CN\r\n{vevents}\r\nEND:VCALENDAR"
    return Response(
        content=ics,
        media_type="text/calendar;charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="events.ics"'},
    )


@api_router.post("/events/import", response_model=dict, summary="从 iCalendar 导入事件")
async def import_event(body: dict, token: str = Depends(get_current_token)):
    """传入完整的 iCalendar 文本创建事件（用于 .ics 文件导入）。支持多事件 VCALENDAR。"""
    ical_data = body.get("ical_data", "")
    if not ical_data:
        raise HTTPException(400, "缺少 ical_data")
    svc = EventService()
    try:
        comp = vobject.readOne(ical_data)
        if comp.name == 'VCALENDAR':
            vevents = comp.contents.get('vevent', [])
            if len(vevents) > 1:
                results = []
                for ev in vevents:
                    single = vobject.iCalendar()
                    single.add(ev)
                    uid, op = svc.add_event(single.serialize())
                    if uid:
                        results.append({"uid": uid, "operation": op})
                return {"results": results, "count": len(results)}
        uid, op = svc.add_event(ical_data)
        if uid is None:
            raise HTTPException(400, f"导入事件失败: {op}")
        return {"uid": uid, "operation": op, "count": 1}
    except Exception as e:
        _logger.error("import_event 解析失败: %s", e)
        uid, op = svc.add_event(ical_data)
        if uid is None:
            raise HTTPException(400, f"导入事件失败: {op}")
        return {"uid": uid, "operation": op}


@api_router.put("/events/{uid}", response_model=dict, summary="更新事件")
async def update_event(uid: str, body: EventUpdate, token: str = Depends(get_current_token)):
    """通过结构化字段更新事件，后端自动构建 iCalendar。"""
    svc = EventService()
    try:
        existing = svc.get_by_uid(uid)
        if not existing:
            raise HTTPException(404, "事件不存在")
        out = _ical_to_event_out(existing)
        merged = EventCreate(
            summary=body.summary if _is_event_field_set(body.summary) else (out.summary if out else ""),
            dtstart=body.dtstart if _is_event_field_set(body.dtstart) else (out.dtstart if out else ""),
            dtend=body.dtend if _is_event_field_set(body.dtend) else (out.dtend if out else ""),
            all_day=body.all_day if body.all_day is not None else (out.all_day if out else False),
            description=body.description if _is_event_field_set(body.description) else (out.description if out else ""),
            location=body.location if _is_event_field_set(body.location) else (out.location if out else ""),
            categories=body.categories if _is_event_field_set(body.categories) else (out.categories if out else ""),
            rrule=body.rrule if _is_event_field_set(body.rrule) else (out.rrule if out else ""),
            reminders=body.reminders if body.reminders is not None else (out.reminders if out else []),
            attachments=body.attachments if body.attachments is not None else (out.attachments if out else []),
        )
        ical = _event_fields_to_ical(merged, uid=uid)
        new_uid, op = svc.add_event(ical, force=True)
        if new_uid is None:
            _logger.error("update_event uid=%s 失败: %s", uid, op)
            raise HTTPException(400, f"更新事件失败: {op}")
        return {"uid": new_uid, "operation": op}
    except HTTPException:
        raise
    except Exception as e:
        _logger.error("update_event uid=%s 异常: %s", uid, e)
        raise HTTPException(500, f"更新事件异常: {e}")


@api_router.delete("/events/{uid}", response_model=dict, summary="删除事件")
async def delete_event(uid: str, token: str = Depends(get_current_token)):
    """删除指定 UID 的事件。"""
    svc = EventService()
    if not svc.get_by_uid(uid):
        raise HTTPException(404, "事件不存在")
    ok = svc.delete(uid)
    return {"deleted": ok}


# ── Settings ───────────────────────────────────────────────────

@api_router.get("/settings", summary="获取所有设置")
async def list_settings(token: str = Depends(get_current_token)):
    s = SettingsService()
    return s.get_all_settings()


@api_router.get("/settings/{key}", summary="获取单个设置")
async def get_setting(key: str, token: str = Depends(get_current_token)):
    s = SettingsService()
    val = s.get_setting(key, None)
    if val is None:
        raise HTTPException(404, "设置不存在")
    return {"key": key, "value": val}


@api_router.put("/settings/{key}", summary="更新设置")
async def update_setting(key: str, body: dict, token: str = Depends(get_current_token)):
    s = SettingsService()
    s.set_setting(key, body.get("value", ""))
    return {"key": key, "updated": True}


# ── Server Config ─────────────────────────────────────────────

@api_router.get("/server/config", response_model=ServerConfigOut, summary="服务器配置信息")
async def server_config(token: str = Depends(get_current_token)):
    s = SettingsService()
    return ServerConfigOut(
        host=s.get_setting("default_host", "127.0.0.1"),
        port=int(s.get_setting("default_port", "8000")),
        db_path=s.get_setting("db_path", "data/dav_data.db"),
        dav_root=s.get_setting("dav_root", "./dav_root"),
        log_level=s.get_setting("log_level", "INFO"),
        mcp_enabled=s.get_setting("mcp_enabled", "False") == "True",
        mcp_port=int(s.get_setting("mcp_port", "8100")),
        mcp_safety_mode=s.get_setting("mcp_safety_mode", "confirm"),
        mcp_readonly=s.get_setting("mcp_readonly", "False") == "True",
        server_protocol=s.get_setting("server_protocol", "http_https"),
        ssl_enabled=s.get_setting("ssl_enabled", "False") == "True",
    )


# ── Auth Logs ──────────────────────────────────────────────────

@api_router.get("/auth/logs", response_model=list[AuthLogOut], summary="获取鉴权日志")
async def auth_logs(
    limit: int = Query(100, description="返回条数"),
    protocol: str = Query("", description="协议筛选"),
    token: str = Depends(get_current_token),
):
    svc = AuthService()
    return svc.get_auth_logs_filtered(protocol=protocol, limit=limit)


@api_router.get("/logs", response_model=list[SystemLogOut], summary="获取系统运行日志")
async def system_logs(token: str = Depends(get_current_token)):
    """获取内存中最近的系统日志。"""
    return list(LOG_QUEUE.queue)


# ── Stats ──────────────────────────────────────────────────────

@api_router.get("/stats", response_model=StatsOut, summary="服务器统计信息")
async def stats(token: str = Depends(get_current_token)):
    cs = ContactService()
    es = EventService()
    s = SettingsService()
    dav_root = s.get_setting("dav_root", "./dav_root")
    total_size = 0
    file_count = 0
    if os.path.isdir(dav_root):
        for dirpath, _, filenames in os.walk(dav_root):
            for fn in filenames:
                fp = os.path.join(dirpath, fn)
                try:
                    total_size += os.path.getsize(fp)
                    file_count += 1
                except Exception:
                    pass
    try: disk_total = shutil.disk_usage(dav_root).total / (1024 * 1024)
    except: disk_total = 0
    return StatsOut(
        contacts_count=cs.count(),
        events_count=es.count(),
        files_count=file_count,
        disk_used_mb=round(total_size / (1024 * 1024), 2),
        disk_total_mb=round(disk_total, 2),
        uptime=time.time() - _start_time,
        version=SOFTWARE_VERSION,
    )


@api_router.get("/trash", summary="回收站列表")
async def trash_list(token: str = Depends(get_current_token)):
    from services.trash_service import TrashService
    return {"items": TrashService.list_items()}


@api_router.post("/trash/restore", summary="从回收站还原")
async def trash_restore(
    uuid: str = Query(...), 
    target_path: str = Query(None), 
    conflict_strategy: str = Query("error"),
    token: str = Depends(get_current_token)
):
    from services.trash_service import TrashService
    try:
        ok = TrashService.restore(uuid, target_path=target_path, conflict_strategy=conflict_strategy)
    except FileExistsError as e:
        raise HTTPException(409, str(e))
    if not ok:
        raise HTTPException(404, "条目不存在")
    return {"restored": True}


@api_router.delete("/trash", summary="永久删除回收站条目")
async def trash_delete(uuid: str = Query(...), token: str = Depends(get_current_token)):
    from services.trash_service import TrashService
    ok = TrashService.permanent_delete(uuid)
    if not ok:
        raise HTTPException(404, "条目不存在")
    return {"deleted": True}


@api_router.post("/trash/purge", summary="清理过期回收站条目")
async def trash_purge(days: int = Query(30), token: str = Depends(get_current_token)):
    from services.trash_service import TrashService
    TrashService.purge(days)
    return {"purged": True}
from services.api_token_service import ApiTokenService

@api_router.get("/auth/tokens", summary="列出 API 令牌（不含原始令牌）")
async def list_api_tokens(token: str = Depends(get_current_token)):
    return ApiTokenService().list_tokens()

@api_router.post("/auth/tokens", summary="创建 API 令牌")
async def create_api_token(body: dict, token: str = Depends(get_current_token)):
    scopes = body.get("scopes", [])
    if not scopes:
        raise HTTPException(400, "至少需要选择一个权限")
    note = body.get("note", "")
    expires_at = body.get("expires_at", "")
    result = ApiTokenService().create_token(scopes, note, expires_at)
    return result

@api_router.delete("/auth/tokens/{token_id}", summary="删除 API 令牌")
async def delete_api_token(token_id: str, token: str = Depends(get_current_token)):
    ApiTokenService().delete_token(token_id)
    return {"deleted": True}

@api_router.put("/auth/tokens/{token_id}/note", summary="更新 API 令牌备注")
async def update_api_token_note(token_id: str, body: dict, token: str = Depends(get_current_token)):
    note = body.get("note", "")
    ApiTokenService().update_token_note(token_id, note)
    return {"updated": True}

@api_router.get("/apple/config", summary="生成 Apple 设备配置 (.mobileconfig)")
async def apple_config(request_host: str = Query(None, alias="host"), token: str = Depends(get_current_token)):
    ss = SettingsService()
    host = request_host or ss.get_setting("apple_config_host", "localhost")
    port = ss.get_setting("default_port", "8000")
    proto = ss.get_setting("server_protocol", "http_https")
    use_ssl = ss.get_setting("ssl_enabled", "False") == "True"
    scheme = "https" if (proto == "https_only" or (proto == "http_https" and use_ssl)) else "http"
    url_suffix = "" if (use_ssl and port == "443") or (not use_ssl and port == "80") else f":{port}"

    payload_uuid = str(uuid.uuid4())
    carddav_uuid = str(uuid.uuid4())
    caldav_uuid = str(uuid.uuid4())

    ssl_true = 'true' if use_ssl else 'false'

    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>CalendarAccountDescription</key>
            <string>PersonalDAV 日历</string>
            <key>CalendarHostName</key>
            <string>{host}</string>
            <key>CalendarPort</key>
            <integer>{port}</integer>
            <key>CalendarPrincipalURL</key>
            <string>{scheme}://{host}{url_suffix}/events/</string>
            <key>CalendarUseSSL</key>
            <{ssl_true}/>
            <key>PayloadDescription</key>
            <string>配置 CalDAV 日历账户</string>
            <key>PayloadDisplayName</key>
            <string>PersonalDAV 日历</string>
            <key>PayloadIdentifier</key>
            <string>com.personaldav.caldav.{caldav_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.caldav.account</string>
            <key>PayloadUUID</key>
            <string>{caldav_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        <dict>
            <key>CardDAVAccountDescription</key>
            <string>PersonalDAV 联系人</string>
            <key>CardDAVHostName</key>
            <string>{host}</string>
            <key>CardDAVPort</key>
            <integer>{port}</integer>
            <key>CardDAVPrincipalURL</key>
            <string>{scheme}://{host}{url_suffix}/contacts/</string>
            <key>CardDAVUseSSL</key>
            <{ssl_true}/>
            <key>PayloadDescription</key>
            <string>配置 CardDAV 联系人账户</string>
            <key>PayloadDisplayName</key>
            <string>PersonalDAV 联系人</string>
            <key>PayloadIdentifier</key>
            <string>com.personaldav.carddav.{carddav_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.carddav.account</string>
            <key>PayloadUUID</key>
            <string>{carddav_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>自动配置 PersonalDAV 联系人和日历账户</string>
    <key>PayloadDisplayName</key>
    <string>PersonalDAV 配置</string>
    <key>PayloadIdentifier</key>
    <string>com.personaldav.apple-config.{payload_uuid}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{payload_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>"""

    return Response(
        content=plist,
        media_type="application/x-apple-aspen-config",
        headers={
            "Content-Disposition": 'attachment; filename="personaldav.mobileconfig"'
        }
    )
