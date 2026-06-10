"""REST API router — CRUD for contacts, events, system."""

import time, os
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from config import SOFTWARE_VERSION, SOFTWARE_NAME
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from services.auth_service import AuthService
from services.embeddings import EmbeddingService
from .models import (
    ContactOut, ContactCreate, ContactStructuredCreate, ContactUpdate,
    EventOut, EventCreate, EventUpdate, HealthOut, AuthTokenOut, AuthTokenRequest,
    ServerConfigOut, AuthLogOut, StatsOut, ErrorOut,
)
from .auth import get_current_token

api_router = APIRouter(tags=["API 接口"])
_start_time = time.time()


def _contact_to_out(raw: str) -> ContactOut | None:
    """Convert a vCard string to ContactOut (minimal parse)."""
    uid = ""
    full_name = email = phone = groups = ""
    for line in raw.splitlines():
        if line.upper().startswith("UID:"):
            uid = line[4:].strip()
        elif line.upper().startswith("FN:"):
            full_name = line[3:].strip()
        elif line.upper().startswith("EMAIL"):
            email = line.split(":", 1)[-1].strip() if ":" in line else ""
        elif line.upper().startswith("TEL"):
            phone = line.split(":", 1)[-1].strip() if ":" in line else ""
        elif line.upper().startswith("CATEGORIES"):
            groups = line.split(":", 1)[-1].strip() if ":" in line else ""
    if not uid:
        return None
    return ContactOut(uid=uid, full_name=full_name, email=email, phone=phone, groups=groups, vcard=raw)


def _event_to_out(raw: str) -> EventOut | None:
    """Convert an iCal string to EventOut (minimal parse)."""
    uid = summary = dtstart = dtend = ""
    for line in raw.splitlines():
        if line.upper().startswith("UID:"):
            uid = line[4:].strip()
        elif line.upper().startswith("SUMMARY"):
            summary = line.split(":", 1)[-1].strip() if ":" in line else ""
        elif line.upper().startswith("DTSTART"):
            dtstart = line.split(":", 1)[-1].strip() if ":" in line else ""
        elif line.upper().startswith("DTEND"):
            dtend = line.split(":", 1)[-1].strip() if ":" in line else ""
    if not uid:
        return None
    return EventOut(uid=uid, summary=summary, dtstart=dtstart, dtend=dtend, ical=raw)


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

    # IP 本机免密或未设密码时直接放行
    if svc.ip_bypasses_auth(client_ip) or not svc.is_password_required():
        token = svc.get_mcp_token()
        return AuthTokenOut(token=token, scopes=body.scopes)

    if not svc.verify_password(body.password):
        raise HTTPException(401, "密码错误")
    token = svc.get_mcp_token()
    if not token:
        raise HTTPException(403, "未设置密码，无法生成令牌")
    return AuthTokenOut(token=token, scopes=body.scopes)


# ── Contacts ────────────────────────────────────────────────────

@api_router.get("/contacts", response_model=list[ContactOut], summary="列出所有联系人")
async def list_contacts(token: str = Depends(get_current_token)):
    """返回所有联系人的摘要列表（姓名、邮箱、电话、分组）。"""
    svc = ContactService()
    raw_list = svc.get_all_raw()
    return [o for r in raw_list if (o := _contact_to_out(r))]


@api_router.get("/contacts/{uid}", response_model=ContactOut, summary="获取单个联系人")
async def get_contact(uid: str, token: str = Depends(get_current_token)):
    """根据 UID 获取联系人的完整 vCard 数据。"""
    svc = ContactService()
    raw = svc.get_by_uid(uid)
    if not raw:
        raise HTTPException(404, "联系人不存在")
    out = _contact_to_out(raw)
    if not out:
        raise HTTPException(500, "解析联系人失败")
    return out


@api_router.post("/contacts", response_model=dict, summary="从 vCard 创建联系人")
async def create_contact(body: ContactCreate, token: str = Depends(get_current_token)):
    """传入完整的 vCard 文本创建联系人，自动提取 UID。"""
    svc = ContactService()
    uid, op = svc.add_contact(body.vcard_data)
    if uid is None:
        raise HTTPException(400, f"创建联系人失败: {op}")
    return {"uid": uid, "operation": op}


@api_router.post("/contacts/structured", response_model=dict, summary="通过结构化信息创建联系人")
async def create_contact_structured(body: ContactStructuredCreate, token: str = Depends(get_current_token)):
    """通过姓名、邮箱、电话等结构化字段创建联系人，无需手动拼接 vCard。"""
    vcard = (
        "BEGIN:VCARD\r\nVERSION:3.0\r\n"
        f"FN:{body.full_name}\r\n"
        f"N:{body.full_name};;;\r\n"
    )
    if body.email:
        vcard += f"EMAIL:{body.email}\r\n"
    if body.phone:
        vcard += f"TEL:{body.phone}\r\n"
    vcard += "END:VCARD\r\n"
    svc = ContactService()
    uid, op = svc.add_contact(vcard)
    if uid is None:
        raise HTTPException(400, f"创建联系人失败: {op}")
    return {"uid": uid, "operation": op}


@api_router.put("/contacts/{uid}", response_model=dict, summary="更新联系人")
async def update_contact(uid: str, body: ContactUpdate, token: str = Depends(get_current_token)):
    """用新的 vCard 数据覆盖更新指定联系人。"""
    svc = ContactService()
    existing = svc.get_by_uid(uid)
    if not existing:
        raise HTTPException(404, "联系人不存在")
    new_uid, op = svc.add_contact(body.vcard_data, force=True)
    return {"uid": new_uid, "operation": op}


@api_router.delete("/contacts/{uid}", response_model=dict, summary="删除联系人")
async def delete_contact(uid: str, token: str = Depends(get_current_token)):
    """删除指定 UID 的联系人。"""
    svc = ContactService()
    if not svc.get_by_uid(uid):
        raise HTTPException(404, "联系人不存在")
    ok = svc.delete(uid)
    return {"deleted": ok}


# ── Events ──────────────────────────────────────────────────────

@api_router.get("/events", response_model=list[EventOut], summary="列出所有事件")
async def list_events(token: str = Depends(get_current_token)):
    """返回所有日历事件的摘要列表（标题、起止时间）。"""
    svc = EventService()
    raw_list = svc.get_all_raw()
    return [o for r in raw_list if (o := _event_to_out(r))]


@api_router.get("/events/{uid}", response_model=EventOut, summary="获取单个事件")
async def get_event(uid: str, token: str = Depends(get_current_token)):
    """根据 UID 获取事件的完整 iCalendar 数据。"""
    svc = EventService()
    raw = svc.get_by_uid(uid)
    if not raw:
        raise HTTPException(404, "事件不存在")
    out = _event_to_out(raw)
    if not out:
        raise HTTPException(500, "解析事件失败")
    return out


@api_router.post("/events", response_model=dict, summary="从 iCalendar 创建事件")
async def create_event(body: EventCreate, token: str = Depends(get_current_token)):
    """传入完整的 iCalendar 文本创建事件，自动提取 UID。"""
    svc = EventService()
    uid, op = svc.add_event(body.ical_data)
    if uid is None:
        raise HTTPException(400, f"创建事件失败: {op}")
    return {"uid": uid, "operation": op}


@api_router.put("/events/{uid}", response_model=dict, summary="更新事件")
async def update_event(uid: str, body: EventUpdate, token: str = Depends(get_current_token)):
    """用新的 iCalendar 数据覆盖更新指定事件。"""
    svc = EventService()
    existing = svc.get_by_uid(uid)
    if not existing:
        raise HTTPException(404, "事件不存在")
    new_uid, op = svc.add_event(body.ical_data, force=True)
    return {"uid": new_uid, "operation": op}


@api_router.delete("/events/{uid}", response_model=dict, summary="删除事件")
async def delete_event(uid: str, token: str = Depends(get_current_token)):
    """删除指定 UID 的事件。"""
    svc = EventService()
    if not svc.get_by_uid(uid):
        raise HTTPException(404, "事件不存在")
    ok = svc.delete(uid)
    return {"deleted": ok}


# ── Contacts Search ────────────────────────────────────────────

@api_router.get("/contacts/search", summary="搜索联系人")
async def search_contacts(
    q: str = Query("", description="关键词"),
    limit: int = Query(10, description="返回条数"),
    token: str = Depends(get_current_token),
):
    svc = EmbeddingService()
    return svc.search_contacts(q, top_k=limit)


# ── Events Search ──────────────────────────────────────────────

@api_router.get("/events/search", summary="搜索事件")
async def search_events(
    q: str = Query("", description="关键词"),
    date_from: str = Query("", description="起始时间"),
    date_to: str = Query("", description="结束时间"),
    limit: int = Query(10, description="返回条数"),
    token: str = Depends(get_current_token),
):
    svc = EmbeddingService()
    return svc.search_events(q, date_from=date_from, date_to=date_to, top_k=limit)


# ── Settings ───────────────────────────────────────────────────

@api_router.get("/settings", summary="获取所有设置")
async def list_settings(token: str = Depends(get_current_token)):
    s = SettingsService()
    rows = s.db.query("SELECT key, value FROM settings")
    return {r[0]: r[1] for r in rows}


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
    return StatsOut(
        contacts_count=cs.count(),
        events_count=es.count(),
        files_count=file_count,
        disk_used_mb=round(total_size / (1024 * 1024), 2),
        uptime=time.time() - _start_time,
        version=SOFTWARE_VERSION,
    )
