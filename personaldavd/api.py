"""REST API router — CRUD for contacts, events, system."""

import time
from fastapi import APIRouter, Depends, HTTPException, Query
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from services.auth_service import AuthService
from .models import (
    ContactOut, ContactCreate, ContactStructuredCreate, ContactUpdate,
    EventOut, EventCreate, EventUpdate, HealthOut, AuthTokenOut, AuthTokenRequest,
)
from .auth import get_current_token

api_router = APIRouter(tags=["REST API"])
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

@api_router.get("/health", response_model=HealthOut, summary="Server health check")
async def health():
    svc = SettingsService()
    cs = ContactService()
    es = EventService()
    return HealthOut(
        status="ok", version="3.0.0",
        uptime=time.time() - _start_time,
        contacts_count=cs.count(),
        events_count=es.count(),
    )


# ── Auth / Token ────────────────────────────────────────────────

@api_router.post("/auth/token", response_model=AuthTokenOut, summary="Obtain bearer token")
async def get_token(req: AuthTokenRequest):
    svc = AuthService()
    if not svc.verify_password(req.password):
        raise HTTPException(401, "Invalid password")
    token = svc.get_mcp_token()
    if not token:
        raise HTTPException(403, "No password configured — token unavailable")
    return AuthTokenOut(token=token, scopes=req.scopes)


# ── Contacts ────────────────────────────────────────────────────

@api_router.get("/contacts", response_model=list[ContactOut], summary="List all contacts")
async def list_contacts(token: str = Depends(get_current_token)):
    svc = ContactService()
    raw_list = svc.get_all_raw()
    return [o for r in raw_list if (o := _contact_to_out(r))]


@api_router.get("/contacts/{uid}", response_model=ContactOut, summary="Get contact by UID")
async def get_contact(uid: str, token: str = Depends(get_current_token)):
    svc = ContactService()
    raw = svc.get_by_uid(uid)
    if not raw:
        raise HTTPException(404, "Contact not found")
    out = _contact_to_out(raw)
    if not out:
        raise HTTPException(500, "Failed to parse contact")
    return out


@api_router.post("/contacts", response_model=dict, summary="Create contact from vCard")
async def create_contact(body: ContactCreate, token: str = Depends(get_current_token)):
    svc = ContactService()
    uid, op = svc.add_contact(body.vcard_data)
    if uid is None:
        raise HTTPException(400, f"Failed to create contact: {op}")
    return {"uid": uid, "operation": op}


@api_router.post("/contacts/structured", response_model=dict, summary="Create contact from structured fields")
async def create_contact_structured(body: ContactStructuredCreate, token: str = Depends(get_current_token)):
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
        raise HTTPException(400, f"Failed to create contact: {op}")
    return {"uid": uid, "operation": op}


@api_router.put("/contacts/{uid}", response_model=dict, summary="Update contact")
async def update_contact(uid: str, body: ContactUpdate, token: str = Depends(get_current_token)):
    svc = ContactService()
    existing = svc.get_by_uid(uid)
    if not existing:
        raise HTTPException(404, "Contact not found")
    new_uid, op = svc.add_contact(body.vcard_data, force=True)
    return {"uid": new_uid, "operation": op}


@api_router.delete("/contacts/{uid}", response_model=dict, summary="Delete contact")
async def delete_contact(uid: str, token: str = Depends(get_current_token)):
    svc = ContactService()
    if not svc.get_by_uid(uid):
        raise HTTPException(404, "Contact not found")
    ok = svc.delete(uid)
    return {"deleted": ok}


# ── Events ──────────────────────────────────────────────────────

@api_router.get("/events", response_model=list[EventOut], summary="List all events")
async def list_events(token: str = Depends(get_current_token)):
    svc = EventService()
    raw_list = svc.get_all_raw()
    return [o for r in raw_list if (o := _event_to_out(r))]


@api_router.get("/events/{uid}", response_model=EventOut, summary="Get event by UID")
async def get_event(uid: str, token: str = Depends(get_current_token)):
    svc = EventService()
    raw = svc.get_by_uid(uid)
    if not raw:
        raise HTTPException(404, "Event not found")
    out = _event_to_out(raw)
    if not out:
        raise HTTPException(500, "Failed to parse event")
    return out


@api_router.post("/events", response_model=dict, summary="Create event from iCalendar")
async def create_event(body: EventCreate, token: str = Depends(get_current_token)):
    svc = EventService()
    uid, op = svc.add_event(body.ical_data)
    if uid is None:
        raise HTTPException(400, f"Failed to create event: {op}")
    return {"uid": uid, "operation": op}


@api_router.put("/events/{uid}", response_model=dict, summary="Update event")
async def update_event(uid: str, body: EventUpdate, token: str = Depends(get_current_token)):
    svc = EventService()
    existing = svc.get_by_uid(uid)
    if not existing:
        raise HTTPException(404, "Event not found")
    new_uid, op = svc.add_event(body.ical_data, force=True)
    return {"uid": new_uid, "operation": op}


@api_router.delete("/events/{uid}", response_model=dict, summary="Delete event")
async def delete_event(uid: str, token: str = Depends(get_current_token)):
    svc = EventService()
    if not svc.get_by_uid(uid):
        raise HTTPException(404, "Event not found")
    ok = svc.delete(uid)
    return {"deleted": ok}
