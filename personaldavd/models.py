"""Pydantic domain models for REST API."""

from datetime import datetime
from pydantic import BaseModel, Field


class ContactOut(BaseModel):
    id: int | None = None
    uid: str
    full_name: str = ""
    email: str = ""
    phone: str = ""
    groups: str = ""
    vcard: str = ""
    created_at: str = ""
    updated_at: str = ""


class ContactCreate(BaseModel):
    vcard_data: str


class ContactStructuredCreate(BaseModel):
    full_name: str
    email: str = ""
    phone: str = ""
    groups: str = ""
    address: str = ""
    org: str = ""
    note: str = ""


class ContactUpdate(BaseModel):
    vcard_data: str


class EventOut(BaseModel):
    id: int | None = None
    uid: str
    summary: str = ""
    dtstart: str = ""
    dtend: str = ""
    ical: str = ""
    created_at: str = ""
    updated_at: str = ""


class EventCreate(BaseModel):
    ical_data: str


class EventUpdate(BaseModel):
    ical_data: str


class HealthOut(BaseModel):
    status: str = "ok"
    version: str = ""
    uptime: float = 0.0
    contacts_count: int = 0
    events_count: int = 0


class AuthTokenOut(BaseModel):
    token: str
    scopes: list[str] = []


class AuthTokenRequest(BaseModel):
    password: str
    fingerprint: str = ""
    scopes: list[str] = ["contacts:read", "contacts:write", "events:read", "events:write", "dav:read", "dav:write"]


class ErrorOut(BaseModel):
    detail: str


class ServerConfigOut(BaseModel):
    host: str = ""
    port: int = 0
    db_path: str = ""
    dav_root: str = ""
    log_level: str = "INFO"
    mcp_enabled: bool = False
    mcp_port: int = 8100
    mcp_safety_mode: str = "confirm"
    mcp_readonly: bool = False


class AuthLogOut(BaseModel):
    id: int
    time: str
    ip: str
    success: bool
    method: str
    detail: str
    user_agent: str = ""
    fingerprint: str = ""
    prev_hash: str = ""
    hash: str = ""


class SystemLogOut(BaseModel):
    time: str
    level: str
    name: str
    message: str


class StatsOut(BaseModel):
    contacts_count: int = 0
    events_count: int = 0
    files_count: int = 0
    disk_used_mb: float = 0.0
    uptime: float = 0.0
    version: str = ""
