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
    address: str = ""
    org: str = ""
    note: str = ""
    photo: str = ""
    vcard: str = ""
    created_at: str = ""
    updated_at: str = ""


class ContactCreate(BaseModel):
    full_name: str
    email: str = ""
    phone: str = ""
    groups: str = ""
    address: str = ""
    org: str = ""
    note: str = ""
    photo: str = ""


class ContactUpdate(BaseModel):
    full_name: str | None = None
    email: str | None = None
    phone: str | None = None
    groups: str | None = None
    address: str | None = None
    org: str | None = None
    note: str | None = None
    photo: str | None = None


class EventOut(BaseModel):
    id: int | None = None
    uid: str
    summary: str = ""
    dtstart: str = ""
    dtend: str = ""
    all_day: bool = False
    description: str = ""
    location: str = ""
    categories: str = ""
    rrule: str = ""
    reminders: list[dict] = []
    attachments: list[dict] = []
    ical: str = ""
    created_at: str = ""
    updated_at: str = ""


class EventCreate(BaseModel):
    summary: str
    dtstart: str
    dtend: str
    all_day: bool = False
    description: str = ""
    location: str = ""
    categories: str = ""
    rrule: str = ""
    reminders: list[dict] = []
    attachments: list[dict] = []


class EventUpdate(BaseModel):
    summary: str | None = None
    dtstart: str | None = None
    dtend: str | None = None
    all_day: bool | None = None
    description: str | None = None
    location: str | None = None
    categories: str | None = None
    rrule: str | None = None
    reminders: list[dict] | None = None
    attachments: list[dict] | None = None


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
    scopes: list[str] = []


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
    server_protocol: str = "http_https"
    ssl_enabled: bool = False


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
    disk_total_mb: float = 0.0
    uptime: float = 0.0
    version: str = ""
    trends: dict[str, str] = {}
