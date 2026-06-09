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
    scopes: list[str] = ["contacts:read", "contacts:write", "events:read", "events:write", "dav:read", "dav:write"]


class ErrorOut(BaseModel):
    detail: str
