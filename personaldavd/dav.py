"""DAV protocol ASGI router — CardDAV + CalDAV + WebDAV + Attachments."""

import os
import hashlib
import mimetypes
import shutil
import urllib.parse
import xml.etree.ElementTree as ET
from fastapi import APIRouter, Request, Response
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from utils.attachment_store import ATTACHMENTS_DIR

dav_router = APIRouter(tags=["DAV 协议"])


def _etag(raw: str) -> str:
    return f'"{hashlib.md5(raw.encode("utf-8")).hexdigest()}"'


def _ctag(service) -> str:
    tags = []
    if service:
        for uid, raw in service.get_all_items():
            tags.append(service.get_etag(uid) or _etag(raw))
    return f'"ctag-{hashlib.md5("|".join(sorted(tags)).encode("utf-8")).hexdigest()[:16]}"'


def _multistatus_xml(responses: list[tuple[str, str, str, str, int]], ns: str = "") -> bytes:
    body = "\n".join(
        f'    <D:response>\n'
        f'        <D:href>{href}</D:href>\n'
        f'        <D:propstat>\n'
        f'            <D:prop>\n'
        f'                <D:resourcetype>{rtype}</D:resourcetype>\n'
        f'                <D:getetag>{etag}</D:getetag>\n'
        f'                <D:getcontenttype>{ctype}</D:getcontenttype>\n'
        f'                <D:getcontentlength>{size}</D:getcontentlength>\n'
        f'            </D:prop>\n'
        f'            <D:status>HTTP/1.1 200 OK</D:status>\n'
        f'        </D:propstat>\n'
        f'    </D:response>'
        for href, rtype, etag, ctype, size in responses
    )
    xml = f'<?xml version="1.0" encoding="utf-8" ?>\n<D:multistatus xmlns:D="DAV:" {ns}>\n{body}\n</D:multistatus>'
    return xml.encode("utf-8")


async def _body(request: Request) -> str:
    b = await request.body()
    return b.decode("utf-8") if b else ""


# ── Helpers ─────────────────────────────────────────────────────

def _collection_responses(service, path_prefix: str, ext: str, ctype: str) -> list[tuple[str, str, str, str, int]]:
    resp = [(path_prefix, "", "", "httpd/unix-directory", 0)]
    for uid, raw in service.get_all_items():
        href = f"{path_prefix}{uid}{ext}"
        e = service.get_etag(uid) or _etag(raw)
        resp.append((href, "", e, ctype, len(raw.encode("utf-8"))))
    return resp


# ── CardDAV — Contacts ──────────────────────────────────────────

@dav_router.api_route(
    "/contacts/{rest:path}",
    methods=["GET", "HEAD", "PUT", "DELETE", "PROPFIND", "REPORT", "OPTIONS"],
    include_in_schema=False,
)
@dav_router.api_route("/contacts/", methods=["GET", "HEAD", "PUT", "DELETE", "PROPFIND", "REPORT", "OPTIONS"],
                       include_in_schema=False)
@dav_router.api_route("/contacts", methods=["GET", "HEAD", "PUT", "DELETE", "PROPFIND", "REPORT", "OPTIONS"],
                       include_in_schema=False)
async def contacts_handler(request: Request, rest: str = ""):
    """CardDAV 联系人服务 — 支持 GET/PUT/DELETE/PROPFIND/REPORT/OPTIONS。"""
    svc = ContactService()
    method = request.method
    path = request.url.path.rstrip("/") or "/contacts"

    if method == "OPTIONS":
        return Response(headers={"Allow": "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, REPORT", "DAV": "1, 2, addressbook"})

    if method in ("GET", "HEAD"):
        uid = os.path.basename(path).replace(".vcf", "")
        if not uid or path.endswith("/contacts"):
            xml = _multistatus_xml(_collection_responses(svc, "/contacts/", ".vcf", "text/vcard"),
                                   'xmlns:C="urn:ietf:params:xml:ns:carddav"')
            return Response(content=xml, media_type="text/xml", status_code=207)
        raw = svc.get_by_uid(uid)
        if not raw:
            return Response("Not found", status_code=404)
        headers = {"ETag": svc.get_etag(uid) or _etag(raw), "Content-Type": "text/vcard"}
        if method == "HEAD":
            return Response(headers=headers)
        return Response(content=raw, headers=headers)

    if method == "PUT":
        data = await _body(request)
        uid, op = svc.add_contact(data, force=True)
        return Response(status_code=201, headers={"ETag": _etag(data)})

    if method == "DELETE":
        uid = os.path.basename(path).replace(".vcf", "")
        if svc.delete(uid):
            return Response(status_code=204)
        return Response("Not found", status_code=404)

    if method == "PROPFIND":
        depth = request.headers.get("Depth", "0")
        is_collection = path.endswith("/contacts") or path.endswith("/contacts/") or (not path.endswith(".vcf"))
        if is_collection:
            responses = [(path + "/", "", "", "httpd/unix-directory", 0)]
            if depth != "0":
                for uid, raw in svc.get_all_items():
                    href = f"{path}/{uid}.vcf" if not path.endswith("/") else f"{path}{uid}.vcf"
                    e = svc.get_etag(uid) or _etag(raw)
                    responses.append((href, "", e, "text/vcard", len(raw.encode("utf-8"))))
            xml = _multistatus_xml(responses, 'xmlns:C="urn:ietf:params:xml:ns:carddav"')
        else:
            uid = os.path.basename(path).replace(".vcf", "")
            raw = svc.get_by_uid(uid)
            e = svc.get_etag(uid) or (_etag(raw) if raw else '""')
            xml = _multistatus_xml([(path, "", e, "text/vcard", len(raw.encode("utf-8")) if raw else 0)],
                                   'xmlns:C="urn:ietf:params:xml:ns:carddav"')
        return Response(content=xml, media_type="text/xml; charset=utf-8", status_code=207)

    if method == "REPORT":
        data = await _body(request)
        root = ET.fromstring(data)
        ns = {"D": "DAV:", "C": "urn:ietf:params:xml:ns:carddav"}
        hrefs = [h.text for h in root.findall(".//D:href", ns) if h.text]
        responses = []
        for href in hrefs:
            uid = os.path.basename(href).replace(".vcf", "")
            raw = svc.get_by_uid(uid)
            if raw:
                e = svc.get_etag(uid) or _etag(raw)
                responses.append((href, "", e, "text/vcard", len(raw.encode("utf-8"))))
            else:
                responses.append((href, "", '""', "text/vcard", 0))
        xml = _multistatus_xml(responses, 'xmlns:C="urn:ietf:params:xml:ns:carddav"')
        return Response(content=xml, media_type="text/xml; charset=utf-8", status_code=207)

    return Response(status_code=405)


# ── CalDAV — Events ─────────────────────────────────────────────

@dav_router.api_route(
    "/events/{rest:path}",
    methods=["GET", "HEAD", "PUT", "DELETE", "PROPFIND", "REPORT", "OPTIONS"],
    include_in_schema=False,
)
@dav_router.api_route("/events/", methods=["GET", "HEAD", "PUT", "DELETE", "PROPFIND", "REPORT", "OPTIONS"],
                       include_in_schema=False)
@dav_router.api_route("/events", methods=["GET", "HEAD", "PUT", "DELETE", "PROPFIND", "REPORT", "OPTIONS"],
                       include_in_schema=False)
async def events_handler(request: Request, rest: str = ""):
    """CalDAV 日历事件服务 — 支持 GET/PUT/DELETE/PROPFIND/REPORT/OPTIONS。"""
    svc = EventService()
    method = request.method
    path = request.url.path.rstrip("/") or "/events"
    ss = SettingsService()
    mode = ss.get_setting("attachment_mode", "inline")
    scheme = request.url.scheme
    host = request.headers.get("Host", f"localhost:{request.url.port or 8000}")
    base_url = f"{scheme}://{host}"

    if method == "OPTIONS":
        return Response(headers={"Allow": "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, REPORT", "DAV": "1, 2, calendar-access"})

    if method in ("GET", "HEAD"):
        uid = os.path.basename(path).replace(".ics", "")
        if not uid or path.endswith("/events"):
            xml = _multistatus_xml(
                _collection_responses(svc, "/events/", ".ics", "text/calendar"),
                'xmlns:CAL="urn:ietf:params:xml:ns:caldav"',
            )
            return Response(content=xml, media_type="text/xml", status_code=207)
        raw = svc.get_by_uid(uid)
        if not raw:
            return Response("Not found", status_code=404)
        full = svc.get_full_ical(uid, mode, base_url) or raw
        headers = {"ETag": svc.get_etag(uid) or _etag(full), "Content-Type": "text/calendar"}
        if method == "HEAD":
            return Response(headers=headers)
        return Response(content=full, headers=headers)

    if method == "PUT":
        data = await _body(request)
        uid, op = svc.add_event(data, force=True)
        return Response(status_code=201, headers={"ETag": _etag(data)})

    if method == "DELETE":
        uid = os.path.basename(path).replace(".ics", "")
        if svc.delete(uid):
            return Response(status_code=204)
        return Response("Not found", status_code=404)

    if method == "PROPFIND":
        depth = request.headers.get("Depth", "0")
        is_collection = path.endswith("/events") or path.endswith("/events/") or (not path.endswith(".ics"))
        if is_collection:
            responses = [(path + "/", "", "", "httpd/unix-directory", 0)]
            if depth != "0":
                for uid, raw in svc.get_all_items():
                    href = f"{path}/{uid}.ics" if not path.endswith("/") else f"{path}{uid}.ics"
                    e = svc.get_etag(uid) or _etag(raw)
                    responses.append((href, "", e, "text/calendar", len(raw.encode("utf-8"))))
            xml = _multistatus_xml(responses, 'xmlns:CAL="urn:ietf:params:xml:ns:caldav"')
        else:
            uid = os.path.basename(path).replace(".ics", "")
            raw = svc.get_by_uid(uid)
            e = svc.get_etag(uid) or (_etag(raw) if raw else '""')
            xml = _multistatus_xml([(path, "", e, "text/calendar", len(raw.encode("utf-8")) if raw else 0)],
                                   'xmlns:CAL="urn:ietf:params:xml:ns:caldav"')
        return Response(content=xml, media_type="text/xml; charset=utf-8", status_code=207)

    if method == "REPORT":
        data = await _body(request)
        root = ET.fromstring(data)
        ns = {"D": "DAV:", "CAL": "urn:ietf:params:xml:ns:caldav"}
        hrefs = [h.text for h in root.findall(".//D:href", ns) if h.text]
        responses = []
        for href in hrefs:
            uid = os.path.basename(href).replace(".ics", "")
            raw = svc.get_by_uid(uid)
            if raw:
                full = svc.get_full_ical(uid, mode, base_url) or raw
                e = svc.get_etag(uid) or _etag(full)
                responses.append((href, "", e, "text/calendar", len(full.encode("utf-8"))))
            else:
                responses.append((href, "", '""', "text/calendar", 0))
        xml = _multistatus_xml(responses, 'xmlns:CAL="urn:ietf:params:xml:ns:caldav"')
        return Response(content=xml, media_type="text/xml; charset=utf-8", status_code=207)

    return Response(status_code=405)


# ── Attachments ─────────────────────────────────────────────────

@dav_router.api_route("/attachments/{filename}", methods=["GET", "HEAD"], include_in_schema=False)
async def attachment_asgi(request: Request, filename: str):
    """附件下载 — 返回日历事件中引用的附件文件。"""
    safe_path = os.path.normpath(os.path.join(ATTACHMENTS_DIR, os.path.basename(filename)))
    if not safe_path.startswith(os.path.normpath(ATTACHMENTS_DIR)):
        return Response("Forbidden", status_code=403)
    if not os.path.isfile(safe_path):
        return Response("Not found", status_code=404)
    try:
        with open(safe_path, "rb") as f:
            data = f.read()
        ct, _ = mimetypes.guess_type(filename)
        headers = {
            "Content-Type": ct or "application/octet-stream",
            "Content-Length": str(len(data)),
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
        if request.method == "HEAD":
            return Response(headers=headers)
        return Response(content=data, headers=headers)
    except Exception as e:
        return Response(str(e), status_code=500)


# ── WebDAV — File Services ──────────────────────────────────────

@dav_router.api_route(
    "/dav/{rest:path}",
    methods=["GET", "HEAD", "PUT", "DELETE", "PROPFIND", "MKCOL", "COPY", "MOVE", "OPTIONS"],
    include_in_schema=False,
)
@dav_router.api_route("/dav", methods=["GET", "HEAD", "PUT", "DELETE", "PROPFIND", "MKCOL", "COPY", "MOVE", "OPTIONS"],
                       include_in_schema=False)
async def webdav_handler(request: Request, rest: str = ""):
    """WebDAV 文件服务 — 支持 GET/PUT/DELETE/PROPFIND/MKCOL/COPY/MOVE。"""
    method = request.method
    dav_root = SettingsService().get_setting("dav_root", "./dav_root")

    def _safe(p: str) -> str:
        full = os.path.normpath(os.path.join(dav_root, p.lstrip("/")))
        if not full.startswith(os.path.normpath(dav_root)):
            raise ValueError("Forbidden")
        return full

    if method == "OPTIONS":
        return Response(headers={"Allow": "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, COPY, MOVE", "DAV": "1, 2"})

    if method in ("GET", "HEAD"):
        try:
            fs_path = _safe(rest)
        except ValueError:
            return Response("Forbidden", status_code=403)
        if not os.path.exists(fs_path):
            return Response("Not found", status_code=404)
        if os.path.isdir(fs_path):
            items = []
            for name in sorted(os.listdir(fs_path)):
                items.append(f'<li><a href="/dav/{rest}/{name}">{name}</a></li>' if rest else f'<li><a href="/dav/{name}">{name}</a></li>')
            body = f"<html><body><ul>{''.join(items)}</ul></body></html>"
            return Response(content=body, media_type="text/html")
        with open(fs_path, "rb") as f:
            data = f.read()
        ct, _ = mimetypes.guess_type(fs_path)
        headers = {"Content-Type": ct or "application/octet-stream"}
        if method == "HEAD":
            return Response(headers=headers)
        return Response(content=data, headers=headers)

    if method == "PUT":
        try:
            fs_path = _safe(rest)
        except ValueError:
            return Response("Forbidden", status_code=403)
        os.makedirs(os.path.dirname(fs_path), exist_ok=True)
        body = await request.body()
        with open(fs_path, "wb") as f:
            f.write(body)
        return Response(status_code=201)

    if method == "DELETE":
        try:
            fs_path = _safe(rest)
        except ValueError:
            return Response("Forbidden", status_code=403)
        if os.path.isdir(fs_path):
            shutil.rmtree(fs_path)
        elif os.path.isfile(fs_path):
            os.remove(fs_path)
        else:
            return Response("Not found", status_code=404)
        return Response(status_code=204)

    if method == "PROPFIND":
        try:
            fs_path = _safe(rest)
        except ValueError:
            return Response("Forbidden", status_code=403)
        if not os.path.exists(fs_path):
            return Response("Not found", status_code=404)
        depth = request.headers.get("Depth", "0")
        base_href = f"/dav/{rest}".rstrip("/") or "/dav"
        responses = []
        if os.path.isfile(fs_path):
            with open(fs_path, "rb") as f:
                etag_v = f'"{hashlib.md5(f.read()).hexdigest()}"'
            s = os.stat(fs_path)
            responses.append((base_href, "", etag_v, "application/octet-stream", s.st_size))
        else:
            responses.append((base_href, "", "", "httpd/unix-directory", 0))
            if depth != "0":
                for name in sorted(os.listdir(fs_path)):
                    child = os.path.join(fs_path, name)
                    href = f"{base_href}/{name}"
                    s = os.stat(child)
                    if os.path.isdir(child):
                        responses.append((href, "", "", "httpd/unix-directory", 0))
                    else:
                        with open(child, "rb") as f:
                            etag_v = f'"{hashlib.md5(f.read()).hexdigest()}"'
                        responses.append((href, "", etag_v, "application/octet-stream", s.st_size))
        xml = _multistatus_xml(responses)
        return Response(content=xml, media_type="text/xml; charset=utf-8", status_code=207)

    if method == "MKCOL":
        try:
            fs_path = _safe(rest)
        except ValueError:
            return Response("Forbidden", status_code=403)
        if os.path.exists(fs_path):
            return Response("Already exists", status_code=405)
        os.makedirs(fs_path)
        return Response(status_code=201)

    if method in ("COPY", "MOVE"):
        dst_header = request.headers.get("Destination", "")
        if not dst_header:
            return Response("Destination header required", status_code=400)
        dst_path = urllib.parse.urlparse(dst_header).path
        dst_rel = dst_path.replace("/dav/", "", 1) if "/dav/" in dst_path else dst_path.lstrip("/")
        try:
            src_fs = _safe(rest)
            dst_fs = _safe(dst_rel)
        except ValueError:
            return Response("Forbidden", status_code=403)
        if os.path.isdir(src_fs):
            (shutil.copytree if method == "COPY" else shutil.move)(src_fs, dst_fs, dirs_exist_ok=True)
        elif os.path.isfile(src_fs):
            os.makedirs(os.path.dirname(dst_fs), exist_ok=True)
            (shutil.copy2 if method == "COPY" else shutil.move)(src_fs, dst_fs)
        else:
            return Response("Not found", status_code=404)
        return Response(status_code=201)

    return Response(status_code=405)



