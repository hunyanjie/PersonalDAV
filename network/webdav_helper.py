import os
import time
import email.utils
from xml.etree import ElementTree as ET
from typing import Any

DAV_NS = "DAV:"


def _dav_tag(tag: str) -> str:
    return f"{{{DAV_NS}}}{tag}"


def _fmt_time(t: float) -> str:
    return email.utils.formatdate(timeval=t, localtime=False, usegmt=True)


def multistatus_xml(responses: list[dict[str, Any]]) -> bytes:
    root = ET.Element(_dav_tag("multistatus"), xmlns=DAV_NS)
    for r in responses:
        href = r.get("href", "")
        props = r.get("props", [{}])
        status = r.get("status", "HTTP/1.1 200 OK")

        resp_el = ET.SubElement(root, _dav_tag("response"))
        ET.SubElement(resp_el, _dav_tag("href")).text = href
        propstat = ET.SubElement(resp_el, _dav_tag("propstat"))
        prop_el = ET.SubElement(propstat, _dav_tag("prop"))
        for p in props:
            for k, v in p.items():
                ET.SubElement(prop_el, _dav_tag(k)).text = v
        ET.SubElement(propstat, _dav_tag("status")).text = status
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def propfind_response(path: str, entries: list[dict[str, Any]], base: str = "/dav") -> bytes:
    responses = []
    for e in entries:
        rel = e["name"]
        href = f"{base}/{rel}".replace("\\", "/")
        is_dir = e.get("is_directory", False)
        size = str(e.get("size", 0))
        modified = e.get("modified", "")
        props = [
            {"resourcetype": "" if not is_dir else ""},
            {"getcontenttype": "httpd/unix-directory" if is_dir else "application/octet-stream"},
            {"getcontentlength": size},
            {"getlastmodified": modified or _fmt_time(time.time())},
            {"displayname": rel},
        ]
        responses.append({"href": href, "props": props, "status": "HTTP/1.1 200 OK"})

    props_self = [
        {"resourcetype": ""},
        {"getcontenttype": "httpd/unix-directory"},
        {"getlastmodified": _fmt_time(time.time())},
        {"displayname": os.path.basename(path.rstrip("/")) or "dav"},
    ]
    responses.insert(0, {"href": base + path.rstrip("/") + "/", "props": props_self, "status": "HTTP/1.1 200 OK"})
    return multistatus_xml(responses)


def error_xml(msg: str) -> bytes:
    root = ET.Element(_dav_tag("error"))
    ET.SubElement(root, _dav_tag("message")).text = msg
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)
