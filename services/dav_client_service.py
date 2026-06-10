"""WebDAV client — remote DAV mount for file browsing/operations."""

import os
import re
import requests
from typing import Any
from urllib.parse import urljoin, quote
from xml.etree import ElementTree as ET


class DAVClientService:

    def _connect(self, server: str, port: int, username: str, password: str) -> tuple[str, requests.Session]:
        scheme = "https" if port == 443 else "http"
        base = f"{scheme}://{server}:{port}"
        sess = requests.Session()
        sess.auth = (username, password)
        sess.headers.update({"User-Agent": "PersonalDAV-Client/1.0"})
        return base, sess

    def list_dir(self, protocol: str, server: str, port: int,
                 username: str, password: str, path: str,
                 encoding: str = "utf-8") -> dict[str, Any]:
        try:
            base, sess = self._connect(server, port, username, password)
            url = urljoin(base, path)
            if not url.endswith("/"):
                url += "/"
            body = """<?xml version="1.0"?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname/>
    <d:resourcetype/>
    <d:getcontentlength/>
    <d:getlastmodified/>
  </d:prop>
</d:propfind>"""
            r = sess.request("PROPFIND", url, data=body,
                             headers={"Depth": "1", "Content-Type": "application/xml"},
                             timeout=30)
            r.raise_for_status()

            items = []
            ns = {"d": "DAV:"}
            root = ET.fromstring(r.content)
            for resp in root.findall("d:response", ns):
                href = resp.findtext("d:href", "", ns)
                if not href:
                    continue
                name = href.rstrip("/").split("/")[-1]
                if not name or name == path.rstrip("/").split("/")[-1]:
                    continue
                prop = resp.find("d:propstat/d:prop", ns)
                is_dir = prop is not None and prop.find("d:resourcetype/d:collection", ns) is not None
                size_text = prop.findtext("d:getcontentlength", "0", ns) if prop else "0"
                try:
                    size = int(size_text)
                except ValueError:
                    size = 0
                modified = prop.findtext("d:getlastmodified", "", ns) if prop else ""
                items.append({
                    "name": name,
                    "is_directory": is_dir,
                    "size": size,
                    "modified": modified,
                })
            return {"success": True, "data": items}
        except Exception as e:
            return {"success": False, "data": [], "error": str(e)}

    def upload(self, protocol: str, server: str, port: int,
               username: str, password: str, local: str, remote: str,
               encoding: str = "utf-8") -> dict[str, Any]:
        try:
            base, sess = self._connect(server, port, username, password)
            url = urljoin(base, remote)
            with open(local, "rb") as f:
                r = sess.put(url, data=f, timeout=60)
            r.raise_for_status()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def download(self, protocol: str, server: str, port: int,
                 username: str, password: str, remote: str, local: str,
                 encoding: str = "utf-8") -> dict[str, Any]:
        try:
            base, sess = self._connect(server, port, username, password)
            url = urljoin(base, remote)
            r = sess.get(url, timeout=60)
            r.raise_for_status()
            os.makedirs(os.path.dirname(local) or ".", exist_ok=True)
            with open(local, "wb") as f:
                f.write(r.content)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def delete(self, protocol: str, server: str, port: int,
               username: str, password: str, path: str,
               encoding: str = "utf-8") -> dict[str, Any]:
        try:
            base, sess = self._connect(server, port, username, password)
            url = urljoin(base, path)
            r = sess.delete(url, timeout=30)
            r.raise_for_status()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def rename(self, protocol: str, server: str, port: int,
               username: str, password: str, old: str, new: str,
               encoding: str = "utf-8") -> dict[str, Any]:
        try:
            base, sess = self._connect(server, port, username, password)
            src = urljoin(base, old)
            dst = urljoin(base, new)
            r = sess.request("MOVE", src, headers={"Destination": dst}, timeout=30)
            r.raise_for_status()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def mkdir(self, protocol: str, server: str, port: int,
              username: str, password: str, path: str,
              encoding: str = "utf-8") -> dict[str, Any]:
        try:
            base, sess = self._connect(server, port, username, password)
            url = urljoin(base, path)
            r = sess.request("MKCOL", url, timeout=30)
            r.raise_for_status()
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}
