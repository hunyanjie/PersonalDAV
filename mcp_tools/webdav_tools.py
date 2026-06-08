import os
import urllib.request
import urllib.parse
import urllib.error
import xml.etree.ElementTree as ET
from typing import Any

from mcp_tools.helpers import safe_json, check_readonly
from utils.logger import logger


def _webdav_request(method: str, url: str, data: bytes | None = None,
                    headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
            return {"success": True, "status": r.status, "body": body}
    except urllib.error.HTTPError as e:
        body = e.read()
        return {"success": False, "status": e.code, "body": body, "error": str(e)}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _dav_propfind(path: str, base_url: str = "http://localhost:8080") -> list[dict]:
    url = f"{base_url.rstrip('/')}/dav/{path.lstrip('/')}"
    propfind_body = b"""<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:resourcetype/>
    <D:getetag/>
    <D:getcontentlength/>
    <D:getcontenttype/>
    <D:getlastmodified/>
  </D:prop>
</D:propfind>"""
    result = _webdav_request("PROPFIND", url, propfind_body,
                             {"Content-Type": "text/xml; charset=utf-8", "Depth": "1"})
    if not result["success"]:
        return []
    try:
        root = ET.fromstring(result["body"])
        ns = {"D": "DAV:"}
        entries = []
        for resp in root.findall(".//D:response", ns):
            href = resp.findtext("D:href", "", ns)
            if href.rstrip("/") == url.rstrip("/") or href.rstrip("/") == url.rstrip("/") + "/":
                continue
            name = href.rstrip("/").rsplit("/", 1)[-1] if "/" in href else href
            props = resp.find("D:propstat/D:prop", ns)
            is_dir = props is not None and props.find("D:resourcetype/D:collection", ns) is not None
            size = ""
            modified = ""
            if props is not None:
                size_el = props.find("D:getcontentlength", ns)
                if size_el is not None and size_el.text:
                    size = int(size_el.text)
                mod_el = props.find("D:getlastmodified", ns)
                if mod_el is not None and mod_el.text:
                    modified = mod_el.text
            entries.append({
                "name": urllib.parse.unquote(name),
                "is_directory": is_dir,
                "size": size,
                "modified": modified,
            })
        return entries
    except Exception:
        return []


def register(mcp):
    @mcp.tool(description="列出 WebDAV (/dav/) 目录下的文件")
    def dav_list_files(path: str = "/", base_url: str = "http://localhost:8080") -> str:
        logger.info(f"MCP 调用: dav_list_files path={path}")
        try:
            entries = _dav_propfind(path, base_url)
            return safe_json({"success": True, "data": entries})
        except Exception as e:
            logger.exception("MCP 异常: dav_list_files")
            return safe_json({"error": str(e)})

    @mcp.tool(description="上传文件到 WebDAV (/dav/) 目录")
    def dav_upload(local_path: str, remote_path: str, base_url: str = "http://localhost:8080") -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: dav_upload {local_path} -> {remote_path}")
        try:
            if not os.path.isfile(local_path):
                return safe_json({"error": f"本地文件不存在: {local_path}"})
            url = f"{base_url.rstrip('/')}/dav/{remote_path.lstrip('/')}"
            with open(local_path, "rb") as f:
                data = f.read()
            result = _webdav_request("PUT", url, data)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: dav_upload")
            return safe_json({"error": str(e)})

    @mcp.tool(description="从 WebDAV (/dav/) 下载文件到本地")
    def dav_download(remote_path: str, local_path: str, base_url: str = "http://localhost:8080") -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: dav_download {remote_path} -> {local_path}")
        try:
            url = f"{base_url.rstrip('/')}/dav/{remote_path.lstrip('/')}"
            result = _webdav_request("GET", url)
            if not result["success"]:
                return safe_json(result)
            os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(result["body"])
            return safe_json({"success": True, "local_path": local_path})
        except Exception as e:
            logger.exception("MCP 异常: dav_download")
            return safe_json({"error": str(e)})

    @mcp.tool(description="删除 WebDAV (/dav/) 上的文件或目录")
    def dav_delete(path: str, base_url: str = "http://localhost:8080") -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: dav_delete {path}")
        try:
            url = f"{base_url.rstrip('/')}/dav/{path.lstrip('/')}"
            result = _webdav_request("DELETE", url)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: dav_delete")
            return safe_json({"error": str(e)})

    @mcp.tool(description="在 WebDAV (/dav/) 上创建目录")
    def dav_mkdir(path: str, base_url: str = "http://localhost:8080") -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: dav_mkdir {path}")
        try:
            url = f"{base_url.rstrip('/')}/dav/{path.lstrip('/')}"
            result = _webdav_request("MKCOL", url)
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: dav_mkdir")
            return safe_json({"error": str(e)})
