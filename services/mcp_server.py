"""
MCP（Model Context Protocol）服务器——可嵌入类 + 独立 CLI。

嵌入 GUI：
    from services.mcp_server import MCPServer
    srv = MCPServer()
    srv.start(port=8100)
    srv.stop()

独立运行（调试）：
    python -m services.mcp_server
"""

import argparse
import json
import threading
import time
import traceback
import urllib.request
from typing import Any

from mcp.server.fastmcp import FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_DESCRIPTION, DEFAULT_DB_PATH
from services.contact_service import ContactService
from services.event_service import EventService
from services.auth_service import AuthService
from network.dav_server import DAVServer
from utils.logger import logger

CONTACT_SVC = ContactService()
EVENT_SVC = EventService()


def _make_contact_summary(uid: str) -> dict[str, Any]:
    raw = CONTACT_SVC.get_by_uid(uid)
    if not raw:
        return {"uid": uid, "error": "not found"}
    try:
        import vobject
        v = vobject.readOne(raw)
        fn = v.fn.value if hasattr(v, 'fn') else ""
        emails = [e.value for e in v.email_list] if hasattr(v, 'email_list') else []
        phones = [t.value for t in v.tel_list] if hasattr(v, 'tel_list') else []
        return {"uid": uid, "full_name": fn, "emails": emails, "phones": phones}
    except Exception:
        return {"uid": uid, "detail": "(parse failed)"}


def _make_event_summary(uid: str) -> dict[str, Any]:
    raw = EVENT_SVC.get_by_uid(uid)
    if not raw:
        return {"uid": uid, "error": "not found"}
    try:
        import vobject
        cal = vobject.readOne(raw)
        ev = cal.vevent if cal.name == 'VCALENDAR' else cal
        summary = ev.summary.value if hasattr(ev, 'summary') else ""
        dtstart = str(ev.dtstart.value) if hasattr(ev, 'dtstart') else ""
        dtend = str(ev.dtend.value) if hasattr(ev, 'dtend') else ""
        return {"uid": uid, "summary": summary, "dtstart": dtstart, "dtend": dtend}
    except Exception:
        return {"uid": uid, "detail": "(parse failed)"}


class MCPServer:
    """可在后台线程运行的 MCP SSE 服务器"""

    def __init__(self):
        self._mcp = FastMCP("PersonalDAV")
        self._uvicorn_server: Any = None
        self._thread: threading.Thread | None = None
        self._register_tools()
        logger.info("MCPServer 实例已创建")

    # ── 生命周期 ──────────────────────────────────────────────────

    def start(self, host: str = "127.0.0.1", port: int = 8100) -> bool:
        if self._uvicorn_server is not None:
            logger.warning(f"MCP 服务器已在端口运行，忽略重复启动请求")
            return False
        import uvicorn
        logger.info(f"MCP 服务器正在启动，监听 {host}:{port}")
        app = self._mcp.sse_app()

        class MCPAuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                if request.url.path in ('/sse', '/messages/'):
                    svc = AuthService()
                    if svc.is_enabled():
                        auth = request.headers.get('authorization', '')
                        if not auth.startswith('Bearer '):
                            return JSONResponse({"error": "missing token"}, status_code=401)
                        if not svc.verify_mcp_token(auth[7:]):
                            return JSONResponse({"error": "invalid token"}, status_code=401)
                return await call_next(request)

        app.add_middleware(MCPAuthMiddleware)
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self._uvicorn_server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._uvicorn_server.run, daemon=True)
        self._thread.start()
        time.sleep(0.3)
        if self._uvicorn_server and hasattr(self._uvicorn_server, 'started') and self._uvicorn_server.started:
            logger.info(f"MCP 服务器已启动，端口 {port}")
        else:
            logger.info(f"MCP 服务器启动中（端口 {port}）")
        return True

    def stop(self) -> None:
        if self._uvicorn_server is not None:
            logger.info("MCP 服务器正在关闭")
            self._uvicorn_server.should_exit = True
            self._uvicorn_server = None
            self._thread = None
            logger.info("MCP 服务器已关闭")
        else:
            logger.debug("MCP 服务器停止请求被忽略（未运行）")

    @property
    def is_running(self) -> bool:
        return self._uvicorn_server is not None

    # ── 工具注册 ─────────────────────────────────────────────────

    def _register_tools(self) -> None:
        mcp = self._mcp
        _server_instance: list[DAVServer | None] = [None]

        def _safe_json(data) -> str:
            try:
                return json.dumps(data, ensure_ascii=False)
            except Exception as e:
                logger.exception("JSON 序列化失败")
                return json.dumps({"error": f"serialization failed: {e}"}, ensure_ascii=False)

        # ── 服务端管理 ───────────────────────────────────────────

        @mcp.tool(description="启动 DAV 服务器（后台线程运行）")
        def server_start(port: int = 8080) -> str:
            logger.info(f"MCP 调用: server_start port={port}")
            try:
                if _server_instance[0] is not None:
                    msg = "DAV 服务器已在运行"
                    logger.info(f"MCP 返回: server_start -> {msg}")
                    return msg
                s = DAVServer(port)
                _server_instance[0] = s
                threading.Thread(target=s.start, daemon=True).start()
                time.sleep(0.5)
                msg = f"DAV 服务器已启动，监听端口 {port}"
                logger.info(f"MCP 返回: server_start -> {msg}")
                return msg
            except Exception as e:
                logger.exception(f"MCP 异常: server_start")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="停止正在运行的 DAV 服务器")
        def server_stop() -> str:
            logger.info("MCP 调用: server_stop")
            try:
                s = _server_instance[0]
                if s is None:
                    msg = "DAV 服务器未运行"
                    logger.info(f"MCP 返回: server_stop -> {msg}")
                    return msg
                s.stop()
                _server_instance[0] = None
                logger.info("MCP 返回: server_stop -> DAV 服务器已停止")
                return "DAV 服务器已停止"
            except Exception as e:
                logger.exception("MCP 异常: server_stop")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="查询 DAV 服务器当前运行状态")
        def server_status() -> str:
            try:
                result = {"running": _server_instance[0] is not None, "port": 8080 if _server_instance[0] else None}
                logger.debug(f"MCP 调用: server_status -> {result}")
                return _safe_json(result)
            except Exception as e:
                logger.exception("MCP 异常: server_status")
                return _safe_json({"error": str(e)})

        # ── 联系人 ──────────────────────────────────────────────

        @mcp.tool(description="列出所有联系人摘要（uid + 姓名）")
        def list_contacts() -> str:
            logger.info("MCP 调用: list_contacts")
            try:
                items = CONTACT_SVC.get_list_data()
                result = []
                for row in items:
                    result.append({"uid": row[0], "full_name": row[1], "email": row[2], "phone": row[3]})
                logger.info(f"MCP 返回: list_contacts -> {len(result)} 条")
                return _safe_json(result)
            except Exception as e:
                logger.exception("MCP 异常: list_contacts")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="获取单个联系人的完整 vCard 数据")
        def get_contact(uid: str) -> str:
            logger.info(f"MCP 调用: get_contact uid={uid}")
            try:
                raw = CONTACT_SVC.get_by_uid(uid)
                if raw is None:
                    logger.warning(f"MCP 返回: get_contact -> 联系人 {uid} 不存在")
                    return _safe_json({"error": f"联系人 {uid} 不存在"})
                summary = _make_contact_summary(uid)
                summary["vcard"] = raw
                logger.info(f"MCP 返回: get_contact -> {uid} ({summary.get('full_name', '')})")
                return _safe_json(summary)
            except Exception as e:
                logger.exception(f"MCP 异常: get_contact uid={uid}")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="通过 vCard 数据创建联系人")
        def create_contact(vcard_data: str) -> str:
            logger.info(f"MCP 调用: create_contact vcard_data({len(vcard_data)}B)")
            try:
                uid, op = CONTACT_SVC.add_contact(vcard_data, publish=False)
                if uid is None:
                    logger.error(f"MCP 返回: create_contact -> 失败: {op}")
                    return _safe_json({"error": op})
                logger.info(f"MCP 返回: create_contact -> uid={uid} op={op}")
                return _safe_json({"uid": uid, "operation": op})
            except Exception as e:
                logger.exception("MCP 异常: create_contact")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="更新联系人（提供 UID 和新的 vCard 数据）")
        def update_contact(uid: str, vcard_data: str) -> str:
            logger.info(f"MCP 调用: update_contact uid={uid} vcard_data({len(vcard_data)}B)")
            try:
                uid, op = CONTACT_SVC.add_contact(vcard_data, force=True, publish=False)
                if uid is None:
                    logger.error(f"MCP 返回: update_contact -> 失败: {op}")
                    return _safe_json({"error": op})
                logger.info(f"MCP 返回: update_contact -> uid={uid} op={op}")
                return _safe_json({"uid": uid, "operation": op})
            except Exception as e:
                logger.exception(f"MCP 异常: update_contact uid={uid}")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="删除指定 UID 的联系人")
        def delete_contact(uid: str) -> str:
            logger.info(f"MCP 调用: delete_contact uid={uid}")
            try:
                ok = CONTACT_SVC.delete(uid)
                logger.info(f"MCP 返回: delete_contact -> uid={uid} deleted={ok}")
                return _safe_json({"uid": uid, "deleted": ok})
            except Exception as e:
                logger.exception(f"MCP 异常: delete_contact uid={uid}")
                return _safe_json({"error": str(e)})

        # ── 日历事件 ────────────────────────────────────────────

        @mcp.tool(description="列出所有事件摘要（uid + 标题 + 起止时间）")
        def list_events() -> str:
            logger.info("MCP 调用: list_events")
            try:
                items = EVENT_SVC.get_list_data()
                result = []
                for row in items:
                    result.append({"uid": row[0], "summary": row[1], "dtstart": row[2], "dtend": row[3]})
                logger.info(f"MCP 返回: list_events -> {len(result)} 条")
                return _safe_json(result)
            except Exception as e:
                logger.exception("MCP 异常: list_events")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="获取单个事件的完整 iCalendar 数据")
        def get_event(uid: str) -> str:
            logger.info(f"MCP 调用: get_event uid={uid}")
            try:
                raw = EVENT_SVC.get_by_uid(uid)
                if raw is None:
                    logger.warning(f"MCP 返回: get_event -> 事件 {uid} 不存在")
                    return _safe_json({"error": f"事件 {uid} 不存在"})
                summary = _make_event_summary(uid)
                summary["ical"] = raw
                logger.info(f"MCP 返回: get_event -> {uid} ({summary.get('summary', '')})")
                return _safe_json(summary)
            except Exception as e:
                logger.exception(f"MCP 异常: get_event uid={uid}")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="通过 iCalendar 数据创建事件")
        def create_event(ical_data: str) -> str:
            logger.info(f"MCP 调用: create_event ical_data({len(ical_data)}B)")
            try:
                uid, op = EVENT_SVC.add_event(ical_data, publish=False)
                if uid is None:
                    logger.error(f"MCP 返回: create_event -> 失败: {op}")
                    return _safe_json({"error": op})
                logger.info(f"MCP 返回: create_event -> uid={uid} op={op}")
                return _safe_json({"uid": uid, "operation": op})
            except Exception as e:
                logger.exception("MCP 异常: create_event")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="更新事件（提供 UID 和新的 iCalendar 数据）")
        def update_event(uid: str, ical_data: str) -> str:
            logger.info(f"MCP 调用: update_event uid={uid} ical_data({len(ical_data)}B)")
            try:
                uid, op = EVENT_SVC.add_event(ical_data, force=True, publish=False)
                if uid is None:
                    logger.error(f"MCP 返回: update_event -> 失败: {op}")
                    return _safe_json({"error": op})
                logger.info(f"MCP 返回: update_event -> uid={uid} op={op}")
                return _safe_json({"uid": uid, "operation": op})
            except Exception as e:
                logger.exception(f"MCP 异常: update_event uid={uid}")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="删除指定 UID 的事件")
        def delete_event(uid: str) -> str:
            logger.info(f"MCP 调用: delete_event uid={uid}")
            try:
                ok = EVENT_SVC.delete(uid)
                logger.info(f"MCP 返回: delete_event -> uid={uid} deleted={ok}")
                return _safe_json({"uid": uid, "deleted": ok})
            except Exception as e:
                logger.exception(f"MCP 异常: delete_event uid={uid}")
                return _safe_json({"error": str(e)})

        # ── 系统 ─────────────────────────────────────────────────

        @mcp.tool(description="返回当前系统配置")
        def get_config() -> str:
            logger.info("MCP 调用: get_config")
            try:
                from services.settings_service import SettingsService
                s = SettingsService()
                cfg = {
                    "software_name": SOFTWARE_NAME,
                    "software_version": SOFTWARE_VERSION,
                    "description": SOFTWARE_DESCRIPTION,
                    "db_path": DEFAULT_DB_PATH,
                    "contacts_count": CONTACT_SVC.count(),
                    "events_count": EVENT_SVC.count(),
                    "mcp_port": int(s.get_setting("mcp_port", "8100")),
                }
                logger.debug(f"MCP 返回: get_config -> {cfg}")
                return _safe_json(cfg)
            except Exception as e:
                logger.exception("MCP 异常: get_config")
                return _safe_json({"error": str(e)})

        @mcp.tool(description="验证 DAV 服务器是否正常工作（PROPFIND + OPTIONS + GET）")
        def dav_health_check(base_url: str = "http://localhost:8080") -> str:
            logger.info(f"MCP 调用: dav_health_check base_url={base_url}")
            results = {}
            try:
                checks = [
                    ("root", "GET", f"{base_url}/", {}),
                    ("options_contacts", "OPTIONS", f"{base_url}/contacts/", {}),
                    ("options_events", "OPTIONS", f"{base_url}/events/", {}),
                ]
                for name, method, url, extra in checks:
                    try:
                        req = urllib.request.Request(url, method=method)
                        with urllib.request.urlopen(req, timeout=5) as r:
                            results[name] = {"status": r.status}
                            if "DAV" in r.headers:
                                results[name]["dav"] = r.headers["DAV"]
                    except Exception as e:
                        logger.warning(f"健康检查 {name} 失败: {e}")
                        results[name] = str(e)

                propfind_body = """<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:resourcetype/>
    <D:getetag/>
    <D:getcontenttype/>
  </D:prop>
</D:propfind>""".encode("utf-8")
                try:
                    import lxml.etree as ET
                    req = urllib.request.Request(f"{base_url}/contacts/", data=propfind_body, method="PROPFIND")
                    req.add_header("Content-Type", "text/xml; charset=utf-8")
                    req.add_header("Depth", "0")
                    with urllib.request.urlopen(req, timeout=5) as r:
                        body = r.read()
                        root = ET.fromstring(body)
                        ns = {"D": "DAV:"}
                        types = root.findall(".//D:resourcetype/D:*", ns)
                        results["propfind_contacts"] = {
                            "status": r.status,
                            "resource_types": [t.tag.split("}")[-1] for t in types]
                        }
                except Exception as e:
                    logger.warning(f"健康检查 propfind 失败: {e}")
                    results["propfind_contacts"] = str(e)

                all_ok = all(
                    isinstance(v, dict) and v.get("status", 0) in (200, 207)
                    for v in results.values()
                )
                results["_healthy"] = all_ok
                logger.info(f"MCP 返回: dav_health_check -> healthy={all_ok}")
                return _safe_json(results)
            except Exception as e:
                logger.exception("MCP 异常: dav_health_check")
                return _safe_json({"error": str(e)})


# ── 独立入口 ──────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PersonalDAV MCP 服务器")
    parser.add_argument("--port", type=int, default=8100, help="SSE 模式端口（默认 8100）")
    args = parser.parse_args()

    srv = MCPServer()
    srv.start(host="127.0.0.1", port=args.port)
    print(f"MCP SSE 服务器已启动: http://127.0.0.1:{args.port}/sse", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.stop()
        print("MCP 服务器已停止", flush=True)
