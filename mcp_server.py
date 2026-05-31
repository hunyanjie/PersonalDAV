"""
MCP（Model Context Protocol）服务器——可嵌入类 + 独立 CLI。

嵌入 GUI：
    from mcp_server import MCPServer
    srv = MCPServer()
    srv.start(port=8100)   # 后台 SSE 服务器
    srv.stop()

独立运行（stdio 调试）：
    python mcp_server.py
"""

import argparse
import json
import threading
import time
import urllib.request
from typing import Any

from mcp.server.fastmcp import FastMCP

from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_DESCRIPTION, DEFAULT_DB_PATH
from services.contact_service import ContactService
from services.event_service import EventService
from network.dav_server import DAVServer

CONTACT_SVC = ContactService()
EVENT_SVC = EventService()


# ── 辅助 ──────────────────────────────────────────────────────────

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


# ── MCPServer 类 ──────────────────────────────────────────────────

class MCPServer:
    """可在后台线程运行的 MCP SSE 服务器"""

    def __init__(self):
        self._mcp = FastMCP("PersonalDAV")
        self._uvicorn_server: Any = None
        self._thread: threading.Thread | None = None
        self._register_tools()

    # ── 生命周期 ──────────────────────────────────────────────────

    def start(self, host: str = "127.0.0.1", port: int = 8100) -> bool:
        """启动 SSE 服务器（后台线程，非阻塞）"""
        if self._uvicorn_server is not None:
            return False
        import uvicorn
        app = self._mcp.sse_app()
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self._uvicorn_server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._uvicorn_server.run, daemon=True)
        self._thread.start()
        time.sleep(0.3)
        return True

    def stop(self) -> None:
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True
            self._uvicorn_server = None
            self._thread = None

    @property
    def is_running(self) -> bool:
        return self._uvicorn_server is not None

    # ── 工具注册 ─────────────────────────────────────────────────

    def _register_tools(self) -> None:
        mcp = self._mcp

        # 服务端管理
        _server_instance: list[DAVServer | None] = [None]

        @mcp.tool(description="启动 DAV 服务器（后台线程运行）")
        def server_start(port: int = 8080) -> str:
            if _server_instance[0] is not None:
                return f"服务器已在端口运行"
            s = DAVServer(port)
            _server_instance[0] = s
            threading.Thread(target=s.start, daemon=True).start()
            time.sleep(0.5)
            return f"DAV 服务器已启动，监听端口 {port}"

        @mcp.tool(description="停止正在运行的 DAV 服务器")
        def server_stop() -> str:
            s = _server_instance[0]
            if s is None:
                return "服务器未运行"
            s.stop()
            _server_instance[0] = None
            return "DAV 服务器已停止"

        @mcp.tool(description="查询 DAV 服务器当前运行状态")
        def server_status() -> str:
            return json.dumps({
                "running": _server_instance[0] is not None,
                "port": 8080 if _server_instance[0] else None
            }, ensure_ascii=False)

        # 联系人
        @mcp.tool(description="列出所有联系人摘要（uid + 姓名）")
        def list_contacts() -> str:
            items = CONTACT_SVC.get_list_data()
            result = []
            for row in items:
                result.append({"uid": row[0], "full_name": row[1], "email": row[2], "phone": row[3]})
            return json.dumps(result, ensure_ascii=False)

        @mcp.tool(description="获取单个联系人的完整 vCard 数据")
        def get_contact(uid: str) -> str:
            raw = CONTACT_SVC.get_by_uid(uid)
            if raw is None:
                return json.dumps({"error": f"联系人 {uid} 不存在"}, ensure_ascii=False)
            summary = _make_contact_summary(uid)
            summary["vcard"] = raw
            return json.dumps(summary, ensure_ascii=False)

        @mcp.tool(description="通过 vCard 数据创建联系人")
        def create_contact(vcard_data: str) -> str:
            uid, op = CONTACT_SVC.add_contact(vcard_data, publish=False)
            if uid is None:
                return json.dumps({"error": op}, ensure_ascii=False)
            return json.dumps({"uid": uid, "operation": op}, ensure_ascii=False)

        @mcp.tool(description="更新联系人（提供 UID 和新的 vCard 数据）")
        def update_contact(uid: str, vcard_data: str) -> str:
            uid, op = CONTACT_SVC.add_contact(vcard_data, force=True, publish=False)
            if uid is None:
                return json.dumps({"error": op}, ensure_ascii=False)
            return json.dumps({"uid": uid, "operation": op}, ensure_ascii=False)

        @mcp.tool(description="删除指定 UID 的联系人")
        def delete_contact(uid: str) -> str:
            ok = CONTACT_SVC.delete(uid)
            # delete() 内部会 publish，但 GUI 订阅的是弱引用，线程安全暂不处理
            return json.dumps({"uid": uid, "deleted": ok}, ensure_ascii=False)

        # 日历事件
        @mcp.tool(description="列出所有事件摘要（uid + 标题 + 起止时间）")
        def list_events() -> str:
            items = EVENT_SVC.get_list_data()
            result = []
            for row in items:
                result.append({"uid": row[0], "summary": row[1], "dtstart": row[2], "dtend": row[3]})
            return json.dumps(result, ensure_ascii=False)

        @mcp.tool(description="获取单个事件的完整 iCalendar 数据")
        def get_event(uid: str) -> str:
            raw = EVENT_SVC.get_by_uid(uid)
            if raw is None:
                return json.dumps({"error": f"事件 {uid} 不存在"}, ensure_ascii=False)
            summary = _make_event_summary(uid)
            summary["ical"] = raw
            return json.dumps(summary, ensure_ascii=False)

        @mcp.tool(description="通过 iCalendar 数据创建事件")
        def create_event(ical_data: str) -> str:
            uid, op = EVENT_SVC.add_event(ical_data, publish=False)
            if uid is None:
                return json.dumps({"error": op}, ensure_ascii=False)
            return json.dumps({"uid": uid, "operation": op}, ensure_ascii=False)

        @mcp.tool(description="更新事件（提供 UID 和新的 iCalendar 数据）")
        def update_event(uid: str, ical_data: str) -> str:
            uid, op = EVENT_SVC.add_event(ical_data, force=True, publish=False)
            if uid is None:
                return json.dumps({"error": op}, ensure_ascii=False)
            return json.dumps({"uid": uid, "operation": op}, ensure_ascii=False)

        @mcp.tool(description="删除指定 UID 的事件")
        def delete_event(uid: str) -> str:
            ok = EVENT_SVC.delete(uid)
            return json.dumps({"uid": uid, "deleted": ok}, ensure_ascii=False)

        # 系统
        @mcp.tool(description="返回当前系统配置")
        def get_config() -> str:
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
            return json.dumps(cfg, ensure_ascii=False)

        @mcp.tool(description="验证 DAV 服务器是否正常工作（PROPFIND + OPTIONS + GET）")
        def dav_health_check(base_url: str = "http://localhost:8080") -> str:
            results = {}
            try:
                req = urllib.request.Request(f"{base_url}/")
                with urllib.request.urlopen(req, timeout=5) as r:
                    results["root"] = r.status
            except Exception as e:
                results["root"] = str(e)

            try:
                req = urllib.request.Request(f"{base_url}/contacts/", method="OPTIONS")
                with urllib.request.urlopen(req, timeout=5) as r:
                    results["options_contacts"] = {"status": r.status, "dav": r.headers.get("DAV", "")}
            except Exception as e:
                results["options_contacts"] = str(e)

            try:
                req = urllib.request.Request(f"{base_url}/events/", method="OPTIONS")
                with urllib.request.urlopen(req, timeout=5) as r:
                    results["options_events"] = {"status": r.status, "dav": r.headers.get("DAV", "")}
            except Exception as e:
                results["options_events"] = str(e)

            try:
                import lxml.etree as ET
                propfind_body = """<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:resourcetype/>
    <D:getetag/>
    <D:getcontenttype/>
  </D:prop>
</D:propfind>""".encode("utf-8")
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
                results["propfind_contacts"] = str(e)

            all_ok = all(
                isinstance(v, dict) and v.get("status", 0) in (200, 207)
                for v in results.values()
            )
            results["_healthy"] = all_ok
            return json.dumps(results, ensure_ascii=False)


# ── 独立入口 ──────────────────────────────────────────────────────
# 独立运行时仍走 stdio 模式，方便 AI 直接调用启动

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
