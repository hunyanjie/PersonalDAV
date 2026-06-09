"""MCP 工具 HTTP 端到端测试 — 走 SSE 协议调用，验证中间件链路"""
import sys, json, asyncio
sys.path.insert(0, '.')
from services.mcp_server import MCPServer
from utils.logger import logger
import logging
logger.setLevel(logging.WARNING)

MCP_PORT = 8101
srv = MCPServer()

async def test():
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    assert srv.start(host="127.0.0.1", port=MCP_PORT), "MCP server start failed"
    results = []

    def r(name, ok, detail=""):
        tag = "OK" if ok else "FAIL"
        results.append(f"  {name}: {tag}  {detail}")

    async def test_tools(session, label):
        tools = await session.list_tools()
        r(f"{label}: list_tools", True, f'{len(tools.tools)} 个')

        ok, d = await _call(session, "list_contacts", {})
        r(f"{label}: list_contacts", ok, f'{len(d)} 条')

        ok, d = await _call(session, "create_contact", {"vcard_data":
            "BEGIN:VCARD\nVERSION:3.0\nUID:mcp-http-c\nFN:HTTP Test\nEMAIL:http@test.com\nEND:VCARD",
            "confirmed": True})
        r(f"{label}: create_contact", ok, str(d))

        ok, d = await _call(session, "get_contact", {"uid": "mcp-http-c"})
        r(f"{label}: get_contact", ok, f'名称={d.get("full_name","?")}')

        ok, d = await _call(session, "update_contact", {"uid": "mcp-http-c", "vcard_data":
            "BEGIN:VCARD\nVERSION:3.0\nUID:mcp-http-c\nFN:HTTP Updated\nEMAIL:upd@test.com\nEND:VCARD",
            "confirmed": True})
        r(f"{label}: update_contact", ok, str(d))

        ok, d = await _call(session, "delete_contact", {"uid": "mcp-http-c", "confirmed": True})
        r(f"{label}: delete_contact", ok, f'deleted={d.get("deleted")}')

        ical = 'BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//EN\nBEGIN:VEVENT\nUID:mcp-http-e\nSUMMARY:HTTP Event\nDTSTART:20260601T000000\nDTEND:20260601T010000\nEND:VEVENT\nEND:VCALENDAR'
        ok, d = await _call(session, "create_event", {"ical_data": ical, "confirmed": True})
        r(f"{label}: create_event", ok, str(d))

        ok, d = await _call(session, "get_event", {"uid": "mcp-http-e"})
        r(f"{label}: get_event", ok, f'摘要={d.get("summary","?")}')

        ical2 = 'BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//EN\nBEGIN:VEVENT\nUID:mcp-http-e\nSUMMARY:HTTP Updated\nDTSTART:20260601T000000\nDTEND:20260601T020000\nEND:VEVENT\nEND:VCALENDAR'
        ok, d = await _call(session, "update_event", {"uid": "mcp-http-e", "ical_data": ical2, "confirmed": True})
        r(f"{label}: update_event", ok, str(d))

        ok, d = await _call(session, "delete_event", {"uid": "mcp-http-e", "confirmed": True})
        r(f"{label}: delete_event", ok, f'deleted={d.get("deleted")}')

        ok, d = await _call(session, "get_config", {})
        r(f"{label}: get_config", ok, f'contacts={d.get("contacts_count")}')

        ok, d = await _call(session, "server_status", {})
        r(f"{label}: server_status", ok, f'running={d.get("running")}')

    async def _call(session, name, args):
        result = await session.call_tool(name, args)
        if not result.content:
            return False, {"error": "empty response"}
        try:
            data = json.loads(result.content[0].text)
            return ('error' not in data), data
        except (json.JSONDecodeError, IndexError, AttributeError):
            return False, {"error": "parse failed", "_raw": getattr(result.content[0], 'text', '')}

    # 测试 1: 无密码
    async with sse_client(f"http://127.0.0.1:{MCP_PORT}/sse") as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await test_tools(session, "无密码")

    # 测试 2: 开启密码
    from services.auth_service import AuthService
    auth_svc = AuthService()
    password = "test-password-123"
    auth_svc.set_password(password)
    token = auth_svc.get_mcp_token()

    async with sse_client(f"http://127.0.0.1:{MCP_PORT}/sse",
                          headers={"Authorization": f"Bearer {token}"}) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            await test_tools(session, "有密码")

    auth_svc.clear_password()
    srv.stop()
    print("\n".join(results))
    ok = all("FAIL" not in l for l in results)
    print(f"\nHTTP MCP 工具测试{'通过' if ok else '失败'}")
    sys.exit(0 if ok else 1)

asyncio.run(test())
