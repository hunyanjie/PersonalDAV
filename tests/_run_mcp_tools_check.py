"""Test all MCP tools (v3.1: new search + analysis + safety tools)"""
import sys, json, asyncio, time
sys.path.insert(0, '.')
from services.mcp_server import MCPServer
from utils.logger import logger
import logging
logger.setLevel(logging.WARNING)

srv = MCPServer()
srv._register_tools()

async def test():
    mcp = srv._mcp
    errors = []
    results = []

    async def call(name, args):
        content, _ = await mcp.call_tool(name, args)
        text = content[0].text
        try:
            data = json.loads(text)
            ok = 'error' not in data or data.get('error') is None
            if not ok:
                errors.append(f'{name}: {data.get("error")}')
            return data, ok
        except json.JSONDecodeError:
            return {"_raw": text}, True

    def r(name, ok, detail):
        if isinstance(detail, dict):
            detail = detail.get('_raw', str(detail))
        tag = "OK" if ok else "FAIL"
        results.append(f"  {name}: {tag}  {detail}")

    results.append("=== 系统工具 ===")
    data, ok = await call('get_config', {})
    r('get_config', ok, f'{data.get("contacts_count")} 联系人, {data.get("events_count")} 事件')

    data, ok = await call('server_status', {})
    r('server_status', ok, f'running={data.get("running")}')

    results.append("=== 联系人工具 ===")
    data, ok = await call('list_contacts', {})
    r('list_contacts', ok, f'{len(data)} 条')

    if data and len(data) > 0:
        uid = data[0]['uid']
        data, ok = await call('get_contact', {'uid': uid})
        r('get_contact', ok, f'uid={uid}')

    data, ok = await call('create_contact', {'vcard_data': 'BEGIN:VCARD\nVERSION:3.0\nUID:mcp-test-c\nFN:MCP Test\nEMAIL:test@mcp.com\nEND:VCARD'})
    r('create_contact', ok, str(data))

    data, ok = await call('get_contact', {'uid': 'mcp-test-c'})
    r('get_contact(新)', ok, f'名称={data.get("full_name", "?")}')

    data, ok = await call('update_contact', {'uid': 'mcp-test-c', 'vcard_data': 'BEGIN:VCARD\nVERSION:3.0\nUID:mcp-test-c\nFN:MCP Updated\nEMAIL:upd@mcp.com\nEND:VCARD'})
    r('update_contact', ok, str(data))

    data, ok = await call('delete_contact', {'uid': 'mcp-test-c'})
    r('delete_contact', ok, f'deleted={data.get("deleted")}')

    results.append("=== v3.1 搜索工具(关键词) ===")
    data, ok = await call('search_contacts', {'query': 'test', 'limit': 5})
    r('search_contacts', ok, f'{len(data)} 条')

    data, ok = await call('search_events', {'query': 'test', 'limit': 5})
    r('search_events', ok, f'{len(data)} 条')

    results.append("=== v3.1 安全机制 ===")
    data, ok = await call('create_contact', {'vcard_data': 'BEGIN:VCARD\nVERSION:3.0\nUID:safe-test\nFN:Safe Test\nEND:VCARD', 'confirmed': True})
    r('create_contact(已确认)', ok, str(data))

    data2, ok2 = await call('delete_contact', {'uid': 'safe-test'})
    r('delete_contact(已确认)', ok2, str(data2))

    results.append("=== 事件工具 ===")
    data, ok = await call('list_events', {})
    r('list_events', ok, f'{len(data)} 条')

    ical = 'BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//EN\nBEGIN:VEVENT\nUID:mcp-test-e\nSUMMARY:Test Event\nDTSTART:20260601T000000\nDTEND:20260601T010000\nEND:VEVENT\nEND:VCALENDAR'
    data, ok = await call('create_event', {'ical_data': ical, 'confirmed': True})
    r('create_event', ok, str(data))

    data, ok = await call('get_event', {'uid': 'mcp-test-e'})
    r('get_event(新)', ok, f'摘要={data.get("summary","?")}')

    ical2 = 'BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//EN\nBEGIN:VEVENT\nUID:mcp-test-e\nSUMMARY:Updated Event\nDTSTART:20260601T000000\nDTEND:20260601T020000\nEND:VEVENT\nEND:VCALENDAR'
    data, ok = await call('update_event', {'uid': 'mcp-test-e', 'ical_data': ical2, 'confirmed': True})
    r('update_event', ok, str(data))

    data, ok = await call('delete_event', {'uid': 'mcp-test-e', 'confirmed': True})
    r('delete_event', ok, f'deleted={data.get("deleted")}')

    results.append("=== v3.1 冲突检测 ===")
    data, ok = await call('detect_contact_duplicates', {'threshold': 0.6})
    r('detect_contact_duplicates', ok, f'{len(data)} 组')

    data, ok = await call('detect_event_conflicts', {'date_from': '20260101T000000', 'date_to': '20270101T000000'})
    r('detect_event_conflicts', ok, f'{len(data)} 组')

    data, ok = await call('detect_upcoming_conflicts', {'days': 365})
    r('detect_upcoming_conflicts', ok, f'{len(data)} 组')

    results.append("=== 服务端管理工具 ===")
    data, ok = await call('server_start', {'port': 8099})
    r('server_start', ok, str(data))

    time.sleep(1)

    data, ok = await call('server_status', {})
    r('server_status(启动后)', ok, f'running={data.get("running")}')

    data, ok = await call('dav_health_check', {'base_url': 'http://localhost:8099'})
    r('dav_health_check', ok, f'healthy={data.get("_healthy")}')

    data, ok = await call('server_stop', {})
    r('server_stop', ok, str(data))

    for line in results:
        print(line)

    if errors:
        print(f'\n!!! {len(errors)} 个工具失败:')
        for e in errors:
            print(f'  - {e}')
    else:
        print(f'\n所有 {len(results)} 个 MCP 工具测试通过')

asyncio.run(test())
