"""Test all MCP tools"""
import sys, json, asyncio, time
sys.path.insert(0, '.')
from services.mcp_server import MCPServer
from utils.logger import logger
import logging
logger.setLevel(logging.WARNING)

srv = MCPServer()

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

    results.append("=== 事件工具 ===")
    data, ok = await call('list_events', {})
    r('list_events', ok, f'{len(data)} 条')

    ical = 'BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//EN\nBEGIN:VEVENT\nUID:mcp-test-e\nSUMMARY:Test Event\nDTSTART:20260601T000000\nDTEND:20260601T010000\nEND:VEVENT\nEND:VCALENDAR'
    data, ok = await call('create_event', {'ical_data': ical})
    r('create_event', ok, str(data))

    data, ok = await call('get_event', {'uid': 'mcp-test-e'})
    r('get_event(新)', ok, f'摘要={data.get("summary","?")}')

    ical2 = 'BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//EN\nBEGIN:VEVENT\nUID:mcp-test-e\nSUMMARY:Updated Event\nDTSTART:20260601T000000\nDTEND:20260601T020000\nEND:VEVENT\nEND:VCALENDAR'
    data, ok = await call('update_event', {'uid': 'mcp-test-e', 'ical_data': ical2})
    r('update_event', ok, str(data))

    data, ok = await call('delete_event', {'uid': 'mcp-test-e'})
    r('delete_event', ok, f'deleted={data.get("deleted")}')

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
        print('\n所有 16 个 MCP 工具测试通过')

asyncio.run(test())
