"""Test v3.1 features: search tools, analysis tools, safety mechanism"""
import sys, json, asyncio
sys.path.insert(0, '.')
from services.mcp_server import MCPServer
from services.embeddings import EmbeddingService, list_available_models
from mcp_tools.helpers import check_safety
from utils.logger import logger
import logging
logger.setLevel(logging.WARNING)

srv = MCPServer()
srv._register_tools()

async def test():
    mcp = srv._mcp
    errors = []
    passed = 0
    failed = 0

    async def call(name, args):
        content, _ = await mcp.call_tool(name, args)
        text = content[0].text
        try:
            data = json.loads(text)
            return data
        except json.JSONDecodeError:
            return {"_raw": text}

    def check(name, ok, msg=""):
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"  OK  {name}  {msg}")
        else:
            failed += 1
            print(f"  FAIL {name}  {msg}")
            errors.append(name)

    # ── 1. EmbeddingService 基础 ──
    print("\n=== 1. EmbeddingService ===")
    svc = EmbeddingService()
    check("provider defaults to keyword", svc.provider_name == "keyword", svc.provider_name)
    models = list_available_models()
    print(f"  INFO available models: {models}")
    check("list_available_models returns list", isinstance(models, list))

    # ── 2. 搜索工具(关键词模式) ──
    print("\n=== 2. MCP 搜索工具(关键词) ===")
    data = await call('search_contacts', {'query': '', 'limit': 5})
    check("search_contacts empty query", isinstance(data, list), f"{len(data)} 条")

    data = await call('search_contacts', {'query': 'test', 'limit': 5})
    check("search_contacts with query", isinstance(data, list), f"{len(data)} 条")

    data = await call('search_events', {'query': '', 'limit': 5})
    check("search_events empty query", isinstance(data, list), f"{len(data)} 条")

    data = await call('search_events', {'query': 'birthday', 'limit': 5})
    check("search_events with query", isinstance(data, list), f"{len(data)} 条")

    # ── 3. 冲突检测工具 ──
    print("\n=== 3. 冲突检测 ===")
    data = await call('detect_contact_duplicates', {'threshold': 0.6})
    check("detect_contact_duplicates", isinstance(data, dict), f"{len(data.get('duplicates',[]))} 组")

    data = await call('detect_event_conflicts', {'date_from': '20260101T000000', 'date_to': '20270101T000000'})
    check("detect_event_conflicts", isinstance(data, dict), f"{len(data.get('conflicts',[]))} 组")

    data = await call('detect_upcoming_conflicts', {'days': 365})
    check("detect_upcoming_conflicts", isinstance(data, dict), f"{len(data.get('conflicts',[]))} 组")

    # ── 4. 安全机制 ──
    print("\n=== 4. 安全机制 ===")
    # check_safety without confirmed should warn
    result = check_safety("delete_contact", False)
    check("check_safety unconfirmed blocks", "确认要求" in result or "confirm" in result, result[:60])

    result = check_safety("delete_contact", True)
    check("check_safety confirmed passes", result is None, "passed")

    # create_contact without confirmed in safe mode - test that confirmed param is accepted
    data = await call('create_contact', {
        'vcard_data': 'BEGIN:VCARD\nVERSION:3.0\nUID:v31-safety-test\nFN:Safety Test\nEND:VCARD',
        'confirmed': True
    })
    check("create_contact with confirmed", isinstance(data, dict), str(data.get("uid", "")))

    data = await call('delete_contact', {'uid': 'v31-safety-test', 'confirmed': True})
    check("delete_contact with confirmed", isinstance(data, dict), str(data.get("deleted", "")))

    # ── 总结 ──
    print(f"\n{'='*40}")
    print(f"通过: {passed}, 失败: {failed}")
    if errors:
        print(f"失败工具: {', '.join(errors)}")
        sys.exit(1)
    else:
        print("v3.1 所有功能测试通过 ✓")

asyncio.run(test())
