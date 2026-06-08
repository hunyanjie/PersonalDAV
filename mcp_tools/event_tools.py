from mcp_tools._state import get_event_svc
from mcp_tools.helpers import safe_json, check_readonly, make_event_summary
from utils.logger import logger


def register(mcp):
    @mcp.tool(description="列出所有事件摘要（uid + 标题 + 起止时间）")
    def list_events() -> str:
        logger.info("MCP 调用: list_events")
        try:
            items = get_event_svc().get_list_data()
            result = []
            for row in items:
                result.append({
                    "uid": row[0],
                    "summary": row[1],
                    "dtstart": row[2],
                    "dtend": row[3] if len(row) > 3 else "",
                })
            logger.info(f"MCP 返回: list_events -> {len(result)} 条")
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: list_events")
            return safe_json({"error": str(e)})

    @mcp.tool(description="获取单个事件的完整 iCalendar 数据")
    def get_event(uid: str) -> str:
        logger.info(f"MCP 调用: get_event uid={uid}")
        try:
            raw = get_event_svc().get_by_uid(uid)
            if raw is None:
                logger.warning(f"MCP 返回: get_event -> 事件 {uid} 不存在")
                return safe_json({"error": f"事件 {uid} 不存在"})
            summary = make_event_summary(uid)
            summary["ical"] = raw
            logger.info(f"MCP 返回: get_event -> {uid} ({summary.get('summary', '')})")
            return safe_json(summary)
        except Exception as e:
            logger.exception(f"MCP 异常: get_event uid={uid}")
            return safe_json({"error": str(e)})

    @mcp.tool(description="通过 iCalendar 数据创建事件")
    def create_event(ical_data: str) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: create_event ical_data({len(ical_data)}B)")
        try:
            uid, op = get_event_svc().add_event(ical_data, publish=False)
            if uid is None:
                logger.error(f"MCP 返回: create_event -> 失败: {op}")
                return safe_json({"error": op})
            logger.info(f"MCP 返回: create_event -> uid={uid} op={op}")
            return safe_json({"uid": uid, "operation": op})
        except Exception as e:
            logger.exception("MCP 异常: create_event")
            return safe_json({"error": str(e)})

    @mcp.tool(description="更新事件（提供 UID 和新的 iCalendar 数据）")
    def update_event(uid: str, ical_data: str) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: update_event uid={uid} ical_data({len(ical_data)}B)")
        try:
            uid, op = get_event_svc().add_event(ical_data, force=True, publish=False)
            if uid is None:
                logger.error(f"MCP 返回: update_event -> 失败: {op}")
                return safe_json({"error": op})
            logger.info(f"MCP 返回: update_event -> uid={uid} op={op}")
            return safe_json({"uid": uid, "operation": op})
        except Exception as e:
            logger.exception(f"MCP 异常: update_event uid={uid}")
            return safe_json({"error": str(e)})

    @mcp.tool(description="删除指定 UID 的事件")
    def delete_event(uid: str) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: delete_event uid={uid}")
        try:
            ok = get_event_svc().delete(uid)
            logger.info(f"MCP 返回: delete_event -> uid={uid} deleted={ok}")
            return safe_json({"uid": uid, "deleted": ok})
        except Exception as e:
            logger.exception(f"MCP 异常: delete_event uid={uid}")
            return safe_json({"error": str(e)})
