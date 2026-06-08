from mcp_tools._state import get_contact_svc
from mcp_tools.helpers import safe_json, check_readonly, make_contact_summary
from utils.logger import logger


def register(mcp):
    @mcp.tool(description="列出所有联系人摘要（uid + 姓名）")
    def list_contacts() -> str:
        logger.info("MCP 调用: list_contacts")
        try:
            items = get_contact_svc().get_list_data()
            result = []
            for row in items:
                result.append({"uid": row[0], "full_name": row[1], "email": row[2], "phone": row[3]})
            logger.info(f"MCP 返回: list_contacts -> {len(result)} 条")
            return safe_json(result)
        except Exception as e:
            logger.exception("MCP 异常: list_contacts")
            return safe_json({"error": str(e)})

    @mcp.tool(description="获取单个联系人的完整 vCard 数据")
    def get_contact(uid: str) -> str:
        logger.info(f"MCP 调用: get_contact uid={uid}")
        try:
            raw = get_contact_svc().get_by_uid(uid)
            if raw is None:
                logger.warning(f"MCP 返回: get_contact -> 联系人 {uid} 不存在")
                return safe_json({"error": f"联系人 {uid} 不存在"})
            summary = make_contact_summary(uid)
            summary["vcard"] = raw
            logger.info(f"MCP 返回: get_contact -> {uid} ({summary.get('full_name', '')})")
            return safe_json(summary)
        except Exception as e:
            logger.exception(f"MCP 异常: get_contact uid={uid}")
            return safe_json({"error": str(e)})

    @mcp.tool(description="通过 vCard 数据创建联系人")
    def create_contact(vcard_data: str) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: create_contact vcard_data({len(vcard_data)}B)")
        try:
            uid, op = get_contact_svc().add_contact(vcard_data, publish=False)
            if uid is None:
                logger.error(f"MCP 返回: create_contact -> 失败: {op}")
                return safe_json({"error": op})
            logger.info(f"MCP 返回: create_contact -> uid={uid} op={op}")
            return safe_json({"uid": uid, "operation": op})
        except Exception as e:
            logger.exception("MCP 异常: create_contact")
            return safe_json({"error": str(e)})

    @mcp.tool(description="更新联系人（提供 UID 和新的 vCard 数据）")
    def update_contact(uid: str, vcard_data: str) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: update_contact uid={uid} vcard_data({len(vcard_data)}B)")
        try:
            uid, op = get_contact_svc().add_contact(vcard_data, force=True, publish=False)
            if uid is None:
                logger.error(f"MCP 返回: update_contact -> 失败: {op}")
                return safe_json({"error": op})
            logger.info(f"MCP 返回: update_contact -> uid={uid} op={op}")
            return safe_json({"uid": uid, "operation": op})
        except Exception as e:
            logger.exception(f"MCP 异常: update_contact uid={uid}")
            return safe_json({"error": str(e)})

    @mcp.tool(description="删除指定 UID 的联系人")
    def delete_contact(uid: str) -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: delete_contact uid={uid}")
        try:
            ok = get_contact_svc().delete(uid)
            logger.info(f"MCP 返回: delete_contact -> uid={uid} deleted={ok}")
            return safe_json({"uid": uid, "deleted": ok})
        except Exception as e:
            logger.exception(f"MCP 异常: delete_contact uid={uid}")
            return safe_json({"error": str(e)})

    @mcp.tool(description="通过结构化参数创建联系人（姓名、邮箱、电话）")
    def create_contact_v2(full_name: str, email: str = "", phone: str = "") -> str:
        if check_readonly():
            return safe_json({"error": "只读模式下不支持此操作"})
        logger.info(f"MCP 调用: create_contact_v2 name={full_name} email={email} phone={phone}")
        try:
            vcard = f"BEGIN:VCARD\nVERSION:3.0\nFN:{full_name}\n"
            if email:
                vcard += f"EMAIL:{email}\n"
            if phone:
                vcard += f"TEL:{phone}\n"
            vcard += "END:VCARD"
            uid, op = get_contact_svc().add_contact(vcard, publish=False)
            if uid is None:
                logger.error(f"MCP 返回: create_contact_v2 -> 失败: {op}")
                return safe_json({"error": op})
            logger.info(f"MCP 返回: create_contact_v2 -> uid={uid} op={op}")
            return safe_json({"uid": uid, "operation": op})
        except Exception as e:
            logger.exception("MCP 异常: create_contact_v2")
            return safe_json({"error": str(e)})
