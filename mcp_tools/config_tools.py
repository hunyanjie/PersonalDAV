import urllib.request
import xml.etree.ElementTree as ET

from config import SOFTWARE_NAME, SOFTWARE_VERSION, SOFTWARE_DESCRIPTION, DEFAULT_DB_PATH
from services.settings_service import SettingsService
from mcp_tools._state import get_contact_svc, get_event_svc
from mcp_tools.helpers import safe_json
from utils.logger import logger


def register(mcp):
    @mcp.tool(description="返回当前系统配置")
    def get_config() -> str:
        logger.info("MCP 调用: get_config")
        try:
            s = SettingsService()
            cfg = {
                "software_name": SOFTWARE_NAME,
                "software_version": SOFTWARE_VERSION,
                "description": SOFTWARE_DESCRIPTION,
                "db_path": DEFAULT_DB_PATH,
                "contacts_count": get_contact_svc().count(),
                "events_count": get_event_svc().count(),
                "mcp_port": int(s.get_setting("mcp_port", "8100")),
            }
            logger.debug(f"MCP 返回: get_config -> {cfg}")
            return safe_json(cfg)
        except Exception as e:
            logger.exception("MCP 异常: get_config")
            return safe_json({"error": str(e)})

    @mcp.tool(description="验证 DAV 服务器是否正常工作（PROPFIND + OPTIONS + GET）")
    def dav_health_check(base_url: str = "http://localhost:8080") -> str:
        logger.info(f"MCP 调用: dav_health_check base_url={base_url}")
        results = {}
        try:
            checks = [
                ("root", "GET", f"{base_url}/", {}),
                ("options_contacts", "OPTIONS", f"{base_url}/contacts/", {}),
                ("options_events", "OPTIONS", f"{base_url}/events/", {}),
                ("options_dav", "OPTIONS", f"{base_url}/dav/", {}),
                ("get_dav", "GET", f"{base_url}/dav/", {}),
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
            return safe_json(results)
        except Exception as e:
            logger.exception("MCP 异常: dav_health_check")
            return safe_json({"error": str(e)})
