"""
检查更新：从 GitHub Releases 获取最新版本号
"""
from config import SOFTWARE_VERSION
from utils.logger import logger
import json
import threading

GITHUB_API = "https://api.github.com/repos/hunyanjie/PersonalDAV/releases/latest"
DOWNLOAD_URL = "https://github.com/hunyanjie/PersonalDAV/releases/latest"


def check_update(timeout=5) -> dict:
    """
    检查是否有新版本
    返回: {"has_update": bool, "latest": str, "current": str, "url": str, "body": str}
    """
    try:
        import urllib.request
        req = urllib.request.Request(
            GITHUB_API,
            headers={"User-Agent": "PersonalDAV", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        latest = data.get("tag_name", "").lstrip("v")
        body = data.get("body", "")
        current = SOFTWARE_VERSION
        has_update = _compare_versions(latest, current) > 0
        return {
            "has_update": has_update,
            "latest": latest,
            "current": current,
            "url": DOWNLOAD_URL,
            "body": body,
        }
    except Exception as e:
        logger.debug(f"检查更新失败: {e}")
        return {"has_update": False, "latest": "", "current": SOFTWARE_VERSION, "url": "", "body": ""}


def _compare_versions(v1: str, v2: str) -> int:
    """比较版本号，v1>v2 返回正数，v1<v2 返回负数"""
    try:
        p1 = [int(x) for x in v1.split(".")]
        p2 = [int(x) for x in v2.split(".")]
        max_len = max(len(p1), len(p2))
        p1 += [0] * (max_len - len(p1))
        p2 += [0] * (max_len - len(p2))
        for a, b in zip(p1, p2):
            if a != b:
                return a - b
        return 0
    except (ValueError, AttributeError):
        return 0


def check_update_async(callback, timeout=5):
    """在后台线程检查更新，完成后回调 callback(result_dict)"""
    def _run():
        result = check_update(timeout)
        if callback:
            callback(result)
    threading.Thread(target=_run, daemon=True).start()
