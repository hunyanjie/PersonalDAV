"""
检查更新：从 GitHub Releases 获取版本信息
"""
from config import SOFTWARE_VERSION
from utils.logger import logger
import json
import threading

GITHUB_API = "https://api.github.com/repos/hunyanjie/PersonalDAV/releases?per_page=20"
DOWNLOAD_URL = "https://github.com/hunyanjie/PersonalDAV/releases/latest"


def check_update(timeout=5) -> dict:
    """
    检查是否有新版本
    返回:
      has_update: bool  是否有更新
      latest: str       最新版本号
      current: str      当前版本号
      url: str          下载地址
      releases: list    所有比当前新的 release [{version, body}, ...]
    """
    result = {"has_update": False, "latest": "", "current": SOFTWARE_VERSION,
              "url": DOWNLOAD_URL, "releases": []}
    try:
        import urllib.request
        req = urllib.request.Request(
            GITHUB_API,
            headers={"User-Agent": "PersonalDAV", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        current = SOFTWARE_VERSION
        newer = []
        latest_ver = ""
        for item in data:
            tag = item.get("tag_name", "").lstrip("v")
            body = item.get("body", "")
            if not tag:
                continue
            if _compare_versions(tag, current) > 0:
                newer.append({"version": tag, "body": body or "(无更新说明)"})
            if not latest_ver or _compare_versions(tag, latest_ver) > 0:
                latest_ver = tag

        newer.sort(key=lambda x: [int(p) for p in x["version"].split(".")])

        if newer:
            result["has_update"] = True
            result["latest"] = latest_ver
            result["releases"] = newer
    except Exception as e:
        logger.debug(f"检查更新失败: {e}")

    return result


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
    """在后台线程检查更新，完成后通过 after(0) 回到主线程回调"""
    def _run():
        result = check_update(timeout)
        if callback:
            callback(result)
    threading.Thread(target=_run, daemon=True).start()
