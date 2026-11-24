"""服务器统计：联系人/日程、所有挂载点文件、回收站与趋势。"""

import os
import shutil
from datetime import date, datetime, timedelta

from database.db_manager import Database
from services.contact_service import ContactService
from services.event_service import EventService
from services.file_mount_service import FileMountService
from services.settings_service import SettingsService
from services.trash_service import TrashService

_MB = 1024 * 1024


class StatsService:
    def collect(self) -> dict:
        today = date.today()
        yesterday = today - timedelta(days=1)
        db = Database()

        contacts_count = ContactService().count()
        events_count = EventService().count()

        mounts = FileMountService().get_mounts()
        if not mounts:
            dav_root = SettingsService().get_setting("dav_root", "./dav_root")
            if dav_root:
                mounts = [{"name": "dav_root", "path": dav_root}]

        file_count = 0
        total_size = 0
        today_files = 0
        yesterday_files = 0
        mount_stats = []
        quota_total = 0.0
        quota_free = 0.0
        any_over_quota = False
        volumes: dict[str, dict[str, float]] = {}

        for mount in mounts:
            root = mount.get("path") or ""
            used_bytes, count, today_count, yesterday_count = self._walk_usage(root, today, yesterday)
            file_count += count
            total_size += used_bytes
            today_files += today_count
            yesterday_files += yesterday_count

            quota = self._positive_quota(mount.get("quota_mb"))
            if quota:
                capacity = quota * _MB
                free = max(0.0, capacity - used_bytes)
                over = used_bytes > capacity
                quota_total += capacity
                quota_free += free
                any_over_quota = any_over_quota or over
                mount_stats.append({
                    "name": mount.get("name", ""),
                    "path": root,
                    "used_mb": round(used_bytes / _MB, 2),
                    "quota_mb": round(quota, 2),
                    "total_mb": round(capacity / _MB, 2),
                    "free_mb": round(free / _MB, 2),
                    "over_quota": over,
                })
                continue

            volume = None
            if root and os.path.isdir(root):
                try:
                    usage = shutil.disk_usage(root)
                    key = self._volume_key(root)
                    volume = volumes.setdefault(key, {"total": 0.0, "used": 0.0, "free": 0.0, "managed": 0.0})
                    volume["total"] = usage.total
                    volume["used"] = usage.used
                    volume["free"] = usage.free
                    volume["managed"] += used_bytes
                except OSError:
                    volume = None
            mount_stats.append({
                "name": mount.get("name", ""),
                "path": root,
                "used_mb": round(used_bytes / _MB, 2),
                "quota_mb": None,
                "total_mb": round(volume["total"] / _MB, 2) if volume else None,
                "free_mb": round(volume["free"] / _MB, 2) if volume else None,
                "over_quota": False,
            })

        trash_size = sum(int(item.get("size") or 0) for item in TrashService.list_items())
        total_size += trash_size

        other_used = sum(max(0.0, v["used"] - v["managed"]) for v in volumes.values())
        disk_total = quota_total + sum(v["total"] for v in volumes.values())
        disk_free = quota_free + sum(v["free"] for v in volumes.values())
        if disk_total <= 0:
            # 没有任何可用挂载点时，仍然显示当前工作目录所在磁盘容量。
            disk_total = self._disk_total_mb([]) * _MB
            disk_free = 0.0
        if not any_over_quota:
            any_over_quota = total_size > disk_total > 0

        return {
            "contacts_count": contacts_count,
            "events_count": events_count,
            "files_count": file_count,
            "disk_used_mb": round(total_size / _MB, 2),
            "disk_total_mb": round(disk_total / _MB, 2),
            "disk_other_mb": round(other_used / _MB, 2),
            "disk_free_mb": round(disk_free / _MB, 2),
            "disk_over_quota": any_over_quota,
            "mount_stats": mount_stats,
            "trends": {
                "contacts_count": self._trend(db, "contacts", today, yesterday),
                "events_count": self._trend(db, "events", today, yesterday),
                "files_count": f"{today_files - yesterday_files:+d}",
                "disk_used_mb": "",
            },
        }

    @staticmethod
    def _positive_quota(value) -> float | None:
        try:
            quota = float(value)
        except (TypeError, ValueError):
            return None
        return quota if quota > 0 else None

    @staticmethod
    def _volume_key(path: str) -> str:
        """同一块磁盘上的不同挂载点只计算一次容量。"""
        abs_path = os.path.abspath(path)
        if os.name == "nt":
            return os.path.splitdrive(abs_path)[0].upper() or abs_path
        try:
            return str(os.stat(abs_path).st_dev)
        except OSError:
            return abs_path

    @staticmethod
    def _walk_usage(root: str, today: date, yesterday: date) -> tuple[int, int, int, int]:
        """返回 (字节数, 文件数, 今日修改数, 昨日修改数)。"""
        if not root or not os.path.isdir(root):
            return 0, 0, 0, 0
        total = 0
        count = 0
        today_count = 0
        yesterday_count = 0
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                try:
                    stat = os.stat(file_path)
                    total += stat.st_size
                    count += 1
                    modified = datetime.fromtimestamp(stat.st_mtime).date()
                    if modified == today:
                        today_count += 1
                    elif modified == yesterday:
                        yesterday_count += 1
                except OSError:
                    pass
        return total, count, today_count, yesterday_count

    @staticmethod
    def _disk_total_mb(roots: list[str]) -> float:
        """返回主挂载点所在磁盘的总容量。

        第一个挂载点可能已经从磁盘上移除（例如项目从 D: 搬到 C:），
        此时继续用它会让容量变成 0，前端就会把占用率误显示成 100%。
        因此按顺序找第一个真实存在的目录。
        """
        for root in roots:
            if not root or not os.path.isdir(root):
                continue
            try:
                return shutil.disk_usage(root).total / _MB
            except OSError:
                continue
        try:
            return shutil.disk_usage(os.getcwd()).total / _MB
        except OSError:
            return 0.0

    @staticmethod
    def _trend(db: Database, table: str, today: date, yesterday: date) -> str:
        """按创建日期比较今天与昨天新增数量。表名由内部常量传入。"""
        try:
            row = db.query_one(
                f"SELECT COUNT(*) FROM {table} WHERE date(created_at)=?",
                (today.isoformat(),),
            )
            today_count = row[0] if row else 0
            row = db.query_one(
                f"SELECT COUNT(*) FROM {table} WHERE date(created_at)=?",
                (yesterday.isoformat(),),
            )
            yesterday_count = row[0] if row else 0
            return f"{today_count - yesterday_count:+d}"
        except Exception:
            return ""
