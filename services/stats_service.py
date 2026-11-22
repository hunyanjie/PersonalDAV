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
        roots = [m["path"] for m in mounts if m.get("path")]
        if not roots:
            dav_root = SettingsService().get_setting("dav_root", "./dav_root")
            if dav_root:
                roots = [dav_root]

        file_count = 0
        total_size = 0
        today_files = 0
        yesterday_files = 0
        for root in roots:
            if not os.path.isdir(root):
                continue
            for dirpath, _, filenames in os.walk(root):
                for filename in filenames:
                    file_path = os.path.join(dirpath, filename)
                    try:
                        stat = os.stat(file_path)
                        total_size += stat.st_size
                        file_count += 1
                        modified = datetime.fromtimestamp(stat.st_mtime).date()
                        if modified == today:
                            today_files += 1
                        elif modified == yesterday:
                            yesterday_files += 1
                    except OSError:
                        pass

        trash_size = sum(int(item.get("size") or 0) for item in TrashService.list_items())
        total_size += trash_size

        primary_root = roots[0] if roots else "."
        try:
            disk_total = shutil.disk_usage(primary_root).total / _MB
        except OSError:
            disk_total = 0.0

        return {
            "contacts_count": contacts_count,
            "events_count": events_count,
            "files_count": file_count,
            "disk_used_mb": round(total_size / _MB, 2),
            "disk_total_mb": round(disk_total, 2),
            "trends": {
                "contacts_count": self._trend(db, "contacts", today, yesterday),
                "events_count": self._trend(db, "events", today, yesterday),
                "files_count": f"{today_files - yesterday_files:+d}",
                "disk_used_mb": "",
            },
        }

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
