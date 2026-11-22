"""回收站保留天数解析与自定义清理测试。"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from tests._test_db import init_temp_db
from services.settings_service import SettingsService
from services.trash_service import TrashService


class TestTrashRetention(unittest.TestCase):
    def setUp(self):
        init_temp_db(prefix="pdav-trash-test-")
        SettingsService._instance = None
        SettingsService._cache.clear()
        TrashService._manifest = None
        self.tmp = tempfile.TemporaryDirectory(prefix="pdav-trash-dir-")
        self.addCleanup(self.tmp.cleanup)
        self.patcher = patch.object(TrashService, "_get_trash_dir", return_value=self.tmp.name)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_fixed_days(self):
        SettingsService().set_setting("trash_retention_days", "7")
        self.assertEqual(TrashService._retention_days(), 7)

    def test_custom_days(self):
        SettingsService().set_setting("trash_retention_days", "custom")
        SettingsService().set_setting("trash_retention_custom", "3")
        self.assertEqual(TrashService._retention_days(), 3)

    def test_invalid_value_falls_back_to_30(self):
        SettingsService().set_setting("trash_retention_days", "custom")
        SettingsService().set_setting("trash_retention_custom", "")
        self.assertEqual(TrashService._retention_days(), 30)

    def test_purge_uses_custom_days(self):
        SettingsService().set_setting("trash_retention_days", "custom")
        SettingsService().set_setting("trash_retention_custom", "3")
        old_uuid = "old-item"
        new_uuid = "new-item"
        os.makedirs(os.path.join(self.tmp.name, old_uuid))
        os.makedirs(os.path.join(self.tmp.name, new_uuid))
        TrashService._manifest = [
            {"uuid": old_uuid, "original_path": "/old.txt", "name": "old.txt",
             "is_dir": False, "size": 1,
             "deleted_at": (datetime.now() - timedelta(days=5)).isoformat()},
            {"uuid": new_uuid, "original_path": "/new.txt", "name": "new.txt",
             "is_dir": False, "size": 1,
             "deleted_at": (datetime.now() - timedelta(days=1)).isoformat()},
        ]
        TrashService._purge_expired()
        uuids = [item["uuid"] for item in TrashService.list_items()]
        self.assertEqual(uuids, [new_uuid])
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, old_uuid)))
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, new_uuid)))


if __name__ == "__main__":
    unittest.main()
