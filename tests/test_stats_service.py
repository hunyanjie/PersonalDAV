"""概览磁盘容量计算：失效挂载点不能把总容量变成 0。"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from services.file_mount_service import FileMountService
from services.stats_service import StatsService
from tests._test_db import init_temp_db

_MB = 1024 * 1024


class TestStatsDiskTotal(unittest.TestCase):
    def test_skips_missing_mount(self):
        valid = tempfile.mkdtemp(prefix="pdav-stats-")
        missing = os.path.join(valid, "not-exist")

        def fake_usage(path):
            if path == missing:
                raise OSError("missing")
            return SimpleNamespace(total=1000 * _MB)

        try:
            with patch("services.stats_service.shutil.disk_usage", side_effect=fake_usage):
                total = StatsService._disk_total_mb([missing, valid])
            self.assertAlmostEqual(total, 1000.0)
        finally:
            os.rmdir(valid)

    def test_empty_mounts_falls_back_to_cwd(self):
        with patch(
            "services.stats_service.shutil.disk_usage",
            return_value=SimpleNamespace(total=500 * _MB),
        ):
            total = StatsService._disk_total_mb([])
        self.assertAlmostEqual(total, 500.0)

    def test_returns_zero_when_capacity_unknown(self):
        with patch("services.stats_service.shutil.disk_usage", side_effect=OSError("nope")):
            total = StatsService._disk_total_mb([])
        self.assertEqual(total, 0.0)


class TestStatsQuota(unittest.TestCase):
    def setUp(self):
        init_temp_db(prefix="pdav-stats-quota-")
        self.tmp = tempfile.mkdtemp(prefix="pdav-stats-quota-root-")
        FileMountService._instance = None
        svc = FileMountService()
        svc._migrated = True
        svc._mounts = [{"name": "quota", "path": self.tmp, "quota_mb": 1}]
        with open(os.path.join(self.tmp, "big.bin"), "wb") as f:
            f.write(b"x" * (2 * _MB))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)
        FileMountService._instance = None

    def test_quota_reports_over_quota(self):
        with (
            patch("services.stats_service.ContactService") as contact_cls,
            patch("services.stats_service.EventService") as event_cls,
            patch("services.stats_service.TrashService") as trash_cls,
        ):
            contact_cls.return_value.count.return_value = 0
            event_cls.return_value.count.return_value = 0
            trash_cls.list_items.return_value = []
            data = StatsService().collect()
        self.assertTrue(data["disk_over_quota"])
        self.assertAlmostEqual(data["disk_total_mb"], 1.0)
        self.assertAlmostEqual(data["disk_used_mb"], 2.0)
        self.assertAlmostEqual(data["disk_other_mb"], 0.0)
        self.assertTrue(data["mount_stats"][0]["over_quota"])


if __name__ == "__main__":
    unittest.main()
