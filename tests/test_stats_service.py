"""概览磁盘容量计算：失效挂载点不能把总容量变成 0。"""

import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from services.stats_service import StatsService

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


if __name__ == "__main__":
    unittest.main()
