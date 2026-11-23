"""多挂载点路径解析必须可重入，不能在持有实例锁时自锁死。"""

import os
import tempfile
import threading
import unittest

from services.file_mount_service import FileMountService


class TestFileMountLock(unittest.TestCase):
    def setUp(self):
        FileMountService._instance = None
        self.svc = FileMountService()
        self.tmp = tempfile.mkdtemp(prefix="pdav-mount-test-")
        self.svc._migrated = True
        self.svc._mounts = [
            {"name": "first", "path": self.tmp},
            {"name": "second", "path": self.tmp},
        ]

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_with_timeout(self, fn, timeout=2.0):
        result = {}

        def worker():
            try:
                result["value"] = fn()
            except Exception as exc:  # pragma: no cover - 失败时便于定位
                result["error"] = exc

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout)
        self.assertFalse(t.is_alive(), "FileMountService 方法发生死锁")
        if "error" in result:
            raise result["error"]
        return result.get("value")

    def test_get_root_entries_multi_mount(self):
        entries = self._run_with_timeout(self.svc.get_root_entries)
        self.assertEqual([e["name"] for e in entries], ["first", "second"])

    def test_resolve_multi_mount(self):
        name, path = self._run_with_timeout(lambda: self.svc.resolve("first/a.txt"))
        self.assertEqual(name, "first")
        self.assertEqual(path, os.path.join(self.tmp, "a.txt"))

    def test_resolve_single_mount(self):
        self.svc._mounts = [{"name": "only", "path": self.tmp}]
        name, path = self._run_with_timeout(lambda: self.svc.resolve("a.txt"))
        self.assertEqual(name, "only")
        self.assertEqual(path, os.path.join(self.tmp, "a.txt"))


if __name__ == "__main__":
    unittest.main()
