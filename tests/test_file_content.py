"""文本读写与压缩包浏览的单元测试。"""

import os
import shutil
import tempfile
import unittest
import zipfile

from fastapi import HTTPException

from personaldavd.files import (
    _list_archive,
    _read_archive_entry,
    _read_text_file,
    _write_text_file,
)
from services.file_mount_service import FileMountService
from tests._test_db import init_temp_db


class TestTextFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pdav-content-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_roundtrip_utf8(self):
        path = os.path.join(self.tmp, "a.py")
        _write_text_file(path, "print('你好')\n")
        result = _read_text_file(path)
        self.assertEqual(result["content"], "print('你好')\n")
        self.assertEqual(result["encoding"], "utf-8")

    def test_binary_rejected(self):
        path = os.path.join(self.tmp, "a.bin")
        with open(path, "wb") as f:
            f.write(b"\x00\x01\x02")
        with self.assertRaises(HTTPException) as ctx:
            _read_text_file(path)
        self.assertEqual(ctx.exception.status_code, 415)

    def test_zip_browse(self):
        path = os.path.join(self.tmp, "a.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("hello.txt", "hello")
            zf.writestr("dir/", "")
        listing = _list_archive(path)
        names = [e["name"] for e in listing["entries"]]
        self.assertIn("hello.txt", names)
        self.assertIn("dir/", names)
        raw, ctype = _read_archive_entry(path, "hello.txt")
        self.assertEqual(raw, b"hello")
        self.assertTrue(ctype.startswith("text/"))


class TestMountQuota(unittest.TestCase):
    def setUp(self):
        init_temp_db(prefix="pdav-quota-")
        FileMountService._instance = None
        self.tmp = tempfile.mkdtemp(prefix="pdav-mount-quota-")
        self.svc = FileMountService()
        self.svc._migrated = True
        self.svc._mounts = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_add_and_update_quota(self):
        self.svc.add_mount("docs", self.tmp, 100)
        self.assertEqual(self.svc.get_mount("docs")["quota_mb"], 100.0)

        # 只改路径时必须保留原来的空间上限
        self.svc.update_mount("docs", "docs2", self.tmp)
        self.assertEqual(self.svc.get_mount("docs2")["quota_mb"], 100.0)

        self.svc.update_mount("docs2", "docs2", self.tmp, 200)
        self.assertEqual(self.svc.get_mount("docs2")["quota_mb"], 200.0)

        self.svc.update_mount("docs2", "docs2", self.tmp, None)
        self.assertNotIn("quota_mb", self.svc.get_mount("docs2"))


if __name__ == "__main__":
    unittest.main()
