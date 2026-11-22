"""Web 端功能补齐：分组筛选、例外日期、Apple 配置二维码。"""

import asyncio
import unittest

from starlette.requests import Request

from tests._test_db import init_temp_db
from personaldavd.api import (
    _apple_request_origin,
    _event_fields_to_ical,
    _ical_to_event_out,
    apple_config_qr,
)
from personaldavd.models import EventCreate
from services.contact_service import ContactService
from services.settings_service import SettingsService


class TestContactGroupFilter(unittest.TestCase):
    def setUp(self):
        init_temp_db(prefix="pdav-webui-parity-")
        SettingsService._instance = None
        SettingsService._cache.clear()
        ContactService._instance = None
        self.svc = ContactService()

    def _vcard(self, uid, name, groups):
        return (
            "BEGIN:VCARD\r\nVERSION:3.0\r\n"
            f"UID:{uid}\r\nFN:{name}\r\n"
            f"CATEGORIES:{groups}\r\n"
            "END:VCARD\r\n"
        )

    def test_groups_and_paginated_filter(self):
        self.svc.add_contact(self._vcard("u1", "Alice", "Work;Team"))
        self.svc.add_contact(self._vcard("u2", "Bob", "Work"))
        self.svc.add_contact(self._vcard("u3", "Carol", "Friends"))

        self.assertEqual(self.svc.get_groups(), ["Friends", "Team", "Work"])
        items, total = self.svc.get_all_raw_paginated_by_group("Work", 0, 50)
        self.assertEqual(total, 2)
        self.assertEqual(len(items), 2)
        self.assertTrue(all("Work" in item for item in items))

        # 不能把 Workshop 误当成 Work
        self.svc.add_contact(self._vcard("u4", "Dave", "Workshop"))
        _, total = self.svc.get_all_raw_paginated_by_group("Work", 0, 50)
        self.assertEqual(total, 2)


class TestEventExdates(unittest.TestCase):
    def test_exdate_roundtrip_timed(self):
        raw = _event_fields_to_ical(EventCreate(
            summary="Standup",
            dtstart="2026-01-01T10:00",
            dtend="2026-01-01T11:00",
            rrule="FREQ=DAILY;COUNT=5",
            exdates=["2026-01-03"],
        ), uid="exdate-1")
        self.assertIn("EXDATE:20260103T100000", raw)
        out = _ical_to_event_out(raw)
        self.assertIsNotNone(out)
        self.assertEqual(out.exdates, ["2026-01-03"])

    def test_exdate_roundtrip_all_day(self):
        raw = _event_fields_to_ical(EventCreate(
            summary="Holiday",
            dtstart="2026-01-01",
            dtend="2026-01-02",
            all_day=True,
            rrule="FREQ=YEARLY",
            exdates=["2027-01-01"],
        ), uid="exdate-2")
        self.assertIn("EXDATE:20270101", raw)
        out = _ical_to_event_out(raw)
        self.assertEqual(out.exdates, ["2027-01-01"])


class TestAppleConfig(unittest.TestCase):
    def setUp(self):
        init_temp_db(prefix="pdav-apple-qr-")
        SettingsService._instance = None
        SettingsService._cache.clear()

    @staticmethod
    def _request(scheme="https", host="dav.example.com", port=8443):
        return Request({
            "type": "http",
            "scheme": scheme,
            "server": (host, port),
            "path": "/api/apple/qr",
            "query_string": b"",
            "headers": [(b"host", f"{host}:{port}".encode())],
        })

    def test_origin_uses_actual_request_port(self):
        scheme, host, port = _apple_request_origin(self._request())
        self.assertEqual((scheme, host, port), ("https", "dav.example.com", 8443))

    def test_qr_svg_generated(self):
        response = asyncio.run(apple_config_qr(self._request(), request_host="dav.example.com", token="test"))
        self.assertEqual(response.media_type, "image/svg+xml")
        self.assertIn(b"<svg", response.body)
        self.assertIn(b"no-store", response.headers.get("cache-control", "").encode())


if __name__ == "__main__":
    unittest.main()
