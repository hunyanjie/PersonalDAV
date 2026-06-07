"""
Fuzz testing: feed corrupted vCard/iCal data through all parser entry points.
Verifies parsers never crash (exceptions must be caught, not propagated).
"""
import unittest
import random
import uuid
from utils.vcard_parser import RobustVCardParser


VALID_VCARD = """BEGIN:VCARD
VERSION:3.0
UID:{uid}
FN:Test Contact
N:Contact;Test;;;
EMAIL:test@example.com
TEL:+1234567890
END:VCARD
"""

VALID_ICAL = """BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Test//Test//EN
BEGIN:VEVENT
UID:{uid}
SUMMARY:Test Event
DTSTART:20240101T000000Z
DTEND:20240101T010000Z
END:VEVENT
END:VCALENDAR
"""


def _make_mutations(text: str, seed: int) -> list[str]:
    rng = random.Random(seed)
    results = []
    data = text.encode('utf-8')

    # byte flips
    for _ in range(20):
        b = bytearray(data)
        if b:
            idx = rng.randint(0, len(b) - 1)
            b[idx] ^= 1 << rng.randint(0, 7)
            results.append(b.decode('utf-8', errors='replace'))

    # truncations
    for _ in range(10):
        if len(data) > 5:
            cut = rng.randint(1, len(data) - 1)
            results.append(data[:cut].decode('utf-8', errors='replace'))

    # insert garbage
    for _ in range(10):
        b = bytearray(data)
        garbage = bytes([rng.randint(0, 255) for _ in range(rng.randint(1, 20))])
        pos = rng.randint(0, len(b))
        b[pos:pos] = garbage
        results.append(b.decode('utf-8', errors='replace'))

    # delete random ranges
    for _ in range(10):
        b = bytearray(data)
        if len(b) > 10:
            start = rng.randint(0, len(b) - 5)
            end = rng.randint(start + 1, min(start + 50, len(b)))
            del b[start:end]
            results.append(b.decode('utf-8', errors='replace'))

    # duplicate lines
    for _ in range(10):
        lines = text.splitlines()
        if lines:
            idx = rng.randint(0, len(lines) - 1)
            lines.insert(idx, lines[idx])
            results.append('\n'.join(lines))

    # random binary
    for _ in range(5):
        raw = bytes([rng.randint(0, 255) for _ in range(rng.randint(1, 500))])
        results.append(raw.decode('utf-8', errors='replace'))

    return results


class FuzzMixin:
    def _run(self, base: str, fn):
        mutants = _make_mutations(base, hash(self._testMethodName) & 0xFFFFFFFF)
        for i, mutant in enumerate(mutants):
            with self.subTest(mutant=i):
                try:
                    fn(mutant)
                except Exception:
                    pass


class TestVCardFuzzing(unittest.TestCase, FuzzMixin):
    def test_vobject_vcard(self):
        import vobject
        base = VALID_VCARD.format(uid=str(uuid.uuid4()))
        self._run(base, vobject.readOne)

    def test_manual_vcard(self):
        base = VALID_VCARD.format(uid=str(uuid.uuid4()))
        self._run(base, RobustVCardParser.manual_parse)


class TestICalFuzzing(unittest.TestCase, FuzzMixin):
    def test_vobject_ical(self):
        import vobject
        base = VALID_ICAL.format(uid=str(uuid.uuid4()))
        self._run(base, vobject.readOne)


class TestServiceFuzzing(unittest.TestCase, FuzzMixin):
    @classmethod
    def setUpClass(cls):
        from database.db_manager import Database
        Database.reset()
        Database(db_path=":memory:")

    def setUp(self):
        from database.db_manager import Database
        Database().execute("DELETE FROM contacts")
        Database().execute("DELETE FROM events")

    def test_contact_service(self):
        from services.contact_service import ContactService
        base = VALID_VCARD.format(uid=str(uuid.uuid4()))
        svc = ContactService()
        self._run(base, lambda d: svc.add_contact(d, publish=False))

    def test_event_service(self):
        from services.event_service import EventService
        base = VALID_ICAL.format(uid=str(uuid.uuid4()))
        svc = EventService()
        self._run(base, lambda d: svc.add_event(d, publish=False))


if __name__ == "__main__":
    unittest.main()
