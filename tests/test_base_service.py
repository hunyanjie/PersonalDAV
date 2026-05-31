import unittest
import uuid
from database.db_manager import Database
from services.base_service import BaseService
from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED


class _Item:
    def __init__(self, uid, raw_data):
        self.uid = uid
        self.raw_data = raw_data

class _TestRepo:
    def __init__(self):
        self.db = Database()
        self.db.execute("""CREATE TABLE IF NOT EXISTS test_items
            (id INTEGER PRIMARY KEY, uid TEXT UNIQUE, raw_data TEXT)""")

    def get_by_uid(self, uid):
        row = self.db.query_one("SELECT uid, raw_data FROM test_items WHERE uid=?", (uid,))
        if row:
            return _Item(row[0], row[1])
        return None

    def get_all(self):
        rows = self.db.query("SELECT uid, raw_data FROM test_items")
        return [_Item(r[0], r[1]) for r in rows]

    def delete(self, uid):
        self.db.execute("DELETE FROM test_items WHERE uid=?", (uid,))
        return True

    def count(self):
        row = self.db.query_one("SELECT COUNT(*) FROM test_items")
        return row[0] if row else 0


class _TestService(BaseService):
    def __init__(self):
        repo = _TestRepo()
        super().__init__(repo=repo, changed_event=EVENT_CONTACTS_CHANGED, raw_field="raw_data", list_fields=("uid", "raw_data"))


class TestBaseService(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Database.reset()
        Database(db_path=":memory:")

    def setUp(self):
        self.svc = _TestService()
        self.svc.repo.db.execute("DELETE FROM test_items")

    def test_count_empty(self):
        self.assertEqual(self.svc.count(), 0)

    def test_get_by_uid_nonexistent(self):
        self.assertIsNone(self.svc.get_by_uid("nonexistent"))

    def test_add_and_get(self):
        uid = str(uuid.uuid4())
        self.svc.repo.db.execute("INSERT INTO test_items (uid, raw_data) VALUES (?, ?)", (uid, "test data"))
        result = self.svc.get_by_uid(uid)
        self.assertEqual(result, "test data")

    def test_get_etag(self):
        uid = str(uuid.uuid4())
        self.svc.repo.db.execute("INSERT INTO test_items (uid, raw_data) VALUES (?, ?)", (uid, "hello"))
        etag = self.svc.get_etag(uid)
        self.assertIsNotNone(etag)
        self.assertTrue(etag.startswith('"'))
        self.assertTrue(etag.endswith('"'))

    def test_get_all_items(self):
        uid1, uid2 = str(uuid.uuid4()), str(uuid.uuid4())
        self.svc.repo.db.execute("INSERT INTO test_items (uid, raw_data) VALUES (?, ?)", (uid1, "a"))
        self.svc.repo.db.execute("INSERT INTO test_items (uid, raw_data) VALUES (?, ?)", (uid2, "b"))
        items = self.svc.get_all_items()
        self.assertEqual(len(items), 2)

    def test_delete(self):
        uid = str(uuid.uuid4())
        self.svc.repo.db.execute("INSERT INTO test_items (uid, raw_data) VALUES (?, ?)", (uid, "data"))
        self.assertTrue(self.svc.delete(uid))
        self.assertIsNone(self.svc.get_by_uid(uid))

    def test_get_selected_raw(self):
        uid = str(uuid.uuid4())
        self.svc.repo.db.execute("INSERT INTO test_items (uid, raw_data) VALUES (?, ?)", (uid, "selected"))
        results = self.svc.get_selected_raw([uid])
        self.assertEqual(results, ["selected"])

    def test_get_list_data(self):
        uid = str(uuid.uuid4())
        self.svc.repo.db.execute("INSERT INTO test_items (uid, raw_data) VALUES (?, ?)", (uid, "list"))
        data = self.svc.get_list_data()
        self.assertEqual(len(data), 1)

    def test_count_after_insert(self):
        uid = str(uuid.uuid4())
        self.svc.repo.db.execute("INSERT INTO test_items (uid, raw_data) VALUES (?, ?)", (uid, "cnt"))
        self.assertEqual(self.svc.count(), 1)


if __name__ == "__main__":
    unittest.main()