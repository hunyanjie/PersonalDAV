from database.db_manager import Database
from models.contact import ContactModel
from typing import List, Optional

class ContactRepository:
    """联系人数据访问层"""
    def __init__(self):
        self.db = Database()

    def add_or_update(self, contact: ContactModel) -> bool:
        with self.db.transaction() as cursor:
            cursor.execute(
                '''INSERT OR REPLACE INTO contacts (uid, full_name, email, phone, vcard) 
                   VALUES (?, ?, ?, ?, ?)''',
                (contact.uid, contact.full_name, contact.email, contact.phone, contact.vcard)
            )
        return True

    def get_by_uid(self, uid: str) -> Optional[ContactModel]:
        row = self.db.query_one("SELECT uid, full_name, email, phone, vcard, id FROM contacts WHERE uid=?", (uid,))
        if row:
            return ContactModel(uid=row[0], full_name=row[1], email=row[2], phone=row[3], vcard=row[4], id=row[5])
        return None

    def get_all(self) -> List[ContactModel]:
        rows = self.db.query("SELECT uid, full_name, email, phone, vcard, id FROM contacts")
        return [ContactModel(uid=r[0], full_name=r[1], email=r[2], phone=r[3], vcard=r[4], id=r[5]) for r in rows]

    def delete(self, uid: str) -> bool:
        with self.db.transaction() as cursor:
            cursor.execute("DELETE FROM contacts WHERE uid=?", (uid,))
        return True
