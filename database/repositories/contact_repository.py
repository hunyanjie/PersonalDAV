from typing import Optional, List
from database.repositories.base import BaseRepository
from models.contact import ContactModel

class ContactRepository(BaseRepository[ContactModel]):
    SEARCH_COLUMNS = ['full_name', 'email', 'phone']

    def __init__(self):
        super().__init__(
            table='contacts',
            model_cls=ContactModel,
            columns=['uid', 'full_name', 'email', 'phone', 'vcard', 'groups', 'id', 'created_at', 'updated_at'],
            insert_columns=['uid', 'full_name', 'email', 'phone', 'vcard', 'groups', 'created_at', 'updated_at']
        )

    def search_by_keyword(self, keyword: str, limit: int = 20) -> list[ContactModel]:
        return self.search(self.SEARCH_COLUMNS, keyword, limit)
