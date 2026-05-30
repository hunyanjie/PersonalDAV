from typing import Optional, List
from database.repositories.base import BaseRepository
from models.contact import ContactModel

class ContactRepository(BaseRepository[ContactModel]):
    def __init__(self):
        super().__init__(
            table='contacts',
            model_cls=ContactModel,
            columns=['uid', 'full_name', 'email', 'phone', 'vcard', 'id'],
            insert_columns=['uid', 'full_name', 'email', 'phone', 'vcard']
        )
