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

    @staticmethod
    def _group_where() -> str:
        # groups 以分号分隔，用两端补分号的方式做精确匹配，避免 Work 命中 Workshop。
        return "instr(';' || groups || ';', ';' || ? || ';') > 0"

    def get_by_group_paginated(self, group: str, offset: int = 0, limit: int = 50) -> list[ContactModel]:
        rows = self.db.query(
            f"SELECT {self._col_str} FROM {self.table} WHERE {self._group_where()} "
            "ORDER BY id LIMIT ? OFFSET ?",
            (group, limit, offset)
        )
        return [self._to_model(row) for row in rows]

    def count_by_group(self, group: str) -> int:
        row = self.db.query_one(
            f"SELECT COUNT(*) FROM {self.table} WHERE {self._group_where()}",
            (group,)
        )
        return row[0] if row else 0

    def get_groups(self) -> list[str]:
        rows = self.db.query(
            f"SELECT groups FROM {self.table} WHERE groups IS NOT NULL AND groups != ''"
        )
        groups: set[str] = set()
        for (value,) in rows:
            for group in str(value).replace(',', ';').split(';'):
                group = group.strip()
                if group:
                    groups.add(group)
        return sorted(groups, key=str.casefold)
