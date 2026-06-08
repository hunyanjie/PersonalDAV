from typing import Generic, TypeVar, List, Optional, Type
from database.db_manager import Database

T = TypeVar('T')

class BaseRepository(Generic[T]):
    def __init__(self, table: str, model_cls: Type[T], columns: List[str], insert_columns: List[str]):
        self.db = Database()
        self.table = table
        self.model_cls = model_cls
        self.columns = columns
        self.insert_columns = insert_columns
        self._col_str = ', '.join(columns)
        self._insert_col_str = ', '.join(insert_columns)
        self._placeholders = ', '.join(['?'] * len(insert_columns))

    def _to_model(self, row: tuple) -> T:
        return self.model_cls(**{col: val for col, val in zip(self.columns, row)})

    def add_or_update(self, entity: T) -> bool:
        values = tuple(getattr(entity, col) for col in self.insert_columns)
        with self.db.transaction() as cursor:
            cursor.execute(
                f'INSERT OR REPLACE INTO {self.table} ({self._insert_col_str}) VALUES ({self._placeholders})',
                values
            )
        return True

    def get_by_uid(self, uid: str) -> Optional[T]:
        row = self.db.query_one(f"SELECT {self._col_str} FROM {self.table} WHERE uid=?", (uid,))
        if row:
            return self._to_model(row)
        return None

    def get_all(self) -> List[T]:
        rows = self.db.query(f"SELECT {self._col_str} FROM {self.table}")
        return [self._to_model(row) for row in rows]

    def get_selected_columns(self, column_names: List[str]) -> List[tuple]:
        col_str = ', '.join(column_names)
        return self.db.query(f"SELECT {col_str} FROM {self.table}")

    def delete(self, uid: str) -> bool:
        with self.db.transaction() as cursor:
            cursor.execute(f"DELETE FROM {self.table} WHERE uid=?", (uid,))
        return True

    def count(self) -> int:
        row = self.db.query_one(f"SELECT COUNT(*) FROM {self.table}")
        return row[0] if row else 0
