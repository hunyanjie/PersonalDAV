"""测试用隔离数据库：绝不触碰用户真实的 data/dav_data.db。"""

import os
import tempfile


def init_temp_db(prefix: str = "pdav-test-"):
    from database.db_manager import Database
    Database.reset()
    db_path = os.path.join(tempfile.mkdtemp(prefix=prefix), "test.db")
    Database(db_path=db_path)
    return db_path
