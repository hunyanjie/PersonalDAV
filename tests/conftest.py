"""Shared pytest configuration: tkinter root for UI tests."""


def pytest_sessionstart(session):
    """pytest 会话统一使用临时数据库，避免误改用户真实数据。"""
    from tests._test_db import init_temp_db
    init_temp_db("pdav-pytest-")



try:
    import tkinter as tk
    _root = tk.Tk()
    _root.withdraw()
    _root.update()
    TK_ROOT = _root
    TK_AVAILABLE = True
except Exception:
    TK_ROOT = None
    TK_AVAILABLE = False
