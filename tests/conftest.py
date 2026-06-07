"""Shared pytest configuration: tkinter root for UI tests."""
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
