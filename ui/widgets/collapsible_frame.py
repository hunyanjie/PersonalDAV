import tkinter as tk
from tkinter import ttk


class CollapsibleFrame(ttk.Frame):
    """可折叠/展开的 LabelFrame"""
    def __init__(self, parent, text="", expanded=True, **kwargs):
        super().__init__(parent, **kwargs)
        self._expanded = expanded

        self._toggle_btn = ttk.Button(self, text="▼ " + text if expanded else "▶ " + text,
                                      style="Toolbutton", command=self._toggle)
        self._toggle_btn.pack(fill=tk.X, anchor=tk.W)

        self._body = ttk.Frame(self)
        if expanded:
            self._body.pack(fill=tk.X, padx=5, pady=(0, 5))

    def _toggle(self):
        self._expanded = not self._expanded
        text = self._toggle_btn.cget("text")
        prefix = "▼ " if self._expanded else "▶ "
        self._toggle_btn.config(text=prefix + text[2:])
        if self._expanded:
            self._body.pack(fill=tk.X, padx=5, pady=(0, 5))
        else:
            self._body.forget()

    @property
    def body(self):
        return self._body
