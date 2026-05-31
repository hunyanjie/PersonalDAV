import tkinter as tk
from tkinter import ttk


class EnhancedTooltip:
    def __init__(self, widget, text="", **kwargs):
        if not text:
            return
        self.widget = widget
        self.tip_window = None
        self.offset = (10, 5)
        self.default_style = {
            'background': '#ffffea',
            'relief': 'solid',
            'borderwidth': 1,
            'font': (None, 10)
        }
        self.style_params = {**self.default_style, **kwargs}
        self.text = text
        self.bind_events()

    def bind_events(self):
        self.widget.bind("<Enter>", self.show_tip)
        self.widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
        x, y = self.widget.winfo_pointerxy()
        x, y = x + self.offset[0], y + self.offset[1]
        self.tip_window = self.create_tip_window(x, y, self.text, self.style_params)

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

    def create_tip_window(self, x, y, text, style_params):
        tip = tk.Toplevel(self.widget, borderwidth=0)
        tip.overrideredirect(True)
        tip.geometry(f"+{x}+{y}")
        label = ttk.Label(tip, text=text, **style_params)
        label.pack(ipadx=1, ipady=1, fill="both", expand=True)
        return tip
