import tkinter as tk

_STYLES = {
    "info":    {"bg": "#333333", "fg": "white"},
    "success": {"bg": "#2e7d32", "fg": "white"},
    "warning": {"bg": "#f57f17", "fg": "white"},
    "error":   {"bg": "#c62828", "fg": "white"},
}


class Toast:
    _instance = None

    @classmethod
    def show(cls, parent, message, duration=3000, type="info"):
        if cls._instance:
            try:
                cls._instance.win.destroy()
            except tk.TclError:
                pass
        cls._instance = cls(parent, message, duration, type)

    @classmethod
    def success(cls, parent, message, duration=2500):
        cls.show(parent, message, duration, "success")

    @classmethod
    def warning(cls, parent, message, duration=3500):
        cls.show(parent, message, duration, "warning")

    @classmethod
    def error(cls, parent, message, duration=4000):
        cls.show(parent, message, duration, "error")

    def __init__(self, parent, message, duration=3000, type="info"):
        self.duration = duration
        style = _STYLES.get(type, _STYLES["info"])
        self.win = tk.Toplevel(parent)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.configure(bg=style["bg"])

        label = tk.Label(self.win, text=message, bg=style["bg"], fg=style["fg"],
                         font=("", 10), padx=20, pady=12, wraplength=320)
        label.pack()

        self.win.update_idletasks()
        pw = parent.winfo_width() if parent.winfo_width() > 100 else 800
        ph = parent.winfo_height() if parent.winfo_height() > 100 else 600
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        x = px + pw - self.win.winfo_width() - 20
        y = py + ph - self.win.winfo_height() - 20
        self.win.geometry(f"+{x}+{y}")

        self.win.after(duration, self._close)

    def _close(self):
        try:
            self.win.destroy()
        except tk.TclError:
            pass
        Toast._instance = None
