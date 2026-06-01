import tkinter as tk


class Toast:
    """非模态右下角弹窗通知，数秒后自动消失"""
    _instance = None

    @classmethod
    def show(cls, parent, message, duration=3000):
        if cls._instance:
            try:
                cls._instance.destroy()
            except tk.TclError:
                pass
        cls._instance = cls(parent, message, duration)

    def __init__(self, parent, message, duration=3000):
        self.duration = duration
        self.win = tk.Toplevel(parent)
        self.win.overrideredirect(True)
        self.win.attributes("-topmost", True)
        self.win.configure(bg="#333333")

        label = tk.Label(self.win, text=message, bg="#333333", fg="white",
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

        self.win.after(duration, self._fade_out)

    def _fade_out(self):
        try:
            self.win.destroy()
        except tk.TclError:
            pass
        Toast._instance = None
