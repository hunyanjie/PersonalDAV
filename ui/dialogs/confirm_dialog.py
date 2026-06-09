import tkinter as tk
from tkinter import ttk


class ConfirmDialog:
    @staticmethod
    def ask(parent, title: str, message: str,
            yes_text="确定", no_text="取消",
            default_no=True) -> bool:
        dialog = tk.Toplevel(parent)
        dialog.title(title)
        dialog.resizable(False, False)
        dialog.transient(parent)
        dialog.grab_set()

        result = [False]

        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        msg = ttk.Label(frame, text=message, wraplength=380, justify=tk.LEFT)
        msg.pack(pady=(0, 20))

        btn_f = ttk.Frame(frame)
        btn_f.pack()

        def on_yes():
            result[0] = True
            dialog.destroy()

        def on_no():
            result[0] = False
            dialog.destroy()

        no_btn = ttk.Button(btn_f, text=no_text, command=on_no)
        no_btn.pack(side=tk.RIGHT, padx=(5, 0))

        yes_btn = ttk.Button(btn_f, text=yes_text, command=on_yes)
        yes_btn.pack(side=tk.RIGHT, padx=(0, 5))

        if default_no:
            no_btn.focus()
            dialog.bind("<Return>", lambda e: on_no())
        else:
            yes_btn.focus()
            dialog.bind("<Return>", lambda e: on_yes())

        dialog.bind("<Escape>", lambda e: on_no())

        from utils.window_utils import center_window
        center_window(dialog, parent)

        parent.wait_window(dialog)
        return result[0]
