def center_window(win, parent=None):
    win.update_idletasks()
    if parent:
        x = parent.winfo_x() + (parent.winfo_width() - win.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - win.winfo_height()) // 2
    else:
        x = (win.winfo_screenwidth() - win.winfo_width()) // 2
        y = (win.winfo_screenheight() - win.winfo_height()) // 2
    win.geometry(f"+{max(0,x)}+{max(0,y)}")
