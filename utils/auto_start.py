"""系统自启动管理"""
import os
import sys
import platform

APP_NAME = "PersonalDAV"


def set_auto_start(enabled: bool) -> bool:
    system = platform.system()
    if system == "Windows":
        return _windows_auto_start(enabled)
    elif system == "Linux":
        return _linux_auto_start(enabled)
    elif system == "Darwin":
        return _macos_auto_start(enabled)
    return False


def is_auto_start() -> bool:
    system = platform.system()
    if system == "Windows":
        return _windows_is_auto_start()
    elif system == "Linux":
        return _linux_is_auto_start()
    elif system == "Darwin":
        return _macos_is_auto_start()
    return False


def _get_exe_path() -> str:
    if getattr(sys, 'frozen', False):
        return f'"{sys.executable}"'
    return f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}"'


# ── Windows ──────────────────────────────────────────────────────

def _windows_auto_start(enabled: bool) -> bool:
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _get_exe_path())
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def _windows_is_auto_start() -> bool:
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(key, APP_NAME)
            return True
        except FileNotFoundError:
            return False
        finally:
            winreg.CloseKey(key)
    except Exception:
        return False


# ── Linux ─────────────────────────────────────────────────────────

def _get_autostart_dir():
    from pathlib import Path
    return Path.home() / ".config" / "autostart"


def _linux_auto_start(enabled: bool) -> bool:
    autostart_dir = _get_autostart_dir()
    desktop_file = autostart_dir / f"{APP_NAME.lower()}.desktop"
    try:
        if enabled:
            autostart_dir.mkdir(parents=True, exist_ok=True)
            desktop_file.write_text(
                f"[Desktop Entry]\n"
                f"Type=Application\n"
                f"Name={APP_NAME}\n"
                f"Exec={_get_exe_path()}\n"
                f"Terminal=false\n"
                f"X-GNOME-Autostart-enabled=true\n",
                encoding="utf-8"
            )
        else:
            if desktop_file.exists():
                desktop_file.unlink()
        return True
    except Exception:
        return False


def _linux_is_auto_start() -> bool:
    return _get_autostart_dir().joinpath(f"{APP_NAME.lower()}.desktop").exists()


# ── macOS ─────────────────────────────────────────────────────────

def _get_launch_agents_dir():
    from pathlib import Path
    return Path.home() / "Library" / "LaunchAgents"


def _macos_auto_start(enabled: bool) -> bool:
    plist_path = _get_launch_agents_dir() / f"com.{APP_NAME.lower()}.plist"
    try:
        if enabled:
            _get_launch_agents_dir().mkdir(parents=True, exist_ok=True)
            plist_path.write_text(
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                f'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                f'<plist version="1.0"><dict>\n'
                f'<key>Label</key><string>com.{APP_NAME.lower()}</string>\n'
                f'<key>ProgramArguments</key><array>{_get_exe_path()}</array>\n'
                f'<key>RunAtLoad</key><true/>\n'
                f'<key>KeepAlive</key><false/>\n'
                f'</dict></plist>\n',
                encoding="utf-8"
            )
        else:
            if plist_path.exists():
                plist_path.unlink()
        return True
    except Exception:
        return False


def _macos_is_auto_start() -> bool:
    return _get_launch_agents_dir().joinpath(f"com.{APP_NAME.lower()}.plist").exists()
