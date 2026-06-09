import os
import zipfile
import json
from datetime import datetime
from database.db_manager import Database
from services.settings_service import SettingsService
from config import SOFTWARE_VERSION

KNOWN_SETTINGS = {
    "auto_save_port": "True", "auto_start_server": "False", "default_port": "8000",
    "mcp_enabled": "False", "mcp_port": "8100", "auto_check_update": "True", "mcp_readonly": "False",
    "default_status": "CONFIRMED", "default_version": "2.0", "default_priority": "5",
    "default_transparency": "OPAQUE", "default_sync_timezone": "True",
    "default_repeat": "\u4e0d\u91cd\u590d", "default_end_cond": "\u6c38\u4e0d\u7ed3\u675f",
    "default_end_count": "5", "default_allday": "False", "default_force_reminder": "False",
    "auto_start_app": "False", "auto_start_ftp": "False", "ftps_enabled": "False", "ftp_encoding": "utf-8",
    "attachment_mode": "inline",
    "start_time_snap": "current",
    "enable_log_file": "False", "log_file_path": "", "log_level": "INFO", "timezone_format": "auto",
    "default_duration": "60",
    "ssl_enabled": "False", "ssl_certfile": "", "ssl_keyfile": "", "ssl_auto_renew": "True",
    "data_dir": "data", "close_action": "ask",
    "dav_root": "", "ftp_password": "",
    "sync_url": "", "sync_user": "", "sync_password": "", "sync_interval": "3600", "sync_enabled": "False",
    "force_password": "False", "rate_limit": "0",
    "ip_whitelist_enabled": "False", "ip_whitelist": "", "ip_blacklist_enabled": "False", "ip_blacklist": "",
    "setup_wizard_completed": "False",
}


def _ensure_known_settings():
    ss = SettingsService()
    for k, v in KNOWN_SETTINGS.items():
        if ss.get_setting(k, None) is None:
            ss.set_setting(k, v)


def export_backup(output_path: str) -> bool:
    try:
        db = Database()
        db_path = db.db_path
        settings = SettingsService().get_all_settings()
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(db_path, arcname="dav_data.db")
            zf.writestr("settings.json", json.dumps(dict(settings), ensure_ascii=False, indent=2))
            from utils.path_helper import resolve_data_path
            for f in ["log/dav_server.log"]:
                log_path = resolve_data_path(f)
                if os.path.isfile(log_path):
                    zf.write(log_path, arcname="dav_server.log")
            zf.writestr("backup_info.txt",
                        f"备份时间: {datetime.now().isoformat()}\n"
                        f"软件版本: {SOFTWARE_VERSION}\n"
                        f"包含: 数据库、设置、日志\n")
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"备份失败: {e}")
        return False


def import_backup(zip_path: str) -> bool:
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            raw = zf.read("settings.json") if "settings.json" in zf.namelist() else None
            imported = json.loads(raw) if raw else None
            db = Database()
            db_path = db.db_path
            db_dir = os.path.dirname(db_path) or "."
            if "dav_data.db" in zf.namelist():
                db.close()
                zf.extract("dav_data.db", path=db_dir)
            db.reopen()
            if imported:
                ss = SettingsService()
                for k, v in imported.items():
                    if k in KNOWN_SETTINGS:
                        ss.set_setting(k, v)
            _ensure_known_settings()
            from utils.path_helper import resolve_data_path
            log_dir = os.path.dirname(resolve_data_path("log/dav_server.log")) or "."
            os.makedirs(log_dir, exist_ok=True)
            for name in zf.namelist():
                if name.endswith(".log"):
                    zf.extract(name, path=log_dir)
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"恢复失败: {e}")
        return False
