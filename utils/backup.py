import os
import zipfile
import json
from datetime import datetime
from database.db_manager import Database
from services.settings_service import SettingsService


def export_backup(output_path: str) -> bool:
    try:
        db = Database()
        db_path = db.db_path
        settings = SettingsService().get_all_settings()
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(db_path, arcname="dav_data.db")
            zf.writestr("settings.json", json.dumps(dict(settings), ensure_ascii=False, indent=2))
            for f in ["dav_server.log"]:
                log_path = f
                if not os.path.isfile(log_path):
                    from utils.path_helper import resolve_data_path
                    log_path = resolve_data_path(f)
                if os.path.isfile(log_path):
                    zf.write(log_path, arcname=f)
            zf.writestr("backup_info.txt",
                        f"备份时间: {datetime.now().isoformat()}\n"
                        f"数据版本: 2.3\n"
                        f"包含: 数据库、设置、日志\n")
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"备份失败: {e}")
        return False


def import_backup(zip_path: str) -> bool:
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            # 先读设置到内存
            raw = zf.read("settings.json") if "settings.json" in zf.namelist() else None
            imported = json.loads(raw) if raw else None
            # 关闭当前连接，覆盖 DB 文件
            db = Database()
            db_path = db.db_path
            db_dir = os.path.dirname(db_path) or "."
            if "dav_data.db" in zf.namelist():
                db.close()
                zf.extract("dav_data.db", path=db_dir)
            # 重新连接数据库
            db.reopen()
            # 写回设置
            if imported:
                for k, v in imported.items():
                    SettingsService().set_setting(k, v)
            # 解压日志
            for name in zf.namelist():
                if name.endswith(".log"):
                    zf.extract(name, path=db_dir)
        return True
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"恢复失败: {e}")
        return False
