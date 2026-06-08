import argparse
import logging
import os
import shutil
from tkinterdnd2 import TkinterDnD
from ui.app import DAVServerApp

def _migrate_old_files():
    os.makedirs("data/log", exist_ok=True)

    old_files = {
        "dav_data.db": "data/dav_data.db",
        "dav_data.db.bak": "data/dav_data.db.bak",
        "remote_connections.key": "data/remote_connections.key",
    }
    for old, new in old_files.items():
        if os.path.isfile(old) and not os.path.isfile(new):
            try:
                shutil.copy2(old, new)
                logging.getLogger(__name__).info(f"已迁移: {old} -> {new}")
            except Exception as e:
                logging.getLogger(__name__).warning(f"迁移 {old} 失败: {e}")

    old_log = "dav_server.log"
    new_log = "data/log/dav_server.log"
    if os.path.isfile(old_log) and not os.path.isfile(new_log):
        try:
            shutil.copy2(old_log, new_log)
            logging.getLogger(__name__).info(f"已迁移: {old_log} -> {new_log}")
        except Exception as e:
            logging.getLogger(__name__).warning(f"迁移 {old_log} 失败: {e}")

    from services.settings_service import SettingsService
    try:
        s = SettingsService()
        cur = s.get_setting("data_dir", "")
        if not cur:
            s.set_setting("data_dir", "data")
            logging.getLogger(__name__).info("已设置 data_dir = data")
    except Exception as e:
        logging.getLogger(__name__).warning(f"设置 data_dir 失败: {e}")


def main():
    parser = argparse.ArgumentParser(description="PersonalDAV - 全能 DAV 服务 (CardDAV + CalDAV + WebDAV)")
    parser.add_argument("--port", "-p", type=int, default=None, help="WebDAV 服务器端口号")
    parser.add_argument("--db-path", type=str, default=None, help="数据库文件路径（优先级最高）")
    parser.add_argument("--data-dir", type=str, default=None, help="数据存储目录（与 --db-path 冲突时 --db-path 优先）")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="日志级别")
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    db_path = args.db_path
    if not db_path and args.data_dir:
        os.makedirs(args.data_dir, exist_ok=True)
        db_path = os.path.join(args.data_dir, "dav_data.db")
    if db_path:
        from database.db_manager import Database
        Database(db_path=db_path)

    _migrate_old_files()

    root = TkinterDnD.Tk()
    app = DAVServerApp(root, cli_port=args.port, cli_log_level=args.log_level)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    from utils.window_utils import center_window
    center_window(root)
    root.mainloop()

if __name__ == "__main__":
    main()
