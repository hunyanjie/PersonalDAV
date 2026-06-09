import argparse
import logging
import os
import shutil
import base64
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


def _migrate_attachment_folder():
    old_dir = os.path.join("data", "attachments")
    new_dir = os.path.join("data", "calendar_attachments")
    if os.path.isdir(old_dir) and not os.path.isdir(new_dir):
        try:
            os.makedirs(new_dir, exist_ok=True)
            for fname in os.listdir(old_dir):
                src = os.path.join(old_dir, fname)
                dst = os.path.join(new_dir, fname)
                if os.path.isfile(src):
                    shutil.move(src, dst)
            os.rmdir(old_dir)
            logging.getLogger(__name__).info("附件目录已迁移: data/attachments -> data/calendar_attachments")
        except Exception as e:
            logging.getLogger(__name__).warning(f"附件目录迁移失败: {e}")


def _migrate_inline_attachments():
    try:
        from database.db_manager import Database
        db = Database()
        rows = db.query("SELECT id, uid, ical FROM events WHERE ical LIKE '%ATTACH%'")
        if not rows:
            logging.getLogger(__name__).info("无内联附件需要迁移")
            return
        from services.ical_builder import parse_ical_event, build_ical
        from utils import attachment_store
        import vobject
        migrated = 0
        for row_id, uid, ical_text in rows:
            if 'X-PERSONALDAV-ATTACH' in ical_text:
                continue
            parsed = parse_ical_event(ical_text)
            atts = parsed.get('attachments', [])
            if not atts:
                continue
            changed = False
            for a in atts:
                if a.get('inline') and 'data' in a and (not a.get('filepath')):
                    record = attachment_store.from_base64(
                        a['data'], a.get('filename', 'attachment.bin'), a.get('fmttype')
                    )
                    if '_b64_fallback' not in record:
                        a['filepath'] = record['filepath']
                        a['size'] = record['size']
                        changed = True
                    del a['data']
            if not changed:
                continue
            parsed['attachments'] = atts
            new_ical = build_ical(parsed)
            with db.transaction() as cursor:
                cursor.execute("UPDATE events SET ical=? WHERE id=?", (new_ical, row_id))
            migrated += 1
        if migrated:
            logging.getLogger(__name__).info(f"内联附件迁移完成: {migrated} 条事件")
    except Exception as e:
        logging.getLogger(__name__).warning(f"内联附件迁移失败: {e}")


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
    _migrate_attachment_folder()
    _migrate_inline_attachments()

    root = TkinterDnD.Tk()
    app = DAVServerApp(root, cli_port=args.port, cli_log_level=args.log_level)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    from utils.window_utils import center_window
    center_window(root)
    root.mainloop()

if __name__ == "__main__":
    main()
