import argparse
import logging
import os
from tkinterdnd2 import TkinterDnD
from ui.app import DAVServerApp

def main():
    parser = argparse.ArgumentParser(description="PrivateDAV - 私人 CardDAV/CalDAV 服务")
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

    root = TkinterDnD.Tk()
    app = DAVServerApp(root, cli_port=args.port, cli_log_level=args.log_level)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
