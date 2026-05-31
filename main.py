import argparse
import logging
from tkinterdnd2 import TkinterDnD
from ui.app import DAVServerApp

def main():
    parser = argparse.ArgumentParser(description="PrivateDAV - 私人 CardDAV/CalDAV 服务")
    parser.add_argument("--port", "-p", type=int, default=None, help="WebDAV 服务器端口号")
    parser.add_argument("--db-path", type=str, default=None, help="数据库文件路径")
    parser.add_argument("--log-level", type=str, default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="日志级别")
    args = parser.parse_args()

    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    if args.db_path:
        from database.db_manager import Database
        Database(db_path=args.db_path)

    root = TkinterDnD.Tk()
    app = DAVServerApp(root, cli_port=args.port, cli_log_level=args.log_level)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
