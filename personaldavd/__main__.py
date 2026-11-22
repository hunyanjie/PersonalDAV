"""personaldavd CLI entry point — python -m personaldavd [options]."""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .daemon import run_daemon
from .config import DaemonConfig, DEFAULT_DAEMON_DB


def main():
    from config import SOFTWARE_NAME
    parser = argparse.ArgumentParser(description=f"{SOFTWARE_NAME} headless daemon")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Log level (default: INFO)")
    parser.add_argument("--log-json", action="store_true", help="JSON structured logging")
    parser.add_argument("--db-path", default="", help="Database path (priority over --data-dir)")
    parser.add_argument("--data-dir", default="", help="Data directory (database, logs, attachments, trash)")
    parser.add_argument("--dav-root", default="", help="Create a mount point for this directory (default: none)")
    args = parser.parse_args()

    # --db-path 优先；否则由 --data-dir 推导；两者都没有时使用默认路径。
    if args.db_path:
        db_path = args.db_path
    elif args.data_dir:
        db_path = os.path.join(args.data_dir, "dav_data.db")
    else:
        db_path = DEFAULT_DAEMON_DB

    config = DaemonConfig(
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        log_json=args.log_json,
        db_path=db_path,
        data_dir=args.data_dir,
        dav_root=args.dav_root,
    )
    run_daemon(config)


if __name__ == "__main__":
    main()
