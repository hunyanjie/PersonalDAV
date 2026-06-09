"""personaldavd CLI entry point — python -m personaldavd [options]."""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .daemon import create_app, run_daemon
from .config import DaemonConfig


def main():
    from config import SOFTWARE_NAME
    parser = argparse.ArgumentParser(description=f"{SOFTWARE_NAME} headless daemon")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Log level (default: INFO)")
    parser.add_argument("--log-json", action="store_true", help="JSON structured logging")
    parser.add_argument("--db-path", default="data/dav_data.db", help="Database path")
    parser.add_argument("--dav-root", default="./dav_root", help="WebDAV root directory")
    args = parser.parse_args()

    config = DaemonConfig(
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        log_json=args.log_json,
        db_path=args.db_path,
        dav_root=args.dav_root,
    )
    run_daemon(config)


if __name__ == "__main__":
    main()
