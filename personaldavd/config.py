"""Daemon configuration."""

from dataclasses import dataclass, field


DEFAULT_DAEMON_DB = "data/dav_data.db"


@dataclass
class DaemonConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    log_json: bool = False
    db_path: str = DEFAULT_DAEMON_DB
    data_dir: str = ""
    dav_root: str = ""
    ssl_enabled: bool = False
    ssl_certfile: str = ""
    ssl_keyfile: str = ""
    webui_enabled: bool = True
    server_protocol: str = "http_https"
