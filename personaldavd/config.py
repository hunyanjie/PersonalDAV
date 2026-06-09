"""Daemon configuration."""

from dataclasses import dataclass, field


@dataclass
class DaemonConfig:
    host: str = "127.0.0.1"
    port: int = 8000
    log_level: str = "INFO"
    log_json: bool = False
    db_path: str = "data/dav_data.db"
    dav_root: str = "./dav_root"
