"""
软件配置与元数据
"""

SOFTWARE_NAME = "PrivateDAV"
SOFTWARE_DESCRIPTION = "私人 CardDAV/CalDAV 服务"
SOFTWARE_VERSION = "2.3"
SOFTWARE_AUTHOR = "hunyanjie"

# 数据库路径
DEFAULT_DB_PATH = "dav_data.db"

# 日志配置
DEFAULT_LOG_FILE = "dav_server.log"
DEFAULT_LOG_LEVEL = "INFO"


def resolve_data_path(path: str) -> str:
    from services.settings_service import SettingsService
    data_dir = SettingsService().get_setting("data_dir", "")
    if data_dir and not os.path.isabs(path):
        import os
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, path)
    return path
