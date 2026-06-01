"""
软件配置与元数据
"""
import os

SOFTWARE_NAME = "PrivateDAV"
SOFTWARE_DESCRIPTION = "全能 DAV 服务 (CardDAV + CalDAV + WebDAV)"
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
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, path)
    return path
