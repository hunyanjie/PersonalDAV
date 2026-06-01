import os


def resolve_data_path(path: str) -> str:
    from services.settings_service import SettingsService
    data_dir = SettingsService().get_setting("data_dir", "")
    if data_dir and not os.path.isabs(path):
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, path)
    return path
