import os


def resolve_data_path(path: str) -> str:
    from services.settings_service import SettingsService
    data_dir = SettingsService().get_setting("data_dir", "data")
    if data_dir and not os.path.isabs(path):
        normal_data = data_dir.rstrip("/\\")
        if path.replace("\\", "/").startswith(normal_data.replace("\\", "/") + "/"):
            return os.path.normpath(path)
        os.makedirs(data_dir, exist_ok=True)
        return os.path.normpath(os.path.join(data_dir, path))
    return path
