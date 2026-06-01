import hashlib
import secrets
from services.settings_service import SettingsService


class AuthService:
    """统一鉴权服务（单例）"""
    _instance = None
    _initialized = False

    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    def set_password(self, password: str):
        salt = secrets.token_hex(16)
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex()
        SettingsService().set_setting("access_password_hash", f"{salt}${pw_hash}")

    def verify_password(self, password: str) -> bool:
        stored = SettingsService().get_setting("access_password_hash", "")
        if not stored:
            return True
        if '$' not in stored:
            return False
        salt, pw_hash = stored.split('$', 1)
        computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex()
        return secrets.compare_digest(computed, pw_hash)

    def is_enabled(self) -> bool:
        return bool(SettingsService().get_setting("access_password_hash", ""))

    def get_mcp_token(self) -> str:
        stored = SettingsService().get_setting("access_password_hash", "")
        if not stored:
            return ""
        return hashlib.sha256(f"mcp:{stored}".encode('utf-8')).hexdigest()

    def verify_mcp_token(self, token: str) -> bool:
        if not self.is_enabled():
            return True
        return secrets.compare_digest(self.get_mcp_token(), token)

    def clear_password(self):
        SettingsService().set_setting("access_password_hash", "")
