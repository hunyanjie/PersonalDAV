import hashlib
import secrets
import ipaddress
from services.settings_service import SettingsService
from utils.logger import logger
from utils.rate_limiter import get_rate_limiter


class AuthService:
    """统一鉴权服务（单例）"""
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    # ── 密码 ────────────────────────────────────────────────────

    def set_password(self, password: str):
        salt = secrets.token_hex(16)
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex()
        SettingsService().set_setting("access_password_hash", f"{salt}${pw_hash}")
        logger.info("鉴权密码已设置")

    def clear_password(self):
        SettingsService().set_setting("access_password_hash", "")
        logger.info("鉴权密码已清除")

    def is_enabled(self) -> bool:
        return bool(SettingsService().get_setting("access_password_hash", ""))

    def verify_password(self, password: str) -> bool:
        stored = SettingsService().get_setting("access_password_hash", "")
        if not stored:
            return True
        if '$' not in stored:
            return False
        salt, pw_hash = stored.split('$', 1)
        computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex()
        return secrets.compare_digest(computed, pw_hash)

    # ── MCP 令牌 ────────────────────────────────────────────────

    def get_mcp_token(self) -> str:
        stored = SettingsService().get_setting("access_password_hash", "")
        if not stored:
            return ""
        return hashlib.sha256(f"mcp:{stored}".encode('utf-8')).hexdigest()

    def verify_mcp_token(self, token: str) -> bool:
        if not self.is_enabled():
            return True
        return secrets.compare_digest(self.get_mcp_token(), token)

    def ip_bypasses_auth(self, client_ip: str) -> bool:
        s = SettingsService()
        bypass_local = s.get_setting("bypass_localhost", "True") == "True"
        if bypass_local and client_ip in ('127.0.0.1', '::1', 'localhost'):
            return True
        raw = s.get_setting("ip_bypass_auth", "").strip()
        if not raw:
            return False
        import re
        for p in re.split(r'[\n,，]+', raw):
            p = p.strip()
            if p and self._ip_matches(client_ip, p):
                return True
        return False

    # ── IP 访问控制 ─────────────────────────────────────────────

    def get_whitelist(self) -> list[str]:
        raw = SettingsService().get_setting("ip_whitelist", "").strip()
        if not raw:
            return []
        import re
        parts = re.split(r'[\n,，]+', raw)
        return [p.strip() for p in parts if p.strip()]

    def get_blacklist(self) -> list[str]:
        raw = SettingsService().get_setting("ip_blacklist", "").strip()
        if not raw:
            return []
        import re
        parts = re.split(r'[\n,，]+', raw)
        return [p.strip() for p in parts if p.strip()]

    @staticmethod
    def _ip_matches(ip_str: str, pattern: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if '/' in pattern:
                return ip in ipaddress.ip_network(pattern, strict=False)
            if '*' in pattern:
                import fnmatch
                return fnmatch.fnmatch(ip_str, pattern)
            return ip_str == pattern
        except ValueError:
            return False

    def check_ip(self, client_ip: str) -> bool:
        whitelist = self.get_whitelist()
        blacklist = self.get_blacklist()

        if whitelist:
            allowed = any(self._ip_matches(client_ip, p) for p in whitelist)
            if not allowed:
                logger.warning(f"IP 访问被白名单拒绝: {client_ip}")
                return False

        if blacklist:
            blocked = any(self._ip_matches(client_ip, p) for p in blacklist)
            if blocked:
                logger.warning(f"IP 访问被黑名单拒绝: {client_ip}")
                return False

        return True

    # ── 访问频率限制 ──────────────────────────────────────────

    def is_rate_limit_enabled(self) -> bool:
        return SettingsService().get_setting("rate_limit_enabled", "False") == "True"

    def get_rate_limit_max(self) -> int:
        try:
            return int(SettingsService().get_setting("rate_limit_max", "60"))
        except (ValueError, TypeError):
            return 60

    def check_rate_limit(self, client_ip: str) -> bool:
        if not self.is_rate_limit_enabled():
            return True
        max_req = self.get_rate_limit_max()
        allowed = get_rate_limiter().check(client_ip, max_requests=max_req, window_seconds=60)
        if not allowed:
            logger.warning(f"[{client_ip}] 频率限制已触发 ({max_req}/分钟)")
        return allowed

    # ── 鉴权日志（统一入口，后续可扩展 UA、浏览器指纹等） ──────

    def log_auth(self, success: bool, client_ip: str, method: str = "", extra: str = ""):
        status = "登录成功" if success else "登录失败"
        parts = f"[{client_ip}] {status}"
        if method:
            parts += f" [{method}]"
        if extra:
            parts += f" {extra}"
        if success:
            logger.info(parts)
        else:
            logger.warning(parts)
