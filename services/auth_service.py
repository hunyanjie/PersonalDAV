import hashlib
import secrets
import ipaddress
import time
import json
import urllib.request
from datetime import datetime
from services.settings_service import SettingsService
from utils.logger import logger
from utils.rate_limiter import get_rate_limiter
from database.db_manager import Database


class AuthService:
    """统一鉴权服务（单例）"""
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if getattr(self, '_initialized', False):
            return
        self._initialized = True
        self._prune_auth_logs()

    @staticmethod
    def _prune_auth_logs():
        pass

    # ── 密码 ────────────────────────────────────────────────────

    def set_password(self, password: str):
        salt = secrets.token_hex(16)
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex()
        SettingsService().set_setting("access_password_hash", f"{salt}${pw_hash}")
        SettingsService().set_setting("mcp_token_salt", secrets.token_hex(16))
        SettingsService().set_setting("mcp_token_rotated_at", datetime.now().isoformat())
        logger.info("鉴权密码已设置")

    def clear_password(self):
        SettingsService().set_setting("access_password_hash", "")
        SettingsService().set_setting("mcp_token_salt", "")
        SettingsService().set_setting("mcp_token_rotated_at", "")
        logger.info("鉴权密码已清除")

    def is_enabled(self) -> bool:
        return bool(SettingsService().get_setting("access_password_hash", ""))

    def is_password_required(self) -> bool:
        if self.is_enabled():
            return True
        return SettingsService().get_setting("force_password", "True") == "True"

    def verify_password(self, password: str) -> bool:
        stored = SettingsService().get_setting("access_password_hash", "")
        if not stored:
            return not self.is_password_required()
        if '$' not in stored:
            return False
        salt, pw_hash = stored.split('$', 1)
        computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex()
        return secrets.compare_digest(computed, pw_hash)

    def verify_ftp_password(self, password: str, username: str = "", client_ip: str = "", protocol: str = "FTP") -> bool:
        """FTP/SFTP 通用密码验证（含匿名回退 + 鉴权日志）"""
        ftp_pass = SettingsService().get_setting("ftp_password", "")
        if ftp_pass:
            ok = password == ftp_pass
            self.log_auth(ok, client_ip, protocol, f"用户={username}")
            return ok
        stored = SettingsService().get_setting("access_password_hash", "")
        if not stored:
            self.log_auth(True, client_ip, f"{protocol}-匿名", f"用户={username}")
            return True
        if '$' in stored:
            salt, pw_hash = stored.split('$', 1)
            from hashlib import pbkdf2_hmac
            from secrets import compare_digest
            ok = compare_digest(pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 600000).hex(), pw_hash)
            self.log_auth(ok, client_ip, protocol, f"用户={username}")
            if ok:
                return True
        self.log_auth(False, client_ip, protocol, f"用户={username}")
        return False

    # ── MCP 令牌（可轮换） ──────────────────────────────────────

    def _mcp_token_seed(self) -> str:
        s = SettingsService()
        stored = s.get_setting("access_password_hash", "")
        if not stored:
            salt = s.get_setting("mcp_token_salt", "")
            if not salt:
                salt = secrets.token_hex(16)
                s.set_setting("mcp_token_salt", salt)
            return f"mcp:nopass:{salt}"
        salt = s.get_setting("mcp_token_salt", "")
        return f"mcp:{stored}:{salt}" if salt else f"mcp:{stored}"

    def get_mcp_token(self) -> str:
        seed = self._mcp_token_seed()
        if not seed:
            return ""
        return hashlib.sha256(seed.encode('utf-8')).hexdigest()

    def verify_mcp_token(self, token: str) -> bool:
        if not self.is_password_required():
            return True
        return secrets.compare_digest(self.get_mcp_token(), token)

    def rotate_mcp_token(self):
        SettingsService().set_setting("mcp_token_salt", secrets.token_hex(16))
        SettingsService().set_setting("mcp_token_rotated_at", datetime.now().isoformat())
        logger.info("MCP 令牌已轮换")

    def get_mcp_token_rotated_at(self) -> str:
        return SettingsService().get_setting("mcp_token_rotated_at", "")

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

    # ── URL 鉴权（时间戳+随机数+MD5） ──────────────────────────

    def get_url_auth_secret(self) -> str:
        s = SettingsService()
        secret = s.get_setting("url_auth_secret", "")
        if not secret:
            secret = secrets.token_hex(32)
            s.set_setting("url_auth_secret", secret)
        return secret

    def is_url_auth_enabled(self) -> bool:
        return SettingsService().get_setting("url_auth_enabled", "False") == "True"

    def generate_url_token(self, path: str) -> tuple[str, str, str]:
        secret = self.get_url_auth_secret()
        ts = str(int(time.time()))
        nonce = secrets.token_hex(8)
        raw = f"{secret}|{ts}|{nonce}|{path}"
        token = hashlib.md5(raw.encode('utf-8')).hexdigest()
        return token, ts, nonce

    def verify_url_token(self, path: str, token: str, ts: str, nonce: str) -> bool:
        secret = self.get_url_auth_secret()
        raw = f"{secret}|{ts}|{nonce}|{path}"
        expected = hashlib.md5(raw.encode('utf-8')).hexdigest()
        if not secrets.compare_digest(expected, token):
            logger.warning(f"URL 鉴权: token 不匹配 path={path}")
            return False
        try:
            expiry = int(SettingsService().get_setting("url_auth_expiry", "300"))
            now = int(time.time())
            req_ts = int(ts)
            if now - req_ts > expiry or req_ts > now + 60:
                logger.warning(f"URL 鉴权: 时间戳过期 path={path} ts={ts} expiry={expiry}s")
                return False
        except (ValueError, TypeError):
            return False
        return True

    # ── Referer 鉴权 ────────────────────────────────────────────

    def is_referer_enabled(self) -> bool:
        return SettingsService().get_setting("referer_enabled", "False") == "True"

    def check_referer(self, referer: str) -> bool:
        raw = SettingsService().get_setting("referer_whitelist", "").strip()
        if not raw:
            return False
        allowed = [line.strip() for line in raw.replace('\r', '').split('\n') if line.strip()]
        if not allowed:
            return False
        for pattern in allowed:
            p = pattern.rstrip('/')
            if referer.startswith(p):
                return True
        return False

    # ── 远程鉴权（转发请求到外部服务器） ───────────────────────

    def is_remote_auth_enabled(self) -> bool:
        return SettingsService().get_setting("remote_auth_enabled", "False") == "True"

    def check_remote_auth(self, handler) -> tuple[bool, bool]:
        url = SettingsService().get_setting("remote_auth_url", "").strip()
        if not url:
            return False, False
        try:
            timeout = int(SettingsService().get_setting("remote_auth_timeout", "10"))
        except (ValueError, TypeError):
            timeout = 10
        body = json.dumps({
            "path": handler.path,
            "method": handler.command,
            "headers": dict(handler.headers),
            "client_ip": handler.client_address[0],
            "timestamp": int(time.time()),
        }).encode('utf-8')
        req = urllib.request.Request(url, data=body, method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('User-Agent', 'PersonalDAV/1.0')
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            if resp.status != 200:
                logger.warning(f"远程鉴权: HTTP {resp.status} from {url}")
                return False, False
            data = resp.read().decode('utf-8').strip().lower()
            if data in ('allow', 'ok', 'true', '1', 'yes'):
                logger.info(f"远程鉴权: 允许 path={handler.path}")
                return True, True
            logger.warning(f"远程鉴权: 拒绝 path={handler.path} response={data}")
            return False, True
        except Exception as e:
            logger.warning(f"远程鉴权: 请求失败 {url} - {e}")
            return False, False

    # ── 鉴权日志（防抵赖哈希链） ────────────────────────────────

    @staticmethod
    def _get_last_hash() -> str:
        row = Database().query_one("SELECT hash FROM auth_logs ORDER BY id DESC LIMIT 1")
        return row[0] if row else "0"

    @staticmethod
    def _compute_hash(prev_hash: str, timestamp: str, ip: str, success: int, method: str, detail: str) -> str:
        data = f"{prev_hash}|{timestamp}|{ip}|{success}|{method}|{detail}"
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

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
        try:
            ts = datetime.now().isoformat()
            succ = 1 if success else 0
            prev_hash = self._get_last_hash()
            h = self._compute_hash(prev_hash, ts, client_ip, succ, method, extra)
            Database().execute(
                "INSERT INTO auth_logs (timestamp, ip, success, method, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (ts, client_ip, succ, method, extra, prev_hash, h)
            )
        except Exception as e:
            logger.warning(f"写入鉴权日志失败: {e}")

    @staticmethod
    def verify_auth_chain() -> list[dict]:
        rows = Database().query("SELECT id, timestamp, ip, success, method, detail, prev_hash, hash FROM auth_logs ORDER BY id ASC")
        broken = []
        prev = "0"
        for r in rows:
            expected = AuthService._compute_hash(prev, r[1], r[2], r[3], r[4] or "", r[5] or "")
            if expected != r[7]:
                broken.append({"id": r[0], "expected": expected, "actual": r[7]})
            prev = r[7]
            if r[6] != "0" and r[6] != prev:
                broken.append({"id": r[0], "type": "prev_hash_mismatch", "expected_prev": prev, "stored_prev": r[6]})
        return broken

    def get_auth_logs_filtered(self, protocol: str = "", limit: int = 500) -> list[dict]:
        try:
            if protocol:
                rows = Database().query(
                    "SELECT id, timestamp, ip, success, method, detail FROM auth_logs WHERE method LIKE ? ORDER BY id DESC LIMIT ?",
                    (f"%{protocol}%", limit)
                )
            else:
                rows = Database().query(
                    "SELECT id, timestamp, ip, success, method, detail FROM auth_logs ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
            return [
                {"id": r[0], "time": r[1], "ip": r[2], "success": bool(r[3]), "method": r[4] or "", "detail": r[5] or ""}
                for r in rows
            ]
        except Exception:
            return []

    def get_auth_logs(self, limit: int = 200) -> list[dict]:
        try:
            rows = Database().query(
                "SELECT timestamp, ip, success, method, detail FROM auth_logs ORDER BY id DESC LIMIT ?",
                (limit,)
            )
            return [
                {"time": r[0], "ip": r[1], "success": bool(r[2]), "method": r[3] or "", "detail": r[4] or ""}
                for r in rows
            ]
        except Exception:
            return []
