import base64
from utils.logger import logger


class AuthMiddleware:
    """DAV 认证中间件 — 抽取自 DAVHandler._check_auth"""

    @staticmethod
    def check_auth(handler) -> bool:
        from services.auth_service import AuthService
        svc = AuthService()
        client_ip = handler.client_address[0]
        ua = handler.headers.get('User-Agent', '')

        if not svc.check_ip(client_ip):
            svc.log_auth(False, client_ip, "WebDAV", f"IP被拒绝 UA={ua}")
            AuthMiddleware._send_401(handler)
            return False

        if not svc.check_rate_limit(client_ip):
            handler.send_response(429)
            handler.send_header('Content-Type', 'text/plain')
            handler.end_headers()
            handler.wfile.write(b"Too Many Requests")
            return False

        if svc.ip_bypasses_auth(client_ip):
            svc.log_auth(True, client_ip, "WebDAV", f"免密 IP UA={ua}")
            return True

        if not svc.is_password_required():
            return True

        auth = handler.headers.get('Authorization', '')
        if not auth.startswith('Basic '):
            svc.log_auth(False, client_ip, "WebDAV", f"无凭证 UA={ua}")
            AuthMiddleware._send_401(handler)
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode('utf-8')
            _, password = decoded.split(':', 1)
        except Exception:
            svc.log_auth(False, client_ip, "WebDAV", f"凭证格式错误 UA={ua}")
            AuthMiddleware._send_401(handler)
            return False
        if not svc.verify_password(password):
            svc.log_auth(False, client_ip, "WebDAV", f"密码错误 UA={ua}")
            AuthMiddleware._send_401(handler)
            return False

        svc.log_auth(True, client_ip, "WebDAV", f"UA={ua}")
        return True

    @staticmethod
    def _send_401(handler):
        handler.send_response(401)
        handler.send_header('WWW-Authenticate', 'Basic realm="PersonalDAV"')
        handler.send_header('Content-Type', 'text/plain')
        handler.end_headers()
        handler.wfile.write(b"Authorization required")
