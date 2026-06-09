import base64
from urllib.parse import urlparse, parse_qs
from utils.logger import logger


class AuthMiddleware:
    """DAV 认证中间件 — 抽取自 DAVHandler._check_auth"""

    @staticmethod
    def check_auth(handler) -> bool:
        from services.auth_service import AuthService
        svc = AuthService()
        client_ip = handler.client_address[0]
        ua = handler.headers.get('User-Agent', '')
        path = handler.path.split('?')[0]

        # ── URL 鉴权（仅 /attachments/） ────────────────────────
        if svc.is_url_auth_enabled() and path.startswith("/attachments/"):
            parsed = urlparse(handler.path)
            params = parse_qs(parsed.query)
            token = params.get('token', [None])[0]
            ts = params.get('ts', [None])[0]
            nonce = params.get('nonce', [None])[0]
            if not token or not ts or not nonce:
                AuthMiddleware._send_403(handler, "缺少 URL 鉴权参数")
                svc.log_auth(False, client_ip, "URL-Auth", f"参数缺失 path={path}")
                return False
            if not svc.verify_url_token(path, token, ts, nonce):
                AuthMiddleware._send_403(handler, "URL 鉴权失败")
                svc.log_auth(False, client_ip, "URL-Auth", f"令牌无效 path={path}")
                return False
            svc.log_auth(True, client_ip, "URL-Auth", f"path={path}")
            return True

        # ── Referer 鉴权 ────────────────────────────────────────
        if svc.is_referer_enabled():
            referer = handler.headers.get('Referer', '')
            if not referer:
                AuthMiddleware._send_403(handler, "需要 Referer 头")
                svc.log_auth(False, client_ip, "Referer", f"无 Referer path={path}")
                return False
            if not svc.check_referer(referer):
                AuthMiddleware._send_403(handler, "Referer 不允许")
                svc.log_auth(False, client_ip, "Referer", f"拒绝 referer={referer}")
                return False

        # ── 远程鉴权（替代密码校验） ────────────────────────────
        remote_ok = False
        remote_replied = False
        if svc.is_remote_auth_enabled():
            remote_ok, remote_replied = svc.check_remote_auth(handler)
            if remote_replied and not remote_ok:
                AuthMiddleware._send_403(handler, "远程鉴权拒绝")
                svc.log_auth(False, client_ip, "Remote-Auth", f"远程拒绝 path={path}")
                return False

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

        # 远程鉴权通过则跳过密码校验
        if remote_replied and remote_ok:
            svc.log_auth(True, client_ip, "WebDAV", f"远程鉴权通过 UA={ua}")
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

    @staticmethod
    def _send_403(handler, msg):
        handler.send_response(403)
        handler.send_header('Content-Type', 'text/plain')
        handler.end_headers()
        handler.wfile.write(msg.encode('utf-8'))
