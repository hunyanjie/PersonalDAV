"""Unified auth middleware + token scope support for ASGI."""

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from services.api_scopes import required_scope
from services.auth_service import AuthService

# Token-based auth for REST API
_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class AuthContext:
    """本次请求的鉴权结果。

    ``scopes is None`` 表示完全权限（密码登录、本机免密、MCP 主令牌）。
    ``auth_type == "api_token"`` 时 ``scopes`` 是该令牌被授予的作用域集合。
    """

    auth_type: str
    scopes: frozenset[str] | None = None
    token_id: str | None = None

    @property
    def is_full_access(self) -> bool:
        return self.scopes is None

    def has_scope(self, scope: str) -> bool:
        return self.is_full_access or scope in self.scopes


def get_auth_context(request: Request) -> AuthContext | None:
    """读取中间件写入的鉴权上下文。"""
    return getattr(request.state, "auth_context", None)


async def get_current_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    """供业务路由声明“需要鉴权”，鉴权本身由 AuthMiddleware 完成。"""
    ctx = get_auth_context(request)
    if ctx is None:
        # 理论上不会走到这里；保留兜底，避免绕过中间件时静默放行。
        svc = AuthService()
        client_ip = request.client.host if request.client else "127.0.0.1"
        if not svc.is_password_required() or svc.ip_bypasses_auth(client_ip):
            return "bypass"
        raise HTTPException(401, "Authorization header required")
    if ctx.auth_type == "bypass":
        return "bypass"
    return credentials.credentials if credentials is not None else "bypass"


class AuthMiddleware(BaseHTTPMiddleware):
    """Unified ASGI auth middleware — applies to DAV + REST routes."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if (path.startswith("/api/docs") or path.startswith("/api/openapi") or
            path.startswith("/assets") or path.startswith("/icons") or
            path == "/" or path == "/index.html" or
            path == "/manifest.json" or path == "/sw.js" or
            path == "/api/auth/token"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "127.0.0.1"
        ua = request.headers.get("user-agent", "")
        referer = request.headers.get("referer", "")

        svc = AuthService()

        if not svc.check_ip(client_ip):
            return Response("IP denied", status_code=403)

        if svc.is_referer_enabled():
            if not referer:
                return Response("Referer required", status_code=403)
            if not svc.check_referer_advanced(referer):
                return Response("Referer denied", status_code=403)

        if ua and not svc.check_user_agent(ua):
            return Response("User-Agent denied", status_code=403)

        if not svc.check_rate_limit(client_ip):
            return Response("Too Many Requests", status_code=429)

        if svc.ip_bypasses_auth(client_ip):
            request.state.auth_context = AuthContext("bypass")
            return await call_next(request)

        if not svc.is_password_required():
            request.state.auth_context = AuthContext("bypass")
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif request.method == "GET" and request.url.path.startswith("/api/files/"):
            token = request.query_params.get("token", "")
        if token:
            scope = required_scope(request.method, path)
            if svc.verify_mcp_token(token):
                svc.log_auth(True, client_ip, "ASGI", "Bearer token OK")
                request.state.auth_context = AuthContext("mcp")
                return await call_next(request)

            from services.api_token_service import ApiTokenService
            ats = ApiTokenService()
            tok_data = ats.verify_token(token)
            if tok_data:
                token_scopes = frozenset(tok_data["scopes"])
                if scope and scope not in token_scopes:
                    svc.log_auth(False, client_ip, "ASGI", f"Token scope denied: {scope}")
                    return Response("Insufficient permissions", status_code=403)
                svc.log_auth(True, client_ip, "ASGI", f"API token OK: {tok_data['note'] or tok_data['id']}")
                request.state.auth_context = AuthContext(
                    "api_token", token_scopes, tok_data["id"]
                )
                return await call_next(request)

        if auth_header.startswith("Basic "):
            import base64
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                _, password = decoded.split(":", 1)
            except Exception:
                svc.log_auth(False, client_ip, "ASGI", "Bad Basic Auth format")
                return Response("Bad auth format", status_code=401)
            if svc.verify_password(password):
                svc.log_auth(True, client_ip, "ASGI", "Basic Auth OK")
                request.state.auth_context = AuthContext("basic")
                return await call_next(request)
            svc.log_auth(False, client_ip, "ASGI", "Basic Auth wrong password")
            return Response("Invalid password", status_code=401)

        svc.log_auth(False, client_ip, "ASGI", "No credentials")
        resp = Response("Authorization required", status_code=401)
        from config import SOFTWARE_NAME
        resp.headers["WWW-Authenticate"] = f'Basic realm="{SOFTWARE_NAME}"'
        return resp
