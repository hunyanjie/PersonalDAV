"""Unified auth middleware + token scope support for ASGI."""

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from services.auth_service import AuthService

# Token-based auth for REST API
_bearer = HTTPBearer(auto_error=False)

SCOPE_MAP: dict[str, dict[str, str]] = {
    "GET": {"contacts": "contacts:read", "events": "events:read", "dav": "dav:read"},
    "HEAD": {"contacts": "contacts:read", "events": "events:read", "dav": "dav:read"},
    "PUT": {"contacts": "contacts:write", "events": "events:write", "dav": "dav:write"},
    "POST": {"contacts": "contacts:write", "events": "events:write", "dav": "dav:write"},
    "DELETE": {"contacts": "contacts:write", "events": "events:write", "dav": "dav:write"},
    "PROPFIND": {"contacts": "contacts:read", "events": "events:read", "dav": "dav:read"},
    "MKCOL": {"dav": "dav:write"},
    "COPY": {"dav": "dav:write"},
    "MOVE": {"dav": "dav:write"},
    "OPTIONS": {},
    "REPORT": {"contacts": "contacts:read", "events": "events:read"},
}


def _required_scope(method: str, path: str) -> str | None:
    method_map = SCOPE_MAP.get(method, {})
    if not method_map:
        return None
    for prefix, scope in method_map.items():
        if path.startswith(f"/{prefix}") or path.startswith(f"/api/{prefix}"):
            return scope
    return None


async def get_current_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    if credentials is None:
        raise HTTPException(401, "Authorization header required")
    svc = AuthService()
    if not svc.verify_mcp_token(credentials.credentials):
        raise HTTPException(403, "Invalid token")
    scope = getattr(credentials, "_scope", None)
    if scope and scope not in credentials.credentials:
        raise HTTPException(403, f"Insufficient scope: {scope}")
    return credentials.credentials


class AuthMiddleware(BaseHTTPMiddleware):
    """Unified ASGI auth middleware — applies to DAV + REST routes."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip docs/openapi
        if path.startswith("/api/docs") or path.startswith("/api/openapi"):
            return await call_next(request)

        svc = AuthService()
        client_ip = request.client.host if request.client else "127.0.0.1"

        # IP check
        if not svc.check_ip(client_ip):
            return Response("IP denied", status_code=403)

        # Rate limit
        if not svc.check_rate_limit(client_ip):
            return Response("Too Many Requests", status_code=429)

        # IP bypass (no password needed)
        if svc.ip_bypasses_auth(client_ip):
            return await call_next(request)

        # Password not required
        if not svc.is_password_required():
            return await call_next(request)

        # Try Bearer token (for REST API / MCP)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if svc.verify_mcp_token(token):
                svc.log_auth(True, client_ip, "ASGI", "Bearer token OK")
                return await call_next(request)

        # Try Basic Auth (for DAV clients)
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
                return await call_next(request)
            svc.log_auth(False, client_ip, "ASGI", "Basic Auth wrong password")
            return Response("Invalid password", status_code=401)

        # No auth
        svc.log_auth(False, client_ip, "ASGI", "No credentials")
        resp = Response("Authorization required", status_code=401)
        resp.headers["WWW-Authenticate"] = 'Basic realm="PersonalDAV"'
        return resp
