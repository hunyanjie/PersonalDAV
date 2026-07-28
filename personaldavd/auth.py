"""Unified auth middleware + token scope support for ASGI."""

import asyncio

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from services.auth_service import AuthService

# Token-based auth for REST API
_bearer = HTTPBearer(auto_error=False)

SCOPE_MAP: dict[str, dict[str, str]] = {
    "GET": {"contacts": "contacts:read", "events": "events:read", "dav": "dav:read", "files": "files:read"},
    "HEAD": {"contacts": "contacts:read", "events": "events:read", "dav": "dav:read", "files": "files:read"},
    "PUT": {"contacts": "contacts:update", "events": "events:update", "dav": "dav:write", "files/rename": "files:rename"},
    "POST": {"files/upload": "files:upload", "files/rename": "files:rename", "files/mkdir": "files:upload",
             "contacts": "contacts:create", "events": "events:create"},
    "DELETE": {"contacts": "contacts:delete", "events": "events:delete", "dav": "dav:write",
               "files": "files:delete"},
    "PROPFIND": {"contacts": "dav:read", "events": "dav:read", "dav": "dav:read"},
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


# MCP tokens get all scopes (same as a full-access API token)
_MCP_SCOPES = {"contacts:read", "contacts:create", "contacts:update", "contacts:delete",
               "events:read", "events:create", "events:update", "events:delete",
               "files:read", "files:upload", "files:delete", "files:rename",
               "dav:read", "dav:write", "settings:read", "settings:write"}

def _mcp_token_has_scope(required: str) -> bool:
    return required in _MCP_SCOPES


async def get_current_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> str:
    svc = AuthService()
    if not svc.is_password_required():
        return "bypass"
    if credentials is None:
        raise HTTPException(401, "Authorization header required")
    # 认证已由 AuthMiddleware 中间件完成，此处仅传递 token
    return credentials.credentials


class AuthMiddleware(BaseHTTPMiddleware):
    """Unified ASGI auth middleware — applies to DAV + REST routes."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Skip docs/openapi + public SPA assets + login
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

        # ── All blocking checks offloaded to thread pool ──

        # IP check
        if not await asyncio.to_thread(svc.check_ip, client_ip):
            return Response("IP denied", status_code=403)

        # Referer check
        referer_enabled = await asyncio.to_thread(svc.is_referer_enabled)
        if referer_enabled:
            if not referer:
                return Response("Referer required", status_code=403)
            if not await asyncio.to_thread(svc.check_referer_advanced, referer):
                return Response("Referer denied", status_code=403)

        # User-Agent check
        if ua:
            ua_allowed = await asyncio.to_thread(svc.check_user_agent, ua)
            if not ua_allowed:
                return Response("User-Agent denied", status_code=403)

        # Rate limit
        if not await asyncio.to_thread(svc.check_rate_limit, client_ip):
            return Response("Too Many Requests", status_code=429)

        # IP bypass (no password needed)
        if await asyncio.to_thread(svc.ip_bypasses_auth, client_ip):
            return await call_next(request)

        # Password not required
        if not await asyncio.to_thread(svc.is_password_required):
            return await call_next(request)

        # Try Bearer token (for REST API / MCP)
        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif request.method == "GET" and request.url.path.startswith("/api/files/"):
            token = request.query_params.get("token", "")
        if token:
            scope = _required_scope(request.method, request.url.path)
            # Full MCP token
            if await asyncio.to_thread(svc.verify_mcp_token, token):
                await asyncio.to_thread(svc.log_auth, True, client_ip, "ASGI", "Bearer token OK")
                if scope and not _mcp_token_has_scope(scope):
                    await asyncio.to_thread(svc.log_auth, False, client_ip, "ASGI", f"MCP scope denied: {scope}")
                    return Response("Insufficient permissions", status_code=403)
                return await call_next(request)
            # API 令牌 (v3.4)
            from services.api_token_service import ApiTokenService
            ats = ApiTokenService()
            tok_data = await asyncio.to_thread(ats.verify_token, token)
            if tok_data:
                if scope and not any(s == scope for s in tok_data['scopes']):
                    await asyncio.to_thread(svc.log_auth, False, client_ip, "ASGI", f"Token scope denied: {scope}")
                    return Response("Insufficient permissions", status_code=403)
                await asyncio.to_thread(svc.log_auth, True, client_ip, "ASGI", f"API token OK: {tok_data['note'] or tok_data['id']}")
                return await call_next(request)

        # Try Basic Auth (for DAV clients)
        if auth_header.startswith("Basic "):
            import base64
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                _, password = decoded.split(":", 1)
            except Exception:
                await asyncio.to_thread(svc.log_auth, False, client_ip, "ASGI", "Bad Basic Auth format")
                return Response("Bad auth format", status_code=401)
            # PBKDF2 — offload to thread pool (100-500ms)
            pw_ok = await asyncio.to_thread(svc.verify_password, password)
            if pw_ok:
                await asyncio.to_thread(svc.log_auth, True, client_ip, "ASGI", "Basic Auth OK")
                return await call_next(request)
            await asyncio.to_thread(svc.log_auth, False, client_ip, "ASGI", "Basic Auth wrong password")
            return Response("Invalid password", status_code=401)

        # No auth
        await asyncio.to_thread(svc.log_auth, False, client_ip, "ASGI", "No credentials")
        resp = Response("Authorization required", status_code=401)
        from config import SOFTWARE_NAME
        resp.headers["WWW-Authenticate"] = f'Basic realm="{SOFTWARE_NAME}"'
        return resp
