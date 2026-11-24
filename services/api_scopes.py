"""API 令牌作用域定义与路由权限映射。

集中维护作用域名称、中文标签、敏感设置键，以及每个 HTTP 路由所需的作用域。
鉴权中间件和 API 路由共用本模块，避免两边规则不一致。
"""

from typing import Final

SCOPE_LABELS: Final[dict[str, str]] = {
    "contacts:read": "联系人(只读)",
    "contacts:create": "联系人(创建)",
    "contacts:update": "联系人(编辑)",
    "contacts:delete": "联系人(删除)",
    "events:read": "日程(只读)",
    "events:create": "日程(创建)",
    "events:update": "日程(编辑)",
    "events:delete": "日程(删除)",
    "files:read": "文件(只读)",
    "files:upload": "文件(上传)",
    "files:rename": "文件(重命名)",
    "files:delete": "文件(删除)",
    "files:manage": "挂载点管理",
    "dav:read": "DAV(只读)",
    "dav:write": "DAV(读写)",
    "settings:read": "设置(只读)",
    "settings:write": "设置(编辑)",
    "trash:read": "回收站(只读)",
    "trash:write": "回收站(还原/清空)",
    "logs:read": "日志(只读)",
    "stats:read": "统计(只读)",
    "tokens:manage": "API 令牌管理",
}

ALL_SCOPES: Final[frozenset[str]] = frozenset(SCOPE_LABELS)

# 这些设置只允许桌面端/密码登录修改，不允许通过通用设置接口写入。
PROTECTED_SETTING_KEYS: Final[frozenset[str]] = frozenset({
    "access_password_hash",
    "mcp_token_salt",
    "mcp_token_rotated_at",
    "url_auth_secret",
})

_SENSITIVE_MARKERS: Final[tuple[str, ...]] = ("password", "secret", "salt", "_hash")


def is_sensitive_setting(key: str) -> bool:
    """判断设置值是否需要在 REST API 响应中脱敏。"""
    lowered = key.lower()
    return any(marker in lowered for marker in _SENSITIVE_MARKERS)


def mask_setting(key: str, value):
    """敏感设置统一返回掩码，避免密码哈希/密钥通过 API 泄露。"""
    return "********" if is_sensitive_setting(key) else value


# 顺序很重要：更具体的路径必须排在其父路径之前。
# (HTTP 方法, 路径前缀, 所需作用域)
_SCOPE_RULES: Final[tuple[tuple[str, str, str], ...]] = (
    # 令牌管理
    ("GET", "/api/auth/tokens", "tokens:manage"),
    ("POST", "/api/auth/tokens", "tokens:manage"),
    ("DELETE", "/api/auth/tokens", "tokens:manage"),
    ("PUT", "/api/auth/tokens", "tokens:manage"),
    # 设置与服务器信息
    ("GET", "/api/settings", "settings:read"),
    ("PUT", "/api/settings", "settings:write"),
    ("GET", "/api/server/config", "settings:read"),
    ("GET", "/api/apple/config", "settings:read"),
    ("GET", "/api/apple/qr", "settings:read"),
    # 日志与统计
    ("GET", "/api/auth/logs", "logs:read"),
    ("GET", "/api/logs", "logs:read"),
    ("GET", "/api/stats", "stats:read"),
    # 回收站
    ("GET", "/api/trash", "trash:read"),
    ("POST", "/api/trash", "trash:write"),
    ("DELETE", "/api/trash", "trash:write"),
    # 文件挂载管理必须先于普通文件操作
    ("GET", "/api/files/mounts", "files:read"),
    ("POST", "/api/files/mounts", "files:manage"),
    ("PUT", "/api/files/mounts", "files:manage"),
    ("DELETE", "/api/files/mounts", "files:manage"),
    # 文件内容 / 压缩包 / 卡片
    ("GET", "/api/files/text", "files:read"),
    ("PUT", "/api/files/text", "files:upload"),
    ("POST", "/api/files/archive/list", "files:read"),
    ("POST", "/api/files/archive/preview", "files:read"),
    ("POST", "/api/files/archive/extract", "files:upload"),
    ("GET", "/api/files/card", "files:read"),
    ("PUT", "/api/files/card", "files:upload"),
    # 文件操作
    ("GET", "/api/files", "files:read"),
    ("HEAD", "/api/files", "files:read"),
    ("POST", "/api/files/upload", "files:upload"),
    ("POST", "/api/files/mkdir", "files:upload"),
    ("PUT", "/api/files/rename", "files:rename"),
    ("DELETE", "/api/files", "files:delete"),
    # 联系人与日程
    ("GET", "/api/contacts", "contacts:read"),
    ("HEAD", "/api/contacts", "contacts:read"),
    ("POST", "/api/contacts", "contacts:create"),
    ("PUT", "/api/contacts", "contacts:update"),
    ("DELETE", "/api/contacts", "contacts:delete"),
    ("GET", "/api/events", "events:read"),
    ("HEAD", "/api/events", "events:read"),
    ("POST", "/api/events", "events:create"),
    ("PUT", "/api/events", "events:update"),
    ("DELETE", "/api/events", "events:delete"),
    # DAV 协议路径
    ("GET", "/contacts", "contacts:read"),
    ("HEAD", "/contacts", "contacts:read"),
    ("POST", "/contacts", "contacts:create"),
    ("PUT", "/contacts", "contacts:update"),
    ("DELETE", "/contacts", "contacts:delete"),
    ("GET", "/events", "events:read"),
    ("HEAD", "/events", "events:read"),
    ("POST", "/events", "events:create"),
    ("PUT", "/events", "events:update"),
    ("DELETE", "/events", "events:delete"),
    ("PROPFIND", "/contacts", "dav:read"),
    ("PROPFIND", "/events", "dav:read"),
    ("PROPFIND", "/dav", "dav:read"),
    ("PROPPATCH", "/dav", "dav:write"),
    ("REPORT", "/contacts", "contacts:read"),
    ("REPORT", "/events", "events:read"),
    ("MKCOL", "/dav", "dav:write"),
    ("COPY", "/dav", "dav:write"),
    ("MOVE", "/dav", "dav:write"),
)


def is_mcp_path(path: str) -> bool:
    """MCP 端点只接受 MCP 主令牌或密码登录，不接受普通 API 令牌。"""
    return path == "/mcp" or path.startswith("/mcp/")


def required_scope(method: str, path: str) -> str | None:
    """返回请求所需作用域；返回 ``tokens:manage`` 表示未分类的 API 路径。

    未分类的 ``/api/*`` 路由按“仅管理员令牌可访问”处理（fail closed），
    避免以后新增管理接口时忘记补作用域而造成越权。
    """
    if path == "/api/health":
        return None

    method = method.upper()
    for rule_method, prefix, scope in _SCOPE_RULES:
        if method != rule_method:
            continue
        if path == prefix or path.startswith(prefix + "/"):
            return scope

    if path.startswith("/api/"):
        return "tokens:manage"
    return None
