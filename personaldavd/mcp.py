"""MCP protocol integration — mount into FastAPI ASGI runtime."""

from mcp.server.fastmcp import FastMCP
from starlette.routing import Mount, Host


def create_mcp_app():
    """Create a Starlette ASGI app for the MCP SSE protocol.

    Returns a `Starlette` instance (from ``FastMCP.sse_app()``)
    that handles ``/sse`` and ``/messages/`` routes.
    """

    from config import SOFTWARE_NAME
    mcp = FastMCP(SOFTWARE_NAME)

    from mcp_tools import server_tools, contact_tools, event_tools
    from mcp_tools import config_tools, webdav_tools, ftp_tools, smb_tools, analysis_tools

    server_tools.register(mcp)
    contact_tools.register(mcp)
    event_tools.register(mcp)
    config_tools.register(mcp)
    webdav_tools.register(mcp)
    ftp_tools.register(mcp)
    smb_tools.register(mcp)
    analysis_tools.register(mcp)

    app = mcp.sse_app()
    return app
