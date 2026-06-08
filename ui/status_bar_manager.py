import time
import os
from database.db_manager import Database


class StatusBarManager:
    """状态栏管理器 — 从 DAVServerApp 提取"""

    def __init__(self, status_bar, contact_service, event_service, mcp_server, server_tab):
        self._bar = status_bar
        self.contact_service = contact_service
        self.event_service = event_service
        self.mcp_server = mcp_server
        self.server_tab = server_tab
        self._pending_update = None

    def get_pending_update(self):
        return self._pending_update

    def set_pending_update(self, version):
        self._pending_update = version

    def refresh(self, *args):
        c_count = self.contact_service.count()
        e_count = self.event_service.count()
        mcp = "MCP 运行中" if self.mcp_server is not None and self.mcp_server.is_running else "MCP 已关闭"
        server = self.server_tab.server_instance
        srv = f"运行中 ({self._format_uptime(server.start_time)})" if server else "已停止"
        db_size = self._get_db_size()
        update_text = ""
        if self._pending_update:
            update_text = f" | 📥 新版本 v{self._pending_update} 可用"
        self._bar.config(text=f"联系人: {c_count} | 事件: {e_count} | DB: {db_size} | MCP: {mcp} | 服务器: {srv}{update_text}")

    def tick(self, root):
        self.refresh()
        root.after(100, lambda: self.tick(root))

    def _get_db_size(self):
        try:
            db = Database()
            size = os.path.getsize(db.db_path)
            if size < 1024:
                return f"{size}B"
            elif size < 1024 * 1024:
                return f"{size / 1024:.0f}KB"
            else:
                return f"{size / 1024 / 1024:.1f}MB"
        except Exception:
            return "?"

    @staticmethod
    def _format_uptime(start):
        elapsed = int(time.time() - start)
        h, m = divmod(elapsed, 3600)
        m, s = divmod(m, 60)
        if h:
            return f"{h}h{m}m"
        elif m:
            return f"{m}m{s}s"
        return f"{s}s"
