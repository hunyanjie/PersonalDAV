"""
Service Gateway — 统一服务访问入口

职责：
1. 集中管理所有服务实例的生命周期
2. 延迟初始化（首次访问时才导入模块）
3. 单点追踪服务依赖关系，降低模块间耦合
"""

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from services.contact_service import ContactService
    from services.event_service import EventService
    from services.settings_service import SettingsService
    from services.auth_service import AuthService
    from services.ftp_service import FTPService
    from services.smb_service import SMBService
    from services.sync_service import SyncService
    from services.ftp_client_service import FTPClientService
    from services.mcp_server import MCPServer


class ServiceGateway:
    """服务网关 — 所有业务服务的统一访问点（单例）"""

    _instance: Optional['ServiceGateway'] = None

    _contact_service: Optional['ContactService'] = None
    _event_service: Optional['EventService'] = None
    _settings_service: Optional['SettingsService'] = None
    _auth_service: Optional['AuthService'] = None
    _ftp_service: Optional['FTPService'] = None
    _smb_service: Optional['SMBService'] = None
    _sync_service: Optional['SyncService'] = None
    _ftp_client_service: Optional['FTPClientService'] = None
    _mcp_server: Optional['MCPServer'] = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super().__new__(cls)
        return cls._instance

    @property
    def contact(self) -> 'ContactService':
        if not self._contact_service:
            from services.contact_service import ContactService
            self._contact_service = ContactService()
        return self._contact_service

    @property
    def event(self) -> 'EventService':
        if not self._event_service:
            from services.event_service import EventService
            self._event_service = EventService()
        return self._event_service

    @property
    def settings(self) -> 'SettingsService':
        if not self._settings_service:
            from services.settings_service import SettingsService
            self._settings_service = SettingsService()
        return self._settings_service

    @property
    def auth(self) -> 'AuthService':
        if not self._auth_service:
            from services.auth_service import AuthService
            self._auth_service = AuthService()
        return self._auth_service

    @property
    def ftp(self) -> 'FTPService':
        if not self._ftp_service:
            from services.ftp_service import FTPService
            self._ftp_service = FTPService()
        return self._ftp_service

    @property
    def smb(self) -> 'SMBService':
        if not self._smb_service:
            from services.smb_service import SMBService
            self._smb_service = SMBService()
        return self._smb_service

    @property
    def sync(self) -> 'SyncService':
        if not self._sync_service:
            from services.sync_service import SyncService
            self._sync_service = SyncService()
        return self._sync_service

    @property
    def ftp_client(self) -> 'FTPClientService':
        if not self._ftp_client_service:
            from services.ftp_client_service import FTPClientService
            self._ftp_client_service = FTPClientService()
        return self._ftp_client_service

    @property
    def mcp(self) -> 'MCPServer':
        if not self._mcp_server:
            from services.mcp_server import MCPServer
            self._mcp_server = MCPServer()
        return self._mcp_server


gateway = ServiceGateway()
