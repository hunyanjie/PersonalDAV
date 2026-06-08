from services.smb_service import SMBService
from network.dav_server import DAVServer

_CONTACT_SVC = None
_EVENT_SVC = None
_FTP_SVC = None

def get_contact_svc():
    global _CONTACT_SVC
    if _CONTACT_SVC is None:
        from services.contact_service import ContactService
        _CONTACT_SVC = ContactService()
    return _CONTACT_SVC

def get_event_svc():
    global _EVENT_SVC
    if _EVENT_SVC is None:
        from services.event_service import EventService
        _EVENT_SVC = EventService()
    return _EVENT_SVC

def get_ftp_svc():
    global _FTP_SVC
    if _FTP_SVC is None:
        from services.ftp_service import FTPService
        _FTP_SVC = FTPService()
    return _FTP_SVC

server_instance: list[DAVServer | None] = [None]
