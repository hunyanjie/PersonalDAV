from services.contact_service import ContactService
from services.event_service import EventService
from services.ftp_service import FTPService
from services.smb_service import SMBService
from network.dav_server import DAVServer

CONTACT_SVC = ContactService()
EVENT_SVC = EventService()
FTP_SVC = FTPService()

server_instance: list[DAVServer | None] = [None]
