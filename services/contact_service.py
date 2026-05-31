import uuid
from datetime import datetime
import vobject
from database.repositories.contact_repository import ContactRepository
from models.contact import ContactModel
from services.base_service import BaseService
from utils.logger import logger
from utils.vcard_parser import RobustVCardParser
from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED

class ContactService(BaseService):
    """联系人业务逻辑 - 单例模式"""
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(ContactService, cls).__new__(cls)
            cls._instance.__init__(
                repo=ContactRepository(),
                changed_event=EVENT_CONTACTS_CHANGED,
                raw_field='vcard',
                list_fields=['uid', 'full_name', 'email', 'phone', 'created_at', 'updated_at']
            )
        return cls._instance

    def add_contact(self, vcard_data: str, force: bool = False, publish: bool = True):
        """添加或更新联系人。force=True 时即使内容相同也覆盖更新。"""
        try:
            parsed_data = None
            try:
                vcard = vobject.readOne(vcard_data)
                uid_node = getattr(vcard, 'uid', None)
                uid = uid_node.value if uid_node else str(uuid.uuid4())
                parsed_data = {
                    "uid": uid,
                    "full_name": self._extract_full_name(vcard),
                    "email": ";".join(self._extract_emails(vcard)),
                    "phone": ";".join(self._extract_phones(vcard)),
                    "vcard": vcard_data
                }
            except Exception as e:
                logger.warning(f"vobject 解析失败，切换到鲁棒手动解析: {str(e)}")
                parsed_data = RobustVCardParser.manual_parse(vcard_data)

            if not parsed_data:
                return None, "Parse Error"

            now = datetime.now().isoformat()
            contact = ContactModel(**parsed_data)
            existing = self.repo.get_by_uid(contact.uid)
            operation = "inserted"
            if existing:
                operation = "unchanged" if existing.vcard == vcard_data else "updated"
                if force:
                    operation = "updated"
                contact.created_at = existing.created_at or now
                contact.updated_at = now
            else:
                contact.created_at = now
                contact.updated_at = now

            if operation != "unchanged":
                self.repo.add_or_update(contact)
                if publish:
                    event_bus.publish(EVENT_CONTACTS_CHANGED)

            return contact.uid, operation
        except Exception as e:
            logger.error(f"Service 添加联系人失败: {str(e)}")
            return None, f"Error: {str(e)}"

    def _extract_full_name(self, vcard):
        if hasattr(vcard, 'fn'): return vcard.fn.value
        if hasattr(vcard, 'n'):
            n = vcard.n.value
            parts = [getattr(n, k, "") for k in ['prefix', 'given', 'additional', 'family', 'suffix']]
            return " ".join(filter(None, parts))
        return ""

    def _extract_emails(self, vcard):
        if hasattr(vcard, 'email_list'): return [e.value for e in vcard.email_list]
        if hasattr(vcard, 'email'): return [vcard.email.value]
        return []

    def _extract_phones(self, vcard):
        if hasattr(vcard, 'tel_list'): return [t.value for t in vcard.tel_list]
        if hasattr(vcard, 'tel'): return [vcard.tel.value]
        return []
