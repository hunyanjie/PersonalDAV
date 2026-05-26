import uuid
import vobject
from typing import Optional, List
from database.repositories.contact_repository import ContactRepository
from models.contact import ContactModel
from utils.logger import logger
from utils.vcard_parser import RobustVCardParser
from utils.event_bus import event_bus, EVENT_CONTACTS_CHANGED

class ContactService:
    """联系人业务逻辑 - 引入 Repository 模式、鲁棒解析与事件总线"""
    def __init__(self):
        self.repo = ContactRepository()

    def add_contact(self, vcard_data: str):
        """添加或更新联系人"""
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

            contact = ContactModel(**parsed_data)
            existing = self.repo.get_by_uid(contact.uid)
            operation = "inserted"
            if existing:
                operation = "unchanged" if existing.vcard == vcard_data else "updated"

            if operation != "unchanged":
                self.repo.add_or_update(contact)
                event_bus.publish(EVENT_CONTACTS_CHANGED) # 发布通知

            return contact.uid, operation
        except Exception as e:
            logger.error(f"Service 添加联系人失败: {str(e)}")
            return None, f"Error: {str(e)}"

    def get_contact(self, uid: str) -> str | None:
        contact = self.repo.get_by_uid(uid)
        return contact.vcard if contact else None

    def get_contacts_list(self):
        """返回元组列表以兼容 Treeview"""
        return [(c.uid, c.full_name, c.email, c.phone) for c in self.repo.get_all()]

    def get_all_vcards(self):
        return [c.vcard for c in self.repo.get_all()]

    def get_selected_vcards(self, uids: list):
        return [c.vcard for uid in uids if (c := self.repo.get_by_uid(uid))]

    def delete_contact(self, uid: str):
        return self.repo.delete(uid)

    def _extract_full_name(self, vcard):
        if hasattr(vcard, 'fn'): return vcard.fn.value
        if hasattr(vcard, 'n'):
            n = vcard.n.value
            return " ".join(filter(None, [getattr(n, k, "") for k in ['prefix', 'given', 'additional', 'family', 'suffix']]))
        return ""

    def _extract_emails(self, vcard):
        if hasattr(vcard, 'email_list'): return [e.value for e in vcard.email_list]
        if hasattr(vcard, 'email'): return [vcard.email.value]
        return []

    def _extract_phones(self, vcard):
        if hasattr(vcard, 'tel_list'): return [t.value for t in vcard.tel_list]
        if hasattr(vcard, 'tel'): return [vcard.tel.value]
        return []

    def _manual_add_contact(self, data):
        # 简化版手动解析，实际调用时会存入 repo
        # 此处省略具体实现细节，保持逻辑完整
        uid = str(uuid.uuid4())
        contact = ContactModel(uid=uid, full_name="Unknown", vcard=data)
        self.repo.add_or_update(contact)
        return uid, "inserted"
