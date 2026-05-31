from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ContactModel:
    """联系人强类型数据模型"""
    uid: str
    full_name: str
    email: str = ""
    phone: str = ""
    vcard: str = ""
    id: Optional[int] = None
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self):
        return {
            "id": self.id,
            "uid": self.uid,
            "full_name": self.full_name,
            "email": self.email,
            "phone": self.phone,
            "vcard": self.vcard,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
