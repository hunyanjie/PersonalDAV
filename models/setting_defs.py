from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class SettingDef:
    key: str
    label: str
    widget_type: str
    section: str
    default: Any = ""
    db_default: str = ""
    options: Optional[list] = None
    width: Optional[int] = None
    spin_from: Optional[int] = None
    spin_to: Optional[int] = None
    columnspan: int = 1
    display_map: Optional[Dict[str, str]] = None

    def __post_init__(self):
        if not self.db_default:
            self.db_default = str(self.default)
