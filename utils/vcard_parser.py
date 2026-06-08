import base64
import quopri
import uuid
from abc import ABC, abstractmethod
from utils.logger import logger

class DecodingStrategy(ABC):
    """解码策略接口 (Strategy Pattern)"""
    @abstractmethod
    def decode(self, data: str, charset: str) -> str:
        pass

class QuotedPrintableStrategy(DecodingStrategy):
    def decode(self, data: str, charset: str) -> str:
        try:
            return quopri.decodestring(data).decode(charset, errors="replace")
        except Exception:
            return data

class Base64Strategy(DecodingStrategy):
    def decode(self, data: str, charset: str) -> str:
        try:
            return base64.b64decode(data).decode(charset, errors="replace")
        except Exception:
            return data

class PlainStrategy(DecodingStrategy):
    def decode(self, data: str, charset: str) -> str:
        return data

class RobustVCardParser:
    """
    鲁棒性 vCard 解析器 - Flawless 架构演进版
    引入策略模式处理编码，并 1:1 还原旧版降级逻辑
    """
    _strategies = {
        "quoted-printable": QuotedPrintableStrategy(),
        "base64": Base64Strategy(),
        "b": Base64Strategy()
    }
    _default_strategy = PlainStrategy()

    @classmethod
    def manual_parse(cls, vcard_data):
        try:
            properties = {}
            current_property = None

            for line in vcard_data.splitlines():
                line = line.strip()
                if not line: continue

                # 处理折行逻辑
                if line.startswith(" ") or line.startswith("\t"):
                    if current_property:
                        properties[current_property]["value"] += line.strip()
                    continue

                if ":" in line:
                    name_part, value_part = line.split(":", 1)
                    parts = name_part.split(";")
                    name = parts[0].strip().upper()
                    params = {k.lower(): v for p in parts[1:] if "=" in p for k, v in [p.split("=", 1)]}

                    # 应用解码策略 (Flawless Strategy Pattern)
                    encoding = params.get("encoding", "").lower()
                    charset = params.get("charset", "utf-8").lower()
                    strategy = cls._strategies.get(encoding, cls._default_strategy)
                    
                    value = strategy.decode(value_part, charset)

                    # 兼容性 CHARSET 处理
                    if charset != "utf-8" and strategy == cls._default_strategy:
                        try:
                            value = value.encode('latin1').decode(charset, errors="replace")
                        except Exception:
                            logger.debug("vCard CHARSET 编码转换失败")

                    properties[name] = {"value": value, "params": params}
                    current_property = name

            # 1:1 核心字段提取逻辑
            uid = properties.get("UID", {}).get("value", str(uuid.uuid4()))
            full_name = properties.get("FN", {}).get("value", "")

            if not full_name and "N" in properties:
                n_parts = properties["N"]["value"].split(";")
                if len(n_parts) >= 5:
                    parts = [properties["N"]["value"].split(";")[i] for i in [3, 1, 2, 0, 4] if i < len(n_parts)]
                    full_name = " ".join(filter(None, parts))

            return {
                "uid": uid,
                "full_name": full_name,
                "email": ";".join([v["value"] for k, v in properties.items() if k.startswith("EMAIL")]),
                "phone": ";".join([v["value"] for k, v in properties.items() if k.startswith("TEL")]),
                "vcard": vcard_data
            }
        except Exception as e:
            logger.error(f"vCard 策略解析失败: {str(e)}")
            return None
