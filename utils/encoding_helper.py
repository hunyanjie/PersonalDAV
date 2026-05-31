import quopri
import base64
import re

def should_encode(text: str) -> bool:
    """判断字符串是否包含非 ASCII 字符，决定是否需要编码"""
    if not text:
        return False
    try:
        text.encode('ascii')
        return False
    except UnicodeEncodeError:
        return True

def smart_quoted_printable_encode(text: str) -> str:
    """智能 QP 编码：仅在必要时编码"""
    if not text:
        return ""
    if not should_encode(text):
        return text

    # 按照 vCard/iCal 规范构造编码前缀
    encoded_val = quopri.encodestring(text.encode('utf-8')).decode('utf-8')
    # 注意：vobject 会处理一部分，但在手动拼接时需要
    return encoded_val

def smart_quoted_printable_decode(data: str, charset: str = 'utf-8') -> str:
    """解码 QP 数据"""
    try:
        return quopri.decodestring(data).decode(charset, errors="replace")
    except:
        return data

def decode_ical_value(value) -> str:
    """解码 iCalendar 属性值，处理 QP 编码和换行符"""
    if value is None:
        return ""

    text = str(value)

    # 如果包含 QP 编码前缀，尝试解码
    if 'ENCODING=QUOTED-PRINTABLE' in text or ('=' in text and re.search(r'=[0-9A-Fa-f]{2}', text)):
        try:
            # 移除编码参数前缀
            text = re.sub(r'ENCODING=QUOTED-PRINTABLE;CHARSET=UTF-8:', '', text)
            # 将软换行 (=\n) 转换为实际换行，再解码 QP
            text = text.replace('=\n', '').replace('=\r\n', '')
            return quopri.decodestring(text.encode('utf-8')).decode('utf-8', errors='replace')
        except:
            pass

    # 尝试解码 base64
    if 'ENCODING=BASE64' in text:
        try:
            text = re.sub(r'ENCODING=BASE64:', '', text)
            return base64.b64decode(text).decode('utf-8', errors='replace')
        except:
            pass

    return text
