import quopri
import base64

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
