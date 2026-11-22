import os
import uuid
import base64
import shutil
from typing import BinaryIO
from utils.logger import logger


def get_attachments_dir() -> str:
    """返回当前数据目录下的日历附件目录（随 data_dir 设置变化）。"""
    from utils.path_helper import resolve_data_path
    path = resolve_data_path("calendar_attachments")
    os.makedirs(path, exist_ok=True)
    return path


def _resolve_path(filepath: str) -> str:
    """兼容旧记录中写死的 data/calendar_attachments/... 路径。"""
    if not filepath:
        return filepath
    if os.path.isfile(filepath):
        return filepath
    # 旧记录可能保存的是相对路径；先按原始路径找，再按文件名回落到当前附件目录。
    from utils.path_helper import resolve_data_path
    candidate = resolve_data_path(filepath)
    if os.path.isfile(candidate):
        return candidate
    fallback = os.path.join(get_attachments_dir(), os.path.basename(filepath))
    return fallback if os.path.isfile(fallback) else filepath


def _ext(ext: str) -> str:
    return ext if ext.startswith(".") else f".{ext}" if ext else ".bin"


def save(data: bytes, filename: str, fmttype: str = "application/octet-stream") -> dict:
    attachments_dir = get_attachments_dir()
    uid = str(uuid.uuid4())
    _, e = os.path.splitext(filename)
    dest = os.path.join(attachments_dir, f"{uid}{_ext(e)}")
    with open(dest, "wb") as f:
        f.write(data)
    size = len(data)
    logger.debug(f"附件已保存: {dest} ({size} 字节)")
    return {"filepath": dest, "filename": filename, "fmttype": fmttype, "size": size}


def read(record: dict) -> bytes | None:
    fp = _resolve_path(record.get("filepath", ""))
    if not fp or not os.path.isfile(fp):
        return None
    try:
        with open(fp, "rb") as f:
            return f.read()
    except Exception:
        return None


def delete(record: dict):
    fp = _resolve_path(record.get("filepath", ""))
    if fp and os.path.isfile(fp):
        try:
            os.remove(fp)
            logger.debug(f"附件已删除: {fp}")
        except Exception as e:
            logger.warning(f"删除附件失败: {fp} - {e}")


def from_base64(b64_data: str, filename: str, fmttype: str = "application/octet-stream") -> dict:
    try:
        data = base64.b64decode(b64_data)
        return save(data, filename, fmttype)
    except Exception as e:
        logger.error(f"Base64 解码附件失败: {e}")
        size_est = int(len(b64_data) * 3 / 4)
        return {"filepath": "", "filename": filename, "fmttype": fmttype, "size": size_est, "_b64_fallback": b64_data}


def to_base64(record: dict) -> str | None:
    if "_b64_fallback" in record:
        return record["_b64_fallback"]
    data = read(record)
    if data is None:
        return None
    return base64.b64encode(data).decode("ascii")
