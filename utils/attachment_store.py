import os
import uuid
import base64
import shutil
from typing import BinaryIO
from utils.logger import logger

ATTACHMENTS_DIR = "data/attachments"


def _ensure_dir():
    os.makedirs(ATTACHMENTS_DIR, exist_ok=True)


def _ext(ext: str) -> str:
    return ext if ext.startswith(".") else f".{ext}" if ext else ".bin"


def save(data: bytes, filename: str, fmttype: str = "application/octet-stream") -> dict:
    _ensure_dir()
    uid = str(uuid.uuid4())
    _, e = os.path.splitext(filename)
    dest = os.path.join(ATTACHMENTS_DIR, f"{uid}{_ext(e)}")
    with open(dest, "wb") as f:
        f.write(data)
    size = len(data)
    logger.debug(f"附件已保存: {dest} ({size} 字节)")
    return {"filepath": dest, "filename": filename, "fmttype": fmttype, "size": size}


def read(record: dict) -> bytes | None:
    fp = record.get("filepath", "")
    if not fp or not os.path.isfile(fp):
        return None
    try:
        with open(fp, "rb") as f:
            return f.read()
    except Exception:
        return None


def delete(record: dict):
    fp = record.get("filepath", "")
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
