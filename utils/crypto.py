import os
from config import DEFAULT_DB_PATH
from cryptography.fernet import Fernet


_KEY_FILE = "remote_connections.key"


def _get_key_path():
    return os.path.join(os.path.dirname(DEFAULT_DB_PATH) or ".", _KEY_FILE)


def _load_or_create_key() -> bytes:
    key_path = _get_key_path()
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(key)
    return key


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    key = _load_or_create_key()
    f = Fernet(key)
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    key = _load_or_create_key()
    f = Fernet(key)
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except Exception:
        return ciphertext
