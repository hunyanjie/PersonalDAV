import uuid, hashlib, json, secrets
from datetime import datetime
from database.db_manager import Database
from utils.logger import logger

SCOPE_LABELS = {
    'contacts:read': '联系人(只读)', 'contacts:create': '联系人(创建)',
    'contacts:update': '联系人(编辑)', 'contacts:delete': '联系人(删除)',
    'events:read': '日程(只读)', 'events:create': '日程(创建)',
    'events:update': '日程(编辑)', 'events:delete': '日程(删除)',
    'files:read': '文件(只读)', 'files:upload': '文件(上传)',
    'files:rename': '文件(重命名)', 'files:delete': '文件(删除)',
    'dav:read': 'DAV(只读)', 'dav:write': 'DAV(读写)',
}

class ApiTokenService:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True

    def _hash_token(self, raw: str) -> str:
        return hashlib.sha256(raw.encode('utf-8')).hexdigest()

    def _generate_raw(self) -> str:
        return 'pdav_' + secrets.token_hex(24)

    def create_token(self, scopes: list[str], note: str = '', expires_at: str = '') -> dict:
        raw = self._generate_raw()
        token_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        db = Database()
        db.execute(
            'INSERT INTO api_tokens (id, token_hash, scopes, note, expires_at, created_at, last_used_at) VALUES (?,?,?,?,?,?,?)',
            (token_id, self._hash_token(raw), json.dumps(scopes), note, expires_at, now, '')
        )
        logger.info(f"创建 API 令牌: {token_id} scopes={scopes} note={note}")
        return {'id': token_id, 'token': raw, 'scopes': scopes, 'note': note, 'expires_at': expires_at, 'created_at': now}

    def list_tokens(self) -> list[dict]:
        db = Database()
        rows = db.query('SELECT id, scopes, note, expires_at, created_at, last_used_at FROM api_tokens ORDER BY created_at DESC')
        result = []
        for r in rows:
            try:
                scopes_list = json.loads(r[1]) if isinstance(r[1], str) else r[1]
            except Exception:
                scopes_list = []
            result.append({
                'id': r[0], 'scopes': scopes_list, 'note': r[2],
                'expires_at': r[3] or '', 'created_at': r[4], 'last_used_at': r[5] or ''
            })
        return result

    def verify_token(self, raw_token: str) -> dict | None:
        h = self._hash_token(raw_token)
        db = Database()
        row = db.query_one('SELECT id, scopes, note, expires_at, last_used_at FROM api_tokens WHERE token_hash=?', (h,))
        if not row:
            return None
        token_id, scopes_json, note, expires_at, last_used = row
        if expires_at:
            try:
                if datetime.fromisoformat(expires_at) < datetime.now():
                    logger.info(f"API 令牌已过期: {token_id}")
                    return None
            except ValueError:
                pass
        now = datetime.now().isoformat()
        db.execute('UPDATE api_tokens SET last_used_at=? WHERE id=?', (now, token_id))
        try:
            scopes = json.loads(scopes_json) if isinstance(scopes_json, str) else scopes_json
        except Exception:
            scopes = []
        return {'id': token_id, 'scopes': scopes, 'note': note, 'expires_at': expires_at, 'last_used_at': now}

    def delete_token(self, token_id: str) -> bool:
        db = Database()
        db.execute('DELETE FROM api_tokens WHERE id=?', (token_id,))
        logger.info(f"删除 API 令牌: {token_id}")
        return True

    def has_scope(self, token_scopes: list[str], required_scope: str) -> bool:
        return required_scope in token_scopes
