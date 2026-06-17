import os, json, shutil, uuid
from datetime import datetime, timedelta
from typing import Optional
from utils.logger import logger

TRASH_DIR = "data/trash"
MANIFEST_FILE = os.path.join(TRASH_DIR, "manifest.json")

class TrashService:
    _manifest: list[dict] | None = None

    @classmethod
    def _get_trash_dir(cls) -> str:
        os.makedirs(TRASH_DIR, exist_ok=True)
        return TRASH_DIR

    @classmethod
    def _load_manifest(cls) -> list[dict]:
        if cls._manifest is not None:
            return cls._manifest
        try:
            with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
                cls._manifest = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            cls._manifest = []
        return cls._manifest

    @classmethod
    def _save_manifest(cls):
        with open(MANIFEST_FILE, "w", encoding="utf-8") as f:
            json.dump(cls._manifest, f, ensure_ascii=False, indent=2)

    @classmethod
    def delete(cls, abs_path: str, virtual_path: str) -> dict | None:
        if not os.path.exists(abs_path):
            return None
        trash_dir = cls._get_trash_dir()
        item_uuid = str(uuid.uuid4())
        dest = os.path.join(trash_dir, item_uuid)
        entry = {
            "uuid": item_uuid,
            "original_path": virtual_path,
            "absolute_path": abs_path,
            "name": os.path.basename(abs_path.rstrip("/\\")),
            "is_dir": os.path.isdir(abs_path),
            "size": 0,
            "deleted_at": datetime.now().isoformat()
        }
        if os.path.isfile(abs_path):
            os.makedirs(dest, exist_ok=True)
            shutil.copy2(abs_path, os.path.join(dest, entry["name"]))
            entry["size"] = os.path.getsize(abs_path)
            os.remove(abs_path)
        else:
            os.makedirs(dest, exist_ok=True)
            total = 0
            for root, dirs, files in os.walk(abs_path):
                for f in files:
                    src = os.path.join(root, f)
                    rel = os.path.relpath(src, abs_path)
                    dst = os.path.join(dest, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
                    total += os.path.getsize(src)
            entry["size"] = total
            shutil.rmtree(abs_path)
        manifest = cls._load_manifest()
        manifest.append(entry)
        cls._save_manifest()
        cls._purge_expired()
        logger.info(f"已移至回收站: {virtual_path} ({item_uuid})")
        return entry

    @classmethod
    def list_items(cls) -> list[dict]:
        return list(reversed(cls._load_manifest()))

    @classmethod
    def restore(cls, uuid_: str, target_path: str = None, conflict_strategy: str = "error") -> bool:
        manifest = cls._load_manifest()
        entry = next((e for e in manifest if e["uuid"] == uuid_), None)
        if not entry:
            return False
        
        trash_item = os.path.join(TRASH_DIR, uuid_)
        if not os.path.exists(trash_item):
            manifest.remove(entry)
            cls._save_manifest()
            return False
            
        # Determine target path
        if not target_path:
            abs_path = entry.get("absolute_path")
            if not abs_path:
                svc = _get_mount_service()
                try:
                    _, abs_path = svc.resolve(entry["original_path"])
                except Exception:
                    abs_path = entry["original_path"].lstrip("/")
            target_path = abs_path
            
        # Check conflict
        if os.path.exists(target_path) and conflict_strategy == "error":
            raise FileExistsError(f"文件已存在: {target_path}")

        parent_dir = os.path.dirname(target_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            
        if entry["is_dir"]:
            os.makedirs(target_path, exist_ok=True)
            for root, dirs, files in os.walk(trash_item):
                for f in files:
                    src = os.path.join(root, f)
                    rel = os.path.relpath(src, trash_item)
                    dst = os.path.join(target_path, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)
        else:
            shutil.copy2(os.path.join(trash_item, entry["name"]), target_path)
        shutil.rmtree(trash_item)
        manifest.remove(entry)
        cls._save_manifest()
        logger.info(f"已从回收站还原: {entry['original_path']} -> {target_path} ({uuid_})")
        return True

    @classmethod
    def permanent_delete(cls, uuid_: str) -> bool:
        manifest = cls._load_manifest()
        entry = next((e for e in manifest if e["uuid"] == uuid_), None)
        if not entry:
            return False
        trash_item = os.path.join(TRASH_DIR, uuid_)
        if os.path.exists(trash_item):
            shutil.rmtree(trash_item)
        manifest.remove(entry)
        cls._save_manifest()
        logger.info(f"已永久删除回收站条目: {entry['original_path']} ({uuid_})")
        return True

    @classmethod
    def clear_all(cls) -> None:
        """清空所有回收站条目"""
        manifest = cls._load_manifest()
        for entry in manifest:
            trash_item = os.path.join(TRASH_DIR, entry["uuid"])
            if os.path.exists(trash_item):
                shutil.rmtree(trash_item)
        cls._manifest = []
        cls._save_manifest()
        logger.info("已清空回收站")

    @classmethod
    def startup_init(cls):
        """启动时同步 manifest 与实际磁盘文件"""
        if not os.path.exists(TRASH_DIR):
            return
        manifest = cls._load_manifest()
        new_manifest = []
        for entry in manifest:
            if os.path.exists(os.path.join(TRASH_DIR, entry["uuid"])):
                new_manifest.append(entry)
        if len(new_manifest) != len(manifest):
            cls._manifest = new_manifest
            cls._save_manifest()
            logger.info("回收站索引已同步")
        cls._purge_expired()

    @classmethod
    def purge(cls, retention_days: int = 30):
        manifest = cls._load_manifest()
        cutoff = datetime.now() - timedelta(days=retention_days)
        remaining = []
        for entry in manifest:
            try:
                dt = datetime.fromisoformat(entry["deleted_at"])
                if dt < cutoff:
                    trash_item = os.path.join(TRASH_DIR, entry["uuid"])
                    if os.path.exists(trash_item):
                        shutil.rmtree(trash_item)
                    continue
            except Exception:
                pass
            remaining.append(entry)
        purged = len(manifest) - len(remaining)
        if purged:
            cls._manifest = remaining
            cls._save_manifest()
            logger.info(f"回收站自动清理: 已清除 {purged} 个超期条目 (>{retention_days}天)")

    @classmethod
    def _purge_expired(cls):
        try:
            from services.settings_service import SettingsService
            days = int(SettingsService().get_setting("trash_retention_days", "30"))
        except Exception:
            days = 30
        cls.purge(days)

def _get_mount_service():
    from services.file_mount_service import FileMountService
    return FileMountService()
