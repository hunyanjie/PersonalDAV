"""Multi-mount file service — manages virtual mount points above dav_root."""

import json
import os
import threading
from datetime import datetime
from typing import Any
from utils.logger import logger


class FileMountService:
    _instance: "FileMountService | None" = None
    _lock = threading.Lock()
    _mounts: list[dict[str, Any]]
    _migrated: bool

    def __new__(cls) -> "FileMountService":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._mounts = []
                    cls._instance._migrated = False
        return cls._instance

    # ── persistence ──

    def _load(self) -> list[dict[str, Any]]:
        from services.settings_service import SettingsService
        s = SettingsService()
        raw = s.get_setting("file_mounts", "[]")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []

    def _save(self) -> None:
        from services.settings_service import SettingsService
        SettingsService().set_setting("file_mounts", json.dumps(self._mounts, ensure_ascii=False))

    def _ensure_migrated(self) -> None:
        if self._migrated:
            return
        self._migrated = True
        if self._mounts:
            return
        loaded = self._load()
        if loaded:
            self._mounts = loaded
            return
        from services.settings_service import SettingsService
        dav_root = SettingsService().get_setting("dav_root", "")
        if not dav_root:
            return
        root = os.path.abspath(dav_root)
        if not os.path.isdir(root):
            os.makedirs(root, exist_ok=True)
        name = os.path.basename(root) or "DAVStorage"
        self._mounts.append({"name": name, "path": root})
        self._save()
        logger.info(f"Migrated dav_root -> mount '{name}' ({root})")

    def get_mounts(self) -> list[dict[str, Any]]:
        self._ensure_migrated()
        return [dict(m) for m in self._mounts]

    def get_mount(self, name: str) -> dict[str, Any] | None:
        self._ensure_migrated()
        for m in self._mounts:
            if m["name"] == name:
                return dict(m)
        return None

    def add_mount(self, name: str, path: str) -> dict[str, Any]:
        self._ensure_migrated()
        for m in self._mounts:
            if m["name"] == name:
                raise ValueError(f"Mount name '{name}' already exists")
        abspath = os.path.abspath(path)
        if not os.path.isdir(abspath):
            os.makedirs(abspath, exist_ok=True)
        entry = {"name": name, "path": abspath}
        self._mounts.append(entry)
        self._save()
        logger.info(f"Mount added: {name} -> {abspath}")
        return dict(entry)

    def remove_mount(self, name: str) -> bool:
        self._ensure_migrated()
        for i, m in enumerate(self._mounts):
            if m["name"] == name:
                self._mounts.pop(i)
                self._save()
                logger.info(f"Mount removed: {name}")
                return True
        return False

    def update_mount(self, old_name: str, new_name: str, new_path: str) -> dict[str, Any]:
        self._ensure_migrated()
        abspath = os.path.abspath(new_path)
        idx = -1
        for i, m in enumerate(self._mounts):
            if m["name"] == old_name:
                idx = i
            elif m["name"] == new_name and new_name != old_name:
                raise ValueError(f"Mount name '{new_name}' already exists")
        if idx < 0:
            raise ValueError(f"Mount '{old_name}' not found")
        if not os.path.isdir(abspath):
            os.makedirs(abspath, exist_ok=True)
        self._mounts[idx] = {"name": new_name, "path": abspath}
        self._save()
        logger.info(f"Mount updated: {old_name} -> {new_name} ({abspath})")
        return dict(self._mounts[idx])

    # ── properties ──

    @property
    def is_single_mount(self) -> bool:
        self._ensure_migrated()
        return len(self._mounts) == 1

    # ── path resolution ──

    def resolve(self, api_path: str) -> tuple[str, str]:
        """Resolve an API path to (mount_name, absolute_filesystem_path).

        Single-mount mode:
          "/file.txt" → ("mount_name", "mount_path/file.txt")

        Multi-mount mode:
          "/MountName/file.txt" → ("MountName", "mount_path/file.txt")
          "/" → raises ValueError (caller should use get_root_entries)

        Raises ValueError on mount-not-found or path traversal.
        """
        self._ensure_migrated()
        if not self._mounts:
            raise ValueError("No mounts configured")

        if self.is_single_mount:
            m = self._mounts[0]
            rel = api_path.lstrip("/")
            abs_path = os.path.normpath(os.path.join(m["path"], rel))
            if not abs_path.startswith(os.path.normpath(m["path"])):
                raise ValueError("Path traversal")
            return (m["name"], abs_path)
        else:
            parts = api_path.strip("/").split("/", 1)
            if not parts or not parts[0]:
                raise ValueError("Root path")
            mount_name = parts[0]
            m = self._get_mount_entry(mount_name)
            if not m:
                raise ValueError(f"Mount '{mount_name}' not found")
            rel = parts[1] if len(parts) > 1 else ""
            abs_path = os.path.normpath(os.path.join(m["path"], rel))
            if not abs_path.startswith(os.path.normpath(m["path"])):
                raise ValueError("Path traversal")
            return (m["name"], abs_path)

    def get_root_entries(self) -> list[dict[str, Any]]:
        """Return appropriate entries for the root path '/'.

        Single mount  → list actual files from mount root
        Multiple mounts → list mount point entries
        """
        self._ensure_migrated()
        if not self._mounts:
            return []
        if self.is_single_mount:
            return self._list_fs(self._mounts[0]["path"], self._mounts[0]["name"])
        return self._list_mounts()

    def list_directory(self, mount_name: str, rel_path: str) -> list[dict[str, Any]]:
        """List files in a specific mount's subdirectory."""
        self._ensure_migrated()
        m = self._get_mount_entry(mount_name)
        if not m:
            raise ValueError(f"Mount '{mount_name}' not found")
        dir_path = os.path.normpath(os.path.join(m["path"], rel_path))
        if not dir_path.startswith(os.path.normpath(m["path"])):
            raise ValueError("Path traversal")
        return self._list_fs(dir_path, mount_name)

    # ── helpers ──

    def _get_mount_entry(self, name: str) -> dict[str, Any] | None:
        for m in self._mounts:
            if m["name"] == name:
                return m
        return None

    def _list_mounts(self) -> list[dict[str, Any]]:
        return [{
            "name": m["name"],
            "path": "/" + m["name"],
            "is_dir": True,
            "is_mount": True,
            "size": 0,
            "modified_at": "",
        } for m in self._mounts]

    def _list_fs(self, dir_path: str, mount_name: str) -> list[dict[str, Any]]:
        items = []
        try:
            for name in sorted(os.listdir(dir_path)):
                full = os.path.join(dir_path, name)
                try:
                    st = os.stat(full)
                    rel = mount_name + "/" + name
                    items.append({
                        "name": name,
                        "path": "/" + rel,
                        "is_dir": os.path.isdir(full),
                        "is_mount": False,
                        "size": st.st_size if os.path.isfile(full) else 0,
                        "modified_at": datetime.fromtimestamp(st.st_mtime).isoformat(),
                    })
                except OSError:
                    items.append({
                        "name": name,
                        "path": "/" + mount_name + "/" + name,
                        "is_dir": False,
                        "is_mount": False,
                        "size": 0,
                        "modified_at": "",
                    })
        except OSError:
            pass
        return items
