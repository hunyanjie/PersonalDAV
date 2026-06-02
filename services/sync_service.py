import os
import tempfile
import threading
from datetime import datetime
from webdav3.client import Client
from services.contact_service import ContactService
from services.event_service import EventService
from services.settings_service import SettingsService
from utils.logger import logger


class SyncService:
    """Nextcloud DAV 双向同步服务"""

    def __init__(self):
        self._timer = None
        self._running = False

    def get_options(self):
        s = SettingsService()
        return {
            'webdav_hostname': s.get_setting("sync_url", ""),
            'webdav_login': s.get_setting("sync_user", ""),
            'webdav_password': s.get_setting("sync_password", ""),
            'webdav_root': s.get_setting("sync_path", "/"),
            'webdav_timeout': 30,
        }

    def is_configured(self):
        opts = self.get_options()
        return bool(opts['webdav_hostname'] and opts['webdav_login'])

    def sync_contacts(self, progress_callback=None):
        opts = self.get_options()
        client = Client(opts)
        contact_svc = ContactService()
        remote_vcards = {}
        for f in client.list("", get_info=True):
            name = f.get('name', '')
            if name.lower().endswith('.vcf'):
                try:
                    data = client.download_sync(name)
                    if isinstance(data, bytes):
                        data = data.decode('utf-8')
                    uid = self._extract_uid_from_vcard(data)
                    if uid:
                        remote_vcards[uid] = data
                except Exception as e:
                    logger.warning(f"无法下载远程联系人 {name}: {e}")

        local_all = contact_svc.get_all_items()
        local_vcards = {uid: raw for uid, raw in local_all}

        push_uids = []
        pull_uids = []
        for uid, raw in remote_vcards.items():
            if uid not in local_vcards:
                pull_uids.append(uid)
            elif local_vcards[uid] != raw:
                remote_time = self._get_mtime(client, uid, opts)
                local_time = self._get_local_mtime(uid, contact_svc)
                if remote_time and local_time and remote_time > local_time:
                    pull_uids.append(uid)
                else:
                    push_uids.append(uid)
        for uid in local_vcards:
            if uid not in remote_vcards:
                push_uids.append(uid)

        pulled = pushed = 0
        for uid in pull_uids:
            try:
                contact_svc.add_contact(remote_vcards[uid], force=True)
                pulled += 1
                if progress_callback:
                    progress_callback(f"已拉取联系人: {uid}")
            except Exception as e:
                logger.error(f"拉取联系人 {uid} 失败: {e}")

        for uid in push_uids:
            try:
                raw = local_vcards.get(uid)
                if raw:
                    name = f"{uid}.vcf"
                    client.upload_sync(remote_vcards.get(uid, raw).encode('utf-8') if isinstance(remote_vcards.get(uid, raw), str) else remote_vcards.get(uid, raw), name)
                    pushed += 1
                    if progress_callback:
                        progress_callback(f"已推送联系人: {uid}")
            except Exception as e:
                logger.error(f"推送联系人 {uid} 失败: {e}")

        return pulled, pushed

    def sync_events(self, progress_callback=None):
        opts = self.get_options()
        client = Client(opts)
        event_svc = EventService()
        remote_icals = {}
        for f in client.list("", get_info=True):
            name = f.get('name', '')
            if name.lower().endswith('.ics'):
                try:
                    data = client.download_sync(name)
                    if isinstance(data, bytes):
                        data = data.decode('utf-8')
                    uid = self._extract_uid_from_ical(data)
                    if uid:
                        remote_icals[uid] = data
                except Exception as e:
                    logger.warning(f"无法下载远程事件 {name}: {e}")

        local_all = event_svc.get_all_items()
        local_icals = {uid: raw for uid, raw in local_all}

        push_uids = []
        pull_uids = []
        for uid, raw in remote_icals.items():
            if uid not in local_icals:
                pull_uids.append(uid)
            elif local_icals[uid] != raw:
                remote_time = self._get_mtime(client, uid, opts)
                local_time = self._get_local_mtime(uid, event_svc)
                if remote_time and local_time and remote_time > local_time:
                    pull_uids.append(uid)
                else:
                    push_uids.append(uid)
        for uid in local_icals:
            if uid not in remote_icals:
                push_uids.append(uid)

        pulled = pushed = 0
        for uid in pull_uids:
            try:
                event_svc.add_event(remote_icals[uid], force=True)
                pulled += 1
                if progress_callback:
                    progress_callback(f"已拉取事件: {uid}")
            except Exception as e:
                logger.error(f"拉取事件 {uid} 失败: {e}")

        for uid in push_uids:
            try:
                raw = local_icals.get(uid)
                if raw:
                    client.upload_sync(raw.encode('utf-8') if isinstance(raw, str) else raw, f"{uid}.ics")
                    pushed += 1
                    if progress_callback:
                        progress_callback(f"已推送事件: {uid}")
            except Exception as e:
                logger.error(f"推送事件 {uid} 失败: {e}")

        return pulled, pushed

    def _extract_uid_from_vcard(self, text):
        for line in text.splitlines():
            if line.upper().startswith('UID'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    return parts[1].strip()
        return None

    def _extract_uid_from_ical(self, text):
        for line in text.splitlines():
            if line.upper().startswith('UID'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    return parts[1].strip()
        return None

    def _get_mtime(self, client, uid, opts):
        try:
            name = f"{uid}.vcf"
            info = client.info(name)
            return info.get('modified')
        except Exception:
            return None

    def _get_local_mtime(self, uid, svc):
        try:
            entity = svc.repo.get_by_uid(uid)
            return entity.updated_at if entity else None
        except Exception:
            return None

    def start_periodic_sync(self, interval_minutes=30):
        self._running = True
        self._schedule_sync(interval_minutes)

    def stop_periodic_sync(self):
        self._running = False
        if self._timer:
            self._timer.cancel()
            self._timer = None

    def _schedule_sync(self, interval_minutes):
        if not self._running:
            return
        self._timer = threading.Timer(interval_minutes * 60, self._run_periodic_sync, args=[interval_minutes])
        self._timer.daemon = True
        self._timer.start()

    def _run_periodic_sync(self, interval_minutes):
        if not self._running:
            return
        try:
            if self.is_configured():
                self.sync_contacts()
                self.sync_events()
        except Exception as e:
            logger.error(f"定时同步失败: {e}")
        self._schedule_sync(interval_minutes)
