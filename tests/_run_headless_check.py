"""无头模式与新建数据库检查：--db-path/--data-dir/--dav-root + FTS5。"""

import os
import sys
import tempfile

sys.path.insert(0, '.')
from tests._test_db import init_temp_db

errors = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}  {detail}")
    if not ok:
        errors.append(name)


def main():
    db_path = init_temp_db("pdav-headless-")
    base_dir = os.path.dirname(db_path)
    data_dir = os.path.join(base_dir, "mydata")
    dav_root = os.path.join(base_dir, "myroot")
    os.makedirs(dav_root)

    from fastapi.testclient import TestClient
    from personaldavd.config import DaemonConfig
    from personaldavd.daemon import create_app

    cfg = DaemonConfig(db_path=db_path, data_dir=data_dir, dav_root=dav_root)
    app = create_app(cfg)

    with TestClient(app, client=("127.0.0.1", 50000)) as client:
        r = client.get("/api/health")
        check("健康检查 200", r.status_code == 200, f"status={r.status_code}")
        data = r.json()
        check("临时数据库为空", data.get("contacts_count") == 0 and data.get("events_count") == 0, str(data))
        check("数据库文件已创建", os.path.isfile(db_path), db_path)

        from services.settings_service import SettingsService
        check("data_dir 已生效", SettingsService().get_setting("data_dir") == data_dir, data_dir)

        from services.file_mount_service import FileMountService
        mounts = FileMountService().get_mounts()
        check("dav-root 已注册为挂载", any(m.get("path") == dav_root for m in mounts), str(mounts))

        from services.trash_service import TrashService
        check("回收站跟随数据目录", TrashService._get_trash_dir().startswith(data_dir), TrashService._get_trash_dir())

        from utils.attachment_store import get_attachments_dir
        check("附件目录跟随数据目录", get_attachments_dir().startswith(data_dir), get_attachments_dir())

        # 新建数据库必须成功创建 FTS5，且联系人/日程都能搜到。
        from services.contact_service import ContactService
        from services.event_service import EventService
        ContactService().add_contact(
            "BEGIN:VCARD\nVERSION:3.0\nUID:fts-headless-c\nFN:FTS 无头测试\nEND:VCARD",
            publish=False,
        )
        EventService().add_event(
            "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Test//EN\nBEGIN:VEVENT\n"
            "UID:fts-headless-e\nSUMMARY:FTS 无头会议\nDTSTART:20260601T000000\n"
            "DTEND:20260601T010000\nEND:VEVENT\nEND:VCALENDAR",
            publish=False,
        )
        check("联系人 FTS 搜索", len(ContactService().search("无头测试")) > 0)
        check("日程 FTS 搜索", len(EventService().search("无头会议")) > 0)

    print("\n" + "=" * 40)
    if errors:
        print(f"!!! {len(errors)} 个检查失败: {', '.join(errors)}")
        return 1
    print("无头环境与 FTS5 检查通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
