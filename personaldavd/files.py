"""REST API — file management (multi-mount aware)."""

import asyncio
import base64
import io
import os
import shutil
import mimetypes
import tarfile
import tempfile
import zipfile
import subprocess
from urllib.parse import quote
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form
from fastapi.responses import FileResponse, RedirectResponse
from .auth import get_current_token
from .config import DaemonConfig

_MAX_TEXT_BYTES = 5 * 1024 * 1024
_ARCHIVE_EXTS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz", ".7z", ".rar"}

_OFFICE_EXTS = {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'}

files_router = APIRouter(tags=["文件管理"])


def _mount_svc():
    from services.file_mount_service import FileMountService
    return FileMountService()


def _resolve_abs(path: str, want_file: bool = False) -> str:
    svc = _mount_svc()
    try:
        _, abs_path = svc.resolve(path)
    except ValueError as e:
        raise HTTPException(403, str(e))
    if want_file and not os.path.isfile(abs_path):
        raise HTTPException(404, "文件不存在")
    if not os.path.exists(abs_path):
        raise HTTPException(404, "路径不存在")
    return abs_path


def _decode_text_bytes(raw: bytes) -> tuple[str, str]:
    """尽量用常见编码解码文本，二进制返回 415。"""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16"), "utf-16"
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig"), "utf-8-sig"
    if b"\x00" in raw[:4096]:
        raise HTTPException(415, "该文件是二进制文件，不支持文本预览")
    for encoding in ("utf-8", "gb18030", "big5", "latin-1"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise HTTPException(415, "无法识别文本编码")


def _read_text_file(abs_path: str, max_bytes: int = _MAX_TEXT_BYTES) -> dict:
    size = os.path.getsize(abs_path)
    if size > max_bytes:
        raise HTTPException(413, f"文本文件超过 {max_bytes // (1024 * 1024)} MB，暂不支持在线编辑")
    with open(abs_path, "rb") as f:
        raw = f.read(max_bytes + 1)
    content, encoding = _decode_text_bytes(raw)
    stat = os.stat(abs_path)
    return {
        "content": content,
        "encoding": encoding,
        "size": size,
        "mtime": stat.st_mtime,
    }


def _write_text_file(abs_path: str, content: str, encoding: str = "utf-8") -> None:
    data = content.encode(encoding)
    if len(data) > _MAX_TEXT_BYTES:
        raise HTTPException(413, f"文本内容超过 {_MAX_TEXT_BYTES // (1024 * 1024)} MB，未保存")
    fd, tmp_path = tempfile.mkstemp(prefix=".pdav-edit-", dir=os.path.dirname(abs_path))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, abs_path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def _zip_class():
    """优先使用 pyzipper，兼容 WinRAR/7-Zip 生成的 AES 加密 ZIP。"""
    try:
        import pyzipper
        return pyzipper.AESZipFile
    except ImportError:
        return zipfile.ZipFile


def _archive_format(abs_path: str) -> str:
    ext = os.path.splitext(abs_path)[1].lower()
    if ext == ".zip":
        return "zip"
    if ext in {".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz"}:
        return "tar"
    if ext == ".7z":
        return "7z"
    if ext == ".rar":
        return "rar"
    raise HTTPException(415, "暂不支持该压缩格式")


def _list_archive(abs_path: str, password: str = "") -> dict:
    fmt = _archive_format(abs_path)
    entries = []
    encrypted = False
    names_encrypted = False
    try:
        if fmt == "zip":
            with _zip_class()(abs_path) as zf:
                for info in zf.infolist():
                    is_dir = info.is_dir() or info.filename.endswith("/")
                    item_encrypted = bool(info.flag_bits & 0x1)
                    encrypted = encrypted or item_encrypted
                    entries.append({
                        "name": info.filename.replace("\\", "/"),
                        "size": 0 if is_dir else info.file_size,
                        "is_dir": is_dir,
                        "encrypted": item_encrypted,
                    })
        elif fmt == "tar":
            with tarfile.open(abs_path, "r:*") as tf:
                for info in tf.getmembers():
                    entries.append({
                        "name": info.name.replace("\\", "/"),
                        "size": 0 if info.isdir() else info.size,
                        "is_dir": info.isdir(),
                        "encrypted": False,
                    })
        elif fmt == "7z":
            try:
                import py7zr
            except ImportError:
                raise HTTPException(415, "预览 7z 需要安装 py7zr")
            try:
                with py7zr.SevenZipFile(abs_path, mode="r", password=password or None) as zf:
                    names_encrypted = False
                    infos = zf.list()
                    items = infos.items() if hasattr(infos, "items") else [(i.filename, i) for i in infos]
                    for name, info in items:
                        entries.append({
                            "name": name.replace("\\", "/"),
                            "size": 0 if info.is_directory else (info.uncompressed or 0),
                            "is_dir": bool(info.is_directory),
                            "encrypted": bool(getattr(info, "is_encrypted", False)),
                        })
                    encrypted = any(e["encrypted"] for e in entries)
            except Exception as e:
                message = str(e).lower()
                if "password" in message or "encrypted" in message:
                    if password:
                        raise HTTPException(423, "压缩文件需要密码，或密码错误")
                    return {
                        "entries": [],
                        "encrypted": True,
                        "names_encrypted": True,
                        "password_required": True,
                        "format": fmt,
                    }
                if password and isinstance(e, TypeError):
                    raise HTTPException(423, "压缩文件需要密码，或密码错误")
                raise
        elif fmt == "rar":
            try:
                import rarfile
            except ImportError:
                raise HTTPException(415, "预览 rar 需要安装 rarfile，并配置 unrar")
            try:
                rf = rarfile.RarFile(abs_path)
            except rarfile.PasswordRequired:
                return {
                    "entries": [],
                    "encrypted": True,
                    "names_encrypted": True,
                    "password_required": True,
                    "format": fmt,
                }
            with rf:
                encrypted = bool(rf.needs_password())
                for info in rf.infolist():
                    entries.append({
                        "name": info.filename.replace("\\", "/"),
                        "size": 0 if info.isdir() else info.file_size,
                        "is_dir": info.isdir(),
                        "encrypted": encrypted,
                    })
    except HTTPException:
        raise
    except (zipfile.BadZipFile, tarfile.TarError, NotImplementedError) as e:
        raise HTTPException(415, f"无法读取压缩文件: {e}")
    return {
        "entries": entries,
        "encrypted": encrypted,
        "names_encrypted": names_encrypted,
        "password_required": encrypted,
        "format": fmt,
    }


def _read_archive_entry(abs_path: str, entry: str, password: str = "") -> tuple[bytes, str]:
    fmt = _archive_format(abs_path)
    if fmt == "zip":
        pwd = password.encode() if password else None
        try:
            with _zip_class()(abs_path) as zf:
                info = None
                for candidate in zf.infolist():
                    if candidate.filename == entry or candidate.filename.replace("\\", "/") == entry:
                        info = candidate
                        break
                if info is None:
                    raise HTTPException(404, "压缩包内不存在该文件")
                if info.is_dir():
                    return b"", "inode/directory"
                return zf.read(info, pwd=pwd), mimetypes.guess_type(entry)[0] or "application/octet-stream"
        except HTTPException:
            raise
        except NotImplementedError:
            raise HTTPException(415, "该压缩包使用了暂不支持的压缩或加密方式")
        except RuntimeError:
            raise HTTPException(423, "压缩文件需要密码，或密码错误")
    if fmt == "tar":
        with tarfile.open(abs_path, "r:*") as tf:
            member = tf.getmember(entry)
            if member.isdir():
                return b"", "inode/directory"
            f = tf.extractfile(member)
            return (f.read() if f else b""), mimetypes.guess_type(entry)[0] or "application/octet-stream"
    if fmt in ("7z", "rar"):
        tmp_dir = tempfile.mkdtemp(prefix="pdav-archive-")
        try:
            if fmt == "7z":
                import py7zr
                try:
                    with py7zr.SevenZipFile(abs_path, mode="r", password=password or None) as zf:
                        zf.extract(path=tmp_dir, targets=[entry])
                except Exception as e:
                    message = str(e).lower()
                    if "password" in message or "encrypted" in message:
                        raise HTTPException(423, "压缩文件需要密码，或密码错误")
                    if password and isinstance(e, TypeError):
                        raise HTTPException(423, "压缩文件需要密码，或密码错误")
                    if isinstance(e, NotImplementedError):
                        raise HTTPException(415, "该压缩包使用了暂不支持的压缩方式")
                    raise
            else:
                import rarfile
                with rarfile.RarFile(abs_path) as rf:
                    try:
                        rf.extract(entry, tmp_dir, pwd=password or None)
                    except (RuntimeError, rarfile.PasswordRequired, rarfile.RarWrongPassword):
                        raise HTTPException(423, "压缩文件需要密码，或密码错误")
            target = os.path.join(tmp_dir, entry)
            if not os.path.isfile(target):
                raise HTTPException(404, "压缩包内不存在该文件")
            with open(target, "rb") as f:
                return f.read(), mimetypes.guess_type(entry)[0] or "application/octet-stream"
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    raise HTTPException(415, "暂不支持该压缩格式")


# ── Mount management API ──

@files_router.get("/files/mounts", summary="列出所有挂载点")
async def list_mounts(token: str = Depends(get_current_token)):
    from services.file_mount_service import FileMountService
    return await asyncio.to_thread(FileMountService().get_mounts)


@files_router.post("/files/mounts", summary="添加挂载点")
async def add_mount(
    body: dict,
    token: str = Depends(get_current_token),
):
    from services.file_mount_service import FileMountService
    svc = FileMountService()
    try:
        entry = await asyncio.to_thread(
            svc.add_mount, body["name"], body["path"], body.get("quota_mb")
        )
        return entry
    except ValueError as e:
        raise HTTPException(400, str(e))


@files_router.put("/files/mounts/{name}", summary="更新挂载点")
async def update_mount(
    name: str,
    body: dict,
    token: str = Depends(get_current_token),
):
    from services.file_mount_service import FileMountService
    svc = FileMountService()
    try:
        if "quota_mb" in body:
            entry = await asyncio.to_thread(
                svc.update_mount,
                name,
                body.get("name", name),
                body.get("path", ""),
                body.get("quota_mb"),
            )
        else:
            entry = await asyncio.to_thread(
                svc.update_mount, name, body.get("name", name), body.get("path", "")
            )
        return entry
    except ValueError as e:
        raise HTTPException(400, str(e))


@files_router.delete("/files/mounts/{name}", summary="删除挂载点")
async def delete_mount(
    name: str,
    token: str = Depends(get_current_token),
):
    from services.file_mount_service import FileMountService
    ok = await asyncio.to_thread(FileMountService().remove_mount, name)
    if ok:
        return {"deleted": True}
    raise HTTPException(404, f"Mount '{name}' not found")


@files_router.get("/files", summary="列出目录内容")
async def list_files(
    path: str = Query("/", description="目录路径"),
    token: str = Depends(get_current_token),
):
    from .daemon import logger

    if path == "/" or path == "":
        items = await asyncio.to_thread(_mount_svc().get_root_entries)
        if logger:
            logger.debug(f"Root entries: {len(items)} items")
        return items

    def _list():
        svc = _mount_svc()
        try:
            mount_name, abs_path = svc.resolve(path)
        except ValueError as e:
            raise HTTPException(403, str(e))
        if not os.path.isdir(abs_path):
            os.makedirs(abs_path, exist_ok=True)
        items = []
        try:
            for name in sorted(os.listdir(abs_path)):
                full = os.path.join(abs_path, name)
                try:
                    st = os.stat(full)
                    item_path = (path.rstrip("/") + "/" + name).replace("//", "/")
                    items.append({
                        "name": name,
                        "path": item_path,
                        "is_dir": os.path.isdir(full),
                        "size": st.st_size if os.path.isfile(full) else 0,
                        "modified_at": datetime.fromtimestamp(st.st_mtime).isoformat(),
                    })
                except Exception:
                    pass
        except Exception as e:
            raise HTTPException(500, f"读取目录失败: {e}")
        return items

    return await asyncio.to_thread(_list)


@files_router.get("/files/download", summary="下载文件")
async def download_file(
    path: str = Query(..., description="文件路径"),
    token: str = Depends(get_current_token),
):
    def _resolve():
        svc = _mount_svc()
        try:
            _, abs_path = svc.resolve(path)
        except ValueError as e:
            raise HTTPException(403, str(e))
        if not os.path.isfile(abs_path):
            raise HTTPException(404, "文件不存在")
        return abs_path
    abs_path = await asyncio.to_thread(_resolve)
    from fastapi.responses import FileResponse
    filename = os.path.basename(abs_path)
    return FileResponse(abs_path, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


# MIME fallback for extensions mimetypes may miss on Windows
_MIME_OVERRIDES = {
    '.md': 'text/markdown',
    '.yaml': 'text/yaml',
    '.yml': 'text/yaml',
    '.csv': 'text/csv',
    '.log': 'text/plain',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.svg': 'image/svg+xml',
    '.txt': 'text/plain',
    '.bmp': 'image/bmp',
    '.webp': 'image/webp',
}


@files_router.get("/files/preview", summary="预览文件内容")
async def preview_file(
    path: str = Query(..., description="文件路径"),
    request: Request = None,
):
    def _preview():
        from services.settings_service import SettingsService as _SS
        svc = _mount_svc()
        try:
            _, abs_path = svc.resolve(path)
        except ValueError as e:
            raise HTTPException(403, str(e))
        if not os.path.isfile(abs_path):
            raise HTTPException(404, "文件不存在")
        return (abs_path, _SS().get_setting("office_preview_mode", "off"))

    abs_path, office_mode = await asyncio.to_thread(_preview)
    _, ext = os.path.splitext(abs_path)
    ctype = mimetypes.guess_type(abs_path)[0] or _MIME_OVERRIDES.get(ext.lower())
    if ctype and ctype.startswith(("text/", "image/", "application/pdf")):
        return FileResponse(abs_path, media_type=ctype)

    # Office document preview
    if ext.lower() in _OFFICE_EXTS:
        if office_mode == "libreoffice":
            if not shutil.which("soffice"):
                raise HTTPException(415, "需要 LibreOffice: soffice 未安装")
            pdf_path = await asyncio.to_thread(_convert_office_to_pdf, abs_path)
            if not pdf_path:
                raise HTTPException(500, "文档转换失败")
            return FileResponse(pdf_path, media_type="application/pdf",
                                filename=os.path.basename(abs_path).rsplit('.', 1)[0] + '.pdf')

        elif office_mode == "onlyoffice":
            from services.settings_service import SettingsService
            onlyoffice_host = await asyncio.to_thread(SettingsService().get_setting, "onlyoffice_host", "")
            if not onlyoffice_host:
                raise HTTPException(415, "未配置 ONLYOFFICE 服务器地址")
            file_url = _build_public_url(request, path)
            return RedirectResponse(
                f"{onlyoffice_host.rstrip('/')}/documentserver/doceditor?"
                f"filePath={quote(file_url)}&editorType=view"
            )

        elif office_mode == "ms_online":
            file_url = _build_public_url(request, path)
            return RedirectResponse(
                f"https://view.officeapps.live.com/op/view.aspx?src={quote(file_url)}"
            )

    raise HTTPException(415, "不支持预览该文件类型")


@files_router.get("/files/text", summary="读取文本文件")
async def read_text_file(
    path: str = Query(..., description="文件路径"),
    token: str = Depends(get_current_token),
):
    def _read():
        abs_path = _resolve_abs(path, want_file=True)
        payload = _read_text_file(abs_path)
        payload["path"] = path
        return payload
    return await asyncio.to_thread(_read)


@files_router.put("/files/text", summary="保存文本文件")
async def save_text_file(
    body: dict,
    token: str = Depends(get_current_token),
):
    path = str(body.get("path") or "")
    content = body.get("content")
    if not path or content is None:
        raise HTTPException(400, "缺少 path 或 content")
    encoding = str(body.get("encoding") or "utf-8")
    expected_mtime = body.get("expected_mtime")

    def _save():
        abs_path = _resolve_abs(path, want_file=True)
        if expected_mtime is not None:
            actual = os.stat(abs_path).st_mtime
            try:
                if abs(float(expected_mtime) - actual) > 0.001:
                    raise HTTPException(409, "文件已被其他程序修改，请重新打开后再保存")
            except (TypeError, ValueError):
                pass
        try:
            "".encode(encoding)
        except LookupError:
            raise HTTPException(400, f"不支持的编码: {encoding}")
        _write_text_file(abs_path, str(content), encoding)
        stat = os.stat(abs_path)
        return {"path": path, "saved": True, "size": stat.st_size, "mtime": stat.st_mtime}
    return await asyncio.to_thread(_save)


@files_router.post("/files/archive/list", summary="列出压缩包内容")
async def archive_list(
    body: dict,
    token: str = Depends(get_current_token),
):
    path = str(body.get("path") or "")
    password = str(body.get("password") or "")
    if not path:
        raise HTTPException(400, "缺少 path")
    def _list():
        return _list_archive(_resolve_abs(path, want_file=True), password)
    return await asyncio.to_thread(_list)


@files_router.post("/files/archive/preview", summary="预览压缩包内文件")
async def archive_preview(
    body: dict,
    token: str = Depends(get_current_token),
):
    path = str(body.get("path") or "")
    entry = str(body.get("entry") or "")
    password = str(body.get("password") or "")
    if not path or not entry:
        raise HTTPException(400, "缺少 path 或 entry")
    def _preview():
        raw, ctype = _read_archive_entry(_resolve_abs(path, want_file=True), entry, password)
        if len(raw) > 10 * 1024 * 1024:
            raise HTTPException(413, "压缩包内文件超过 10 MB，请先解压")
        if ctype.startswith("text/") or entry.lower().endswith(
            (".txt", ".md", ".py", ".java", ".js", ".ts", ".json", ".xml", ".csv", ".log", ".yaml", ".yml", ".sql", ".html", ".css", ".ini", ".conf")
        ):
            content, encoding = _decode_text_bytes(raw)
            return {"is_text": True, "content": content, "encoding": encoding, "content_type": ctype, "size": len(raw)}
        # 没有扩展名的 LICENSE / README 等文件，在确认不是二进制后按文本预览。
        if ctype == "application/octet-stream" and "." not in os.path.basename(entry):
            try:
                content, encoding = _decode_text_bytes(raw)
                return {"is_text": True, "content": content, "encoding": encoding, "content_type": ctype, "size": len(raw)}
            except HTTPException:
                pass
        if ctype.startswith("image/"):
            return {
                "is_text": False,
                "content_type": ctype,
                "size": len(raw),
                "data_url": f"data:{ctype};base64," + base64.b64encode(raw).decode("ascii"),
            }
        return {"is_text": False, "content_type": ctype, "size": len(raw)}
    return await asyncio.to_thread(_preview)


@files_router.post("/files/archive/extract", summary="从压缩包提取单个文件")
async def archive_extract(
    body: dict,
    token: str = Depends(get_current_token),
):
    path = str(body.get("path") or "")
    entry = str(body.get("entry") or "")
    password = str(body.get("password") or "")
    target_dir = str(body.get("target_dir") or "")
    overwrite = bool(body.get("overwrite", False))
    if not path or not entry:
        raise HTTPException(400, "缺少 path 或 entry")
    def _extract():
        archive_abs = _resolve_abs(path, want_file=True)
        if target_dir:
            target_abs = _resolve_abs(target_dir)
        else:
            target_abs = os.path.dirname(archive_abs)
        if not os.path.isdir(target_abs):
            raise HTTPException(400, "目标目录不存在")
        raw, _ = _read_archive_entry(archive_abs, entry, password)
        name = os.path.basename(entry.replace("\\", "/").rstrip("/")) or "file"
        dest = os.path.join(target_abs, name)
        if os.path.exists(dest) and not overwrite:
            base, ext = os.path.splitext(name)
            counter = 1
            while os.path.exists(os.path.join(target_abs, f"{base}({counter}){ext}")):
                counter += 1
            dest = os.path.join(target_abs, f"{base}({counter}){ext}")
        with open(dest, "wb") as f:
            f.write(raw)
        return {"path": dest, "name": os.path.basename(dest), "size": len(raw)}
    return await asyncio.to_thread(_extract)


_CARD_EXTS = {".vcf", ".vcs", ".ics", ".ical"}


@files_router.get("/files/card", summary="把联系人/日历文件解析为卡片")
async def read_card(
    path: str = Query(..., description="文件路径"),
    token: str = Depends(get_current_token),
):
    def _read():
        abs_path = _resolve_abs(path, want_file=True)
        ext = os.path.splitext(abs_path)[1].lower()
        if ext not in _CARD_EXTS:
            raise HTTPException(415, "不是联系人/日历文件")
        raw = _read_text_file(abs_path)["content"]
        if ext in {".vcf", ".vcs"}:
            from .api import _vcard_to_contact_out
            item = _vcard_to_contact_out(raw)
            if not item:
                raise HTTPException(422, "无法解析联系人文件，可能缺少 UID")
            return {"kind": "contact", "data": item.model_dump(), "raw": raw}
        from .api import _ical_to_event_out
        item = _ical_to_event_out(raw)
        if not item:
            raise HTTPException(422, "无法解析日历文件，可能缺少 UID")
        return {"kind": "event", "data": item.model_dump(), "raw": raw}
    return await asyncio.to_thread(_read)


@files_router.put("/files/card", summary="保存联系人/日历卡片")
async def save_card(
    body: dict,
    token: str = Depends(get_current_token),
):
    path = str(body.get("path") or "")
    kind = str(body.get("kind") or "")
    data = body.get("data") or {}
    if not path or kind not in {"contact", "event"}:
        raise HTTPException(400, "缺少 path 或 kind")
    def _save():
        abs_path = _resolve_abs(path, want_file=True)
        from .api import _vcard_to_contact_out, _ical_to_event_out, _contact_fields_to_vcard, _event_fields_to_ical
        from .models import ContactCreate, EventCreate
        raw_old = _read_text_file(abs_path)["content"]
        if kind == "contact":
            old = _vcard_to_contact_out(raw_old)
            uid = str(body.get("uid") or (old.uid if old else "") or "")
            fields = ContactCreate(**{k: v for k, v in data.items() if k in ContactCreate.model_fields})
            raw = _contact_fields_to_vcard(fields, uid=uid)
        else:
            old = _ical_to_event_out(raw_old)
            uid = str(body.get("uid") or (old.uid if old else "") or "")
            fields = EventCreate(**{k: v for k, v in data.items() if k in EventCreate.model_fields})
            raw = _event_fields_to_ical(fields, uid=uid)
        _write_text_file(abs_path, raw, "utf-8")
        return {"kind": kind, "raw": raw, "saved": True}
    return await asyncio.to_thread(_save)


def _convert_office_to_pdf(src_path: str) -> str | None:
    """Convert Office document to PDF using LibreOffice headless."""
    out_dir = tempfile.mkdtemp(prefix="personaldav_office_")
    try:
        result = subprocess.run(
            ["soffice", "--headless", "--convert-to", "pdf",
             "--outdir", out_dir, src_path],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            shutil.rmtree(out_dir, ignore_errors=True)
            return None
        # Find generated PDF
        base = os.path.splitext(os.path.basename(src_path))[0]
        pdf_path = os.path.join(out_dir, base + ".pdf")
        if os.path.isfile(pdf_path):
            return pdf_path
        shutil.rmtree(out_dir, ignore_errors=True)
        return None
    except subprocess.TimeoutExpired:
        shutil.rmtree(out_dir, ignore_errors=True)
        return None


def _build_public_url(request: Request, path: str) -> str:
    """Build a public URL for the file, used by Office Online / ONLYOFFICE."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", "localhost:8000"))
    return f"{scheme}://{host}/api/files/download?path={quote(path)}"


@files_router.post("/files/upload", summary="上传文件")
async def upload_file(
    file: UploadFile = File(...),
    path: str = Form("/", description="目标目录"),
    overwrite: bool = Form(False, description="存在时是否覆盖"),
    token: str = Depends(get_current_token),
):
    content = await file.read()

    def _upload():
        svc = _mount_svc()
        try:
            mount_name, target_dir = svc.resolve(path)
        except ValueError as e:
            raise HTTPException(403, str(e))
        os.makedirs(target_dir, exist_ok=True)

        dest = os.path.join(target_dir, file.filename)
        if os.path.exists(dest):
            if overwrite:
                os.remove(dest)
            else:
                base, ext = os.path.splitext(file.filename)
                counter = 1
                while os.path.exists(os.path.join(target_dir, f"{base}({counter}){ext}")):
                    counter += 1
                dest = os.path.join(target_dir, f"{base}({counter}){ext}")

        try:
            with open(dest, "wb") as f:
                f.write(content)
        except Exception as e:
            raise HTTPException(500, f"上传失败: {e}")
        rel = mount_name + "/" + os.path.basename(dest)
        return {"path": "/" + rel, "size": len(content)}

    return await asyncio.to_thread(_upload)


@files_router.post("/files/mkdir", summary="创建目录")
async def mkdir(
    path: str = Query(..., description="目录路径"),
    token: str = Depends(get_current_token),
):
    def _mkdir():
        svc = _mount_svc()
        try:
            _, abs_path = svc.resolve(path)
        except ValueError as e:
            raise HTTPException(403, str(e))
        if os.path.exists(abs_path):
            base = os.path.basename(path.rstrip("/\\"))
            parent = os.path.dirname(abs_path)
            counter = 1
            while os.path.exists(os.path.join(parent, f"{base}({counter})")):
                counter += 1
            abs_path = os.path.join(parent, f"{base}({counter})")
            new_path = os.path.join(os.path.dirname(path.rstrip("/\\")), f"{base}({counter})")
        else:
            new_path = path
        os.makedirs(abs_path, exist_ok=True)
        return {"path": new_path, "created": True}
    return await asyncio.to_thread(_mkdir)


@files_router.put("/files/rename", summary="重命名文件或目录")
async def rename(
    path: str = Query(..., description="原路径"),
    new_name: str = Query(..., description="新名称"),
    token: str = Depends(get_current_token),
):
    def _rename():
        svc = _mount_svc()
        try:
            _, old_abs = svc.resolve(path)
        except ValueError as e:
            raise HTTPException(403, str(e))
        if not os.path.exists(old_abs):
            raise HTTPException(404, "路径不存在")
        parent = os.path.dirname(old_abs)
        new_abs = os.path.join(parent, new_name)
        if os.path.exists(new_abs):
            raise HTTPException(400, "目标名称已存在")
        os.rename(old_abs, new_abs)
        return {"path": path}
    return await asyncio.to_thread(_rename)


@files_router.delete("/files", summary="删除文件或目录")
async def delete(
    path: str = Query(..., description="要删除的路径"),
    token: str = Depends(get_current_token),
):
    def _delete():
        svc = _mount_svc()
        try:
            _, abs_path = svc.resolve(path)
        except ValueError as e:
            raise HTTPException(403, str(e))
        if not os.path.exists(abs_path):
            raise HTTPException(404, "路径不存在")
        from services.trash_service import TrashService
        TrashService.delete(abs_path, path)
        return {"deleted": True, "trashed": True}
    return await asyncio.to_thread(_delete)
