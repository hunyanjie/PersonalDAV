"""REST API — file management (multi-mount aware)."""

import asyncio
import os
import shutil
import mimetypes
import tempfile
import subprocess
from urllib.parse import quote
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form
from fastapi.responses import FileResponse, RedirectResponse
from .auth import get_current_token
from .config import DaemonConfig

_OFFICE_EXTS = {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp'}

files_router = APIRouter(tags=["文件管理"])


def _mount_svc():
    from services.file_mount_service import FileMountService
    return FileMountService()


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
        entry = await asyncio.to_thread(svc.add_mount, body["name"], body["path"])
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
        entry = await asyncio.to_thread(svc.update_mount, name, body.get("name", name), body.get("path", ""))
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
