"""REST API — file management (multi-mount aware)."""

import os
import shutil
import mimetypes
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from .auth import get_current_token
from .config import DaemonConfig

files_router = APIRouter(tags=["文件管理"])


def _mount_svc():
    from services.file_mount_service import FileMountService
    return FileMountService()


# ── Mount management API ──

@files_router.get("/files/mounts", summary="列出所有挂载点")
async def list_mounts(token: str = Depends(get_current_token)):
    from services.file_mount_service import FileMountService
    return FileMountService().get_mounts()


@files_router.post("/files/mounts", summary="添加挂载点")
async def add_mount(
    body: dict,
    token: str = Depends(get_current_token),
):
    from services.file_mount_service import FileMountService
    svc = FileMountService()
    try:
        entry = svc.add_mount(body["name"], body["path"])
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
        entry = svc.update_mount(name, body.get("name", name), body.get("path", ""))
        return entry
    except ValueError as e:
        raise HTTPException(400, str(e))


@files_router.delete("/files/mounts/{name}", summary="删除挂载点")
async def delete_mount(
    name: str,
    token: str = Depends(get_current_token),
):
    from services.file_mount_service import FileMountService
    if FileMountService().remove_mount(name):
        return {"deleted": True}
    raise HTTPException(404, f"Mount '{name}' not found")


@files_router.get("/files", summary="列出目录内容")
async def list_files(
    path: str = Query("/", description="目录路径"),
    token: str = Depends(get_current_token),
):
    svc = _mount_svc()
    from .daemon import logger

    if path == "/" or path == "":
        items = svc.get_root_entries()
        if logger:
            logger.debug(f"Root entries: {len(items)} items")
        return items

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
                rel = mount_name + "/" + name
                items.append({
                    "name": name,
                    "path": "/" + rel,
                    "is_dir": os.path.isdir(full),
                    "size": st.st_size if os.path.isfile(full) else 0,
                    "modified_at": datetime.fromtimestamp(st.st_mtime).isoformat(),
                })
            except Exception:
                pass
    except Exception as e:
        raise HTTPException(500, f"读取目录失败: {e}")
    return items


@files_router.get("/files/download", summary="下载文件")
async def download_file(
    path: str = Query(..., description="文件路径"),
    token: str = Depends(get_current_token),
):
    svc = _mount_svc()
    try:
        _, abs_path = svc.resolve(path)
    except ValueError as e:
        raise HTTPException(403, str(e))
    if not os.path.isfile(abs_path):
        raise HTTPException(404, "文件不存在")
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
    token: str = Depends(get_current_token),
):
    svc = _mount_svc()
    try:
        _, abs_path = svc.resolve(path)
    except ValueError as e:
        raise HTTPException(403, str(e))
    if not os.path.isfile(abs_path):
        raise HTTPException(404, "文件不存在")
    _, ext = os.path.splitext(abs_path)
    ctype = mimetypes.guess_type(abs_path)[0] or _MIME_OVERRIDES.get(ext.lower())
    if ctype and ctype.startswith(("text/", "image/", "application/pdf")):
        from fastapi.responses import FileResponse
        return FileResponse(abs_path, media_type=ctype)
    raise HTTPException(415, "不支持预览该文件类型")


@files_router.post("/files/upload", summary="上传文件")
async def upload_file(
    file: UploadFile = File(...),
    path: str = Form("/", description="目标目录"),
    token: str = Depends(get_current_token),
):
    svc = _mount_svc()
    try:
        mount_name, target_dir = svc.resolve(path)
    except ValueError as e:
        raise HTTPException(403, str(e))
    os.makedirs(target_dir, exist_ok=True)
    dest = os.path.join(target_dir, file.filename)
    try:
        content = await file.read()
        with open(dest, "wb") as f:
            f.write(content)
    except Exception as e:
        raise HTTPException(500, f"上传失败: {e}")
    rel = mount_name + "/" + os.path.basename(dest)
    return {"path": "/" + rel, "size": len(content)}


@files_router.post("/files/mkdir", summary="创建目录")
async def mkdir(
    path: str = Query(..., description="目录路径"),
    token: str = Depends(get_current_token),
):
    svc = _mount_svc()
    try:
        _, abs_path = svc.resolve(path)
    except ValueError as e:
        raise HTTPException(403, str(e))
    if os.path.exists(abs_path):
        raise HTTPException(400, "路径已存在")
    os.makedirs(abs_path, exist_ok=True)
    return {"path": path, "created": True}


@files_router.put("/files/rename", summary="重命名文件或目录")
async def rename(
    path: str = Query(..., description="原路径"),
    new_name: str = Query(..., description="新名称"),
    token: str = Depends(get_current_token),
):
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


@files_router.delete("/files", summary="删除文件或目录")
async def delete(
    path: str = Query(..., description="要删除的路径"),
    token: str = Depends(get_current_token),
):
    svc = _mount_svc()
    try:
        _, abs_path = svc.resolve(path)
    except ValueError as e:
        raise HTTPException(403, str(e))
    if not os.path.exists(abs_path):
        raise HTTPException(404, "路径不存在")
    if os.path.isfile(abs_path):
        os.remove(abs_path)
    else:
        shutil.rmtree(abs_path)
    return {"deleted": True}
