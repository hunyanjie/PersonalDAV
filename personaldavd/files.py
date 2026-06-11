"""REST API — file management (dav_root operations)."""

import os
import shutil
import mimetypes
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from .auth import get_current_token
from .config import DaemonConfig

files_router = APIRouter(tags=["文件管理"])


def _get_dav_root() -> str:
    from services.settings_service import SettingsService
    s = SettingsService()
    return s.get_setting("dav_root", "./dav_root")


@files_router.get("/files", summary="列出目录内容")
async def list_files(
    path: str = Query("/", description="目录路径"),
    token: str = Depends(get_current_token),
):
    from .daemon import logger
    root = os.path.abspath(_get_dav_root())
    abs_path = os.path.normpath(os.path.join(root, path.lstrip("/")))
    
    if logger:
        logger.debug(f"Listing files", path=path, root=root, abs_path=abs_path)

    if not abs_path.startswith(root):
        if logger: logger.warning(f"Path traversal attempt", path=path, abs_path=abs_path)
        raise HTTPException(403, "路径越权")
    if not os.path.exists(abs_path):
        if logger: logger.warning(f"Path not found", abs_path=abs_path)
        raise HTTPException(404, "路径不存在")
    if not os.path.isdir(abs_path):
        raise HTTPException(400, "不是目录")
    items = []
    try:
        filenames = sorted(os.listdir(abs_path))
        if logger: logger.debug(f"Found {len(filenames)} items in {abs_path}")
        for name in filenames:
            full = os.path.join(abs_path, name)
            try:
                st = os.stat(full)
                rel = os.path.relpath(full, root).replace("\\", "/")
                items.append({
                    "name": name,
                    "path": "/" + rel,
                    "is_dir": os.path.isdir(full),
                    "size": st.st_size if os.path.isfile(full) else 0,
                    "modified_at": datetime.fromtimestamp(st.st_mtime).isoformat(),
                })
            except Exception as e:
                if logger: logger.error(f"Failed to stat {full}: {e}")
    except Exception as e:
        if logger: logger.error(f"Failed to list directory {abs_path}: {e}")
        raise HTTPException(500, f"读取目录失败: {e}")
    return items


@files_router.get("/files/download", summary="下载文件")
async def download_file(
    path: str = Query(..., description="文件路径"),
    token: str = Depends(get_current_token),
):
    root = _get_dav_root()
    abs_path = os.path.normpath(os.path.join(root, path.lstrip("/")))
    if not abs_path.startswith(os.path.normpath(root)):
        raise HTTPException(403, "路径越权")
    if not os.path.isfile(abs_path):
        raise HTTPException(404, "文件不存在")
    from fastapi.responses import FileResponse
    return FileResponse(abs_path)


@files_router.get("/files/preview", summary="预览文件内容")
async def preview_file(
    path: str = Query(..., description="文件路径"),
    token: str = Depends(get_current_token),
):
    root = _get_dav_root()
    abs_path = os.path.normpath(os.path.join(root, path.lstrip("/")))
    if not abs_path.startswith(os.path.normpath(root)):
        raise HTTPException(403, "路径越权")
    if not os.path.isfile(abs_path):
        raise HTTPException(404, "文件不存在")
    ctype, _ = mimetypes.guess_type(abs_path)
    if ctype and ctype.startswith(("text/", "image/", "application/pdf")):
        from fastapi.responses import FileResponse
        return FileResponse(abs_path, media_type=ctype)
    if ctype and ctype.startswith("image/"):
        from fastapi.responses import FileResponse
        return FileResponse(abs_path, media_type=ctype)
    raise HTTPException(415, "不支持预览该文件类型")


@files_router.post("/files/upload", summary="上传文件")
async def upload_file(
    file: UploadFile = File(...),
    path: str = Form("/", description="目标目录"),
    token: str = Depends(get_current_token),
):
    root = _get_dav_root()
    target_dir = os.path.normpath(os.path.join(root, path.lstrip("/")))
    if not target_dir.startswith(os.path.normpath(root)):
        raise HTTPException(403, "路径越权")
    os.makedirs(target_dir, exist_ok=True)
    dest = os.path.join(target_dir, file.filename)
    try:
        content = await file.read()
        with open(dest, "wb") as f:
            f.write(content)
    except Exception as e:
        raise HTTPException(500, f"上传失败: {e}")
    rel = os.path.relpath(dest, root).replace("\\", "/")
    return {"path": "/" + rel, "size": len(content)}


@files_router.post("/files/mkdir", summary="创建目录")
async def mkdir(
    path: str = Query(..., description="目录路径"),
    token: str = Depends(get_current_token),
):
    root = _get_dav_root()
    abs_path = os.path.normpath(os.path.join(root, path.lstrip("/")))
    if not abs_path.startswith(os.path.normpath(root)):
        raise HTTPException(403, "路径越权")
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
    root = _get_dav_root()
    old_abs = os.path.normpath(os.path.join(root, path.lstrip("/")))
    if not old_abs.startswith(os.path.normpath(root)):
        raise HTTPException(403, "路径越权")
    if not os.path.exists(old_abs):
        raise HTTPException(404, "路径不存在")
    parent = os.path.dirname(old_abs)
    new_abs = os.path.join(parent, new_name)
    if os.path.exists(new_abs):
        raise HTTPException(400, "目标名称已存在")
    os.rename(old_abs, new_abs)
    rel = os.path.relpath(new_abs, root).replace("\\", "/")
    return {"path": "/" + rel}


@files_router.delete("/files", summary="删除文件或目录")
async def delete(
    path: str = Query(..., description="要删除的路径"),
    token: str = Depends(get_current_token),
):
    root = _get_dav_root()
    abs_path = os.path.normpath(os.path.join(root, path.lstrip("/")))
    if not abs_path.startswith(os.path.normpath(root)):
        raise HTTPException(403, "路径越权")
    if not os.path.exists(abs_path):
        raise HTTPException(404, "路径不存在")
    if os.path.isfile(abs_path):
        os.remove(abs_path)
    else:
        shutil.rmtree(abs_path)
    return {"deleted": True}
