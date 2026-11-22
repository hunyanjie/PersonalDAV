import os
import mimetypes
from utils.attachment_store import get_attachments_dir


class AttachmentHandler:
    """附件 HTTP 端点（/attachments/）"""

    @staticmethod
    def do_GET(handler):
        filename = os.path.basename(handler.path.rstrip("/"))
        if not filename:
            handler._send_error(400, "Missing filename")
            return
        attachments_dir = get_attachments_dir()
        safe_path = os.path.normpath(os.path.join(attachments_dir, filename))
        if not safe_path.startswith(os.path.normpath(attachments_dir)):
            handler._send_error(403, "Forbidden")
            return
        if not os.path.isfile(safe_path):
            handler._send_error(404, "Attachment not found")
            return
        try:
            with open(safe_path, "rb") as f:
                data = f.read()
            content_type, _ = mimetypes.guess_type(filename)
            handler.send_response(200)
            handler.send_header("Content-Type", content_type or "application/octet-stream")
            handler.send_header("Content-Length", str(len(data)))
            handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            handler.end_headers()
            handler.wfile.write(data)
        except Exception as e:
            handler._send_error(500, str(e))
