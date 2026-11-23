"""API 令牌作用域与敏感设置脱敏的单元测试。"""

import os
import shutil
import tempfile
import unittest

from services.api_scopes import ALL_SCOPES, is_mcp_path, mask_setting, required_scope
from services.api_token_service import ApiTokenService
from utils.cert_helper import generate_self_signed_cert, get_cert_info, normalize_cert_path


class TestRequiredScope(unittest.TestCase):
    def test_contacts(self):
        self.assertEqual(required_scope("GET", "/api/contacts"), "contacts:read")
        self.assertEqual(required_scope("POST", "/api/contacts"), "contacts:create")
        self.assertEqual(required_scope("PUT", "/api/contacts/abc"), "contacts:update")
        self.assertEqual(required_scope("DELETE", "/api/contacts/abc"), "contacts:delete")

    def test_management_endpoints_are_not_open(self):
        self.assertEqual(required_scope("GET", "/api/settings"), "settings:read")
        self.assertEqual(required_scope("PUT", "/api/settings/theme_color"), "settings:write")
        self.assertEqual(required_scope("GET", "/api/auth/tokens"), "tokens:manage")
        self.assertEqual(required_scope("POST", "/api/auth/tokens"), "tokens:manage")
        self.assertEqual(required_scope("GET", "/api/apple/qr"), "settings:read")
        self.assertEqual(required_scope("GET", "/api/trash"), "trash:read")
        self.assertEqual(required_scope("DELETE", "/api/trash"), "trash:write")
        self.assertEqual(required_scope("POST", "/api/files/mounts"), "files:manage")

    def test_health_and_unknown_api(self):
        self.assertIsNone(required_scope("GET", "/api/health"))
        # 未分类 API 默认要求令牌管理权限（fail closed）
        self.assertEqual(required_scope("GET", "/api/future-admin"), "tokens:manage")

    def test_mcp_paths(self):
        self.assertTrue(is_mcp_path("/mcp"))
        self.assertTrue(is_mcp_path("/mcp/sse"))
        self.assertTrue(is_mcp_path("/mcp/messages/"))
        self.assertFalse(is_mcp_path("/api/mcp"))
        self.assertFalse(is_mcp_path("/mcpfake"))


class TestSensitiveSettings(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(mask_setting("access_password_hash", "salt$hash"), "********")
        self.assertEqual(mask_setting("ftp_password", "secret"), "********")
        self.assertEqual(mask_setting("mcp_token_salt", "abc"), "********")
        self.assertEqual(mask_setting("theme_color", "#1677ff"), "#1677ff")

    def test_all_scopes_have_labels(self):
        self.assertIn("tokens:manage", ALL_SCOPES)
        self.assertIn("files:manage", ALL_SCOPES)


class TestTokenUpdate(unittest.TestCase):
    def test_update_scopes_note_and_expiry(self):
        svc = ApiTokenService()
        created = svc.create_token(["contacts:read"], "old", "")
        svc.update_token(created["id"], ["contacts:read", "events:read"], "new", "2030-01-01T00:00:00")
        token = next(t for t in svc.list_tokens() if t["id"] == created["id"])
        self.assertEqual(token["note"], "new")
        self.assertEqual(set(token["scopes"]), {"contacts:read", "events:read"})
        self.assertEqual(token["expires_at"], "2030-01-01T00:00:00")
        svc.delete_token(created["id"])


class TestCertPaths(unittest.TestCase):
    def test_relative_path_is_absolutized(self):
        path = normalize_cert_path(r"./docs/cert.pem")
        self.assertTrue(os.path.isabs(path))
        self.assertTrue(path.endswith(os.path.join("docs", "cert.pem")))

    def test_generate_and_read(self):
        tmp = tempfile.mkdtemp(prefix="pdav-cert-test-")
        try:
            cert = os.path.join(tmp, "nested", "cert.pem")
            key = os.path.join(tmp, "nested", "key.pem")
            cert_out, key_out = generate_self_signed_cert(cert, key)
            self.assertTrue(os.path.isfile(cert_out))
            self.assertTrue(os.path.isfile(key_out))
            info = get_cert_info(cert_out)
            self.assertIsNotNone(info)
            self.assertGreater(info["remaining_days"], 300)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
