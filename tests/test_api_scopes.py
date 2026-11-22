"""API 令牌作用域与敏感设置脱敏的单元测试。"""

import unittest

from services.api_scopes import ALL_SCOPES, is_mcp_path, mask_setting, required_scope


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


if __name__ == "__main__":
    unittest.main()
