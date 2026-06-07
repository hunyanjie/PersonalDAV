"""
UI 结构验证测试 — 检测对话框基本结构完整性。
"""
import unittest

from tests.conftest import TK_ROOT as ROOT, TK_AVAILABLE
if TK_AVAILABLE:
    import tkinter as tk
else:
    tk = None


@unittest.skipUnless(TK_AVAILABLE, "tkinter not available")
class TestUiSnapshot(unittest.TestCase):
    def test_about_dialog_title(self):
        from ui.dialogs.about_dialog import AboutDialog
        dlg = AboutDialog(ROOT)
        self.assertEqual(dlg.title(), "关于 PersonalDAV")
        dlg.destroy()

    def test_settings_dialog_title(self):
        from services.settings_service import SettingsService
        from ui.dialogs.settings_dialog import SettingsDialog
        dlg = SettingsDialog(ROOT, SettingsService(), lambda s: None)
        self.assertEqual(dlg.title(), "设置")
        dlg.destroy()

    def test_settings_dialog_has_notebook_tabs(self):
        from services.settings_service import SettingsService
        from ui.dialogs.settings_dialog import SettingsDialog
        dlg = SettingsDialog(ROOT, SettingsService(), lambda s: None)
        for child in dlg.winfo_children():
            if isinstance(child, tk.Frame):
                for sub in child.winfo_children():
                    if hasattr(sub, 'tab'):
                        tabs = [sub.tab(i, "text") for i in range(sub.index("end"))]
                        self.assertIn("安全设置", tabs)
                        self.assertIn("日历设置", tabs)
                        self.assertIn("服务器设置", tabs)
                        self.assertIn("同步设置", tabs)
                        self.assertIn("日志设置", tabs)
                        self.assertIn("审计日志", tabs)
                        self.assertIn("MCP 服务", tabs)
                        break
        ROOT.update()
        dlg.destroy()
