"""
UI 快照测试 — 关键对话框截图对比与结构验证。
首次运行自动生成参考截图，后续运行比对像素差异。
参考截图存放于 tests/snapshots/ 目录。

环境变量:
  SNAPSHOT_UPDATE=1  强制更新所有参考截图
"""
import unittest
import os

from tests.conftest import TK_ROOT as ROOT, TK_AVAILABLE
if TK_AVAILABLE:
    import tkinter as tk
else:
    tk = None

from pathlib import Path
from PIL import Image, ImageChops, ImageGrab

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
UPDATE_SNAPSHOTS = os.environ.get("SNAPSHOT_UPDATE", "0") == "1"
TOLERANCE = 0.02


def _capture_widget(widget) -> Image.Image:
    widget.update_idletasks()
    widget.update()
    x = widget.winfo_rootx()
    y = widget.winfo_rooty()
    w = widget.winfo_width()
    h = widget.winfo_height()
    if w < 10 or h < 10:
        widget.update_idletasks()
        widget.update()
        x = widget.winfo_rootx()
        y = widget.winfo_rooty()
        w = widget.winfo_width()
        h = widget.winfo_height()
    return ImageGrab.grab(bbox=(x, y, x + w, y + h))


def _compare_images(captured: Image.Image, ref_path: Path, tolerance: float = TOLERANCE) -> bool:
    if not ref_path.exists():
        captured.save(ref_path)
        return True
    ref = Image.open(ref_path)
    if captured.size != ref.size:
        return False
    diff = ImageChops.difference(captured, ref)
    pixels = diff.getdata()
    total = len(list(pixels))
    changed = sum(1 for p in pixels if any(c > 5 for c in p[:3]))
    return (changed / total) <= tolerance


@unittest.skipUnless(TK_AVAILABLE, "tkinter not available")
class TestUiSnapshot(unittest.TestCase):
    def test_about_dialog_snapshot(self):
        from ui.dialogs.about_dialog import AboutDialog
        dlg = AboutDialog(ROOT)
        self.assertEqual(dlg.title(), "关于 PrivateDAV")
        self._snapshot(dlg, "about_dialog")
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

    def _snapshot(self, dialog, name: str):
        ref_path = SNAPSHOT_DIR / f"{name}.png"
        captured = _capture_widget(dialog)
        if UPDATE_SNAPSHOTS:
            captured.save(ref_path)
            self.skipTest(f"Snapshot updated: {ref_path}")
        ok = _compare_images(captured, ref_path)
        if not ok:
            diff_dir = SNAPSHOT_DIR / "diff"
            diff_dir.mkdir(exist_ok=True)
            captured.save(diff_dir / f"{name}_actual.png")
        self.assertTrue(ok, f"Snapshot mismatch for {name}. Actual saved to diff/{name}_actual.png")
