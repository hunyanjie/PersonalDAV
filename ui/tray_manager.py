import threading
import pystray
from PIL import Image, ImageDraw, ImageFont
from config import SOFTWARE_NAME


class TrayManager:
    def __init__(self, root, on_show=None, on_quit=None):
        self.root = root
        self._on_show = on_show
        self._on_quit = on_quit
        self._icon = None
        self._thread = None

    def start(self):
        icon = self._create_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem("显示窗口", self._show_window, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("退出", self._quit_app),
        )
        self._icon = pystray.Icon(SOFTWARE_NAME, icon, SOFTWARE_NAME, menu)
        self._thread = threading.Thread(target=self._icon.run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._icon:
            self._icon.stop()

    def _create_icon_image(self):
        size = 64
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse([2, 2, size - 2, size - 2], fill=(41, 128, 255))
        try:
            font = ImageFont.truetype("segoeui.ttf", 32)
        except Exception:
            font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), "PD", font=font)
        tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
        x = (size - tw) / 2 - bbox[0]
        y = (size - th) / 2 - bbox[1]
        draw.text((x, y), "PD", fill="white", font=font)
        return img

    def _show_window(self):
        self.root.after(0, self._on_show)

    def _quit_app(self):
        self.root.after(0, self._on_quit)
