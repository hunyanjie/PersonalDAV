import unittest
import gc
import tkinter as tk


class TestMemoryLeak(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tk.Tk()
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()
        del cls.root

    def setUp(self):
        gc.collect()

    def assert_no_widget_leak(self, factory_fn, iterations: int = 10):
        gc.collect()
        type_counts_before = {}
        for obj in gc.get_objects():
            name = type(obj).__name__
            type_counts_before[name] = type_counts_before.get(name, 0) + 1

        created = []
        for i in range(iterations):
            w = factory_fn()
            created.append(w)
        for w in created:
            try:
                if w.winfo_exists():
                    w.destroy()
            except tk.TclError:
                pass
        del created

        gc.collect()
        type_counts_after = {}
        for obj in gc.get_objects():
            name = type(obj).__name__
            type_counts_after[name] = type_counts_after.get(name, 0) + 1

        sensitive = {"Toplevel", "Tk", "Frame", "Label", "Button", "Entry", "Text", "Listbox", "Checkbutton"}
        leaked = {}
        for name in sensitive:
            diff = type_counts_after.get(name, 0) - type_counts_before.get(name, 0)
            if diff > 3:
                leaked[name] = diff

        if leaked:
            self.fail(f"Leaked tkinter widgets after {iterations} cycles: {leaked}")

    def test_toplevel_no_leak(self):
        def make():
            d = tk.Toplevel(self.root)
            tk.Label(d, text="x").pack()
            tk.Button(d, text="ok").pack()
            return d
        self.assert_no_widget_leak(make, iterations=10)

    def test_label_no_leak(self):
        def make():
            return tk.Label(self.root, text="test")
        self.assert_no_widget_leak(make, iterations=100)


if __name__ == "__main__":
    unittest.main()
