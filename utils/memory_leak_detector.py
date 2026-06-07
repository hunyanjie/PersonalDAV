import tracemalloc
import gc
from collections import defaultdict


class MemoryLeakDetector:
    def __init__(self):
        self._snapshots = {}
        self._running = False

    def start(self):
        tracemalloc.start(25)
        self._running = True

    def stop(self):
        tracemalloc.stop()
        self._running = False

    def take_snapshot(self, label: str):
        if not self._running:
            raise RuntimeError("tracemalloc not started, call start() first")
        self._snapshots[label] = tracemalloc.take_snapshot()

    def diff(self, label_a: str, label_b: str, top: int = 20) -> list[tuple[int, str]]:
        snap_a = self._snapshots.get(label_a)
        snap_b = self._snapshots.get(label_b)
        if not snap_a or not snap_b:
            return []
        stats = snap_b.compare_to(snap_a, 'lineno')
        return [(stat.size_diff, str(stat)) for stat in stats[:top]]

    def diff_summary(self, label_a: str, label_b: str) -> str:
        lines = []
        for size_diff, stat_str in self.diff(label_a, label_b):
            lines.append(f"{size_diff:>+10}  {stat_str}")
        return "\n".join(lines)

    def print_diff(self, label_a: str, label_b: str):
        print(f"\n--- Memory diff: {label_a} → {label_b} ---")
        total = 0
        for size_diff, stat_str in self.diff(label_a, label_b, top=30):
            if abs(size_diff) > 1024:
                print(f"{size_diff // 1024:>+6} KB  {stat_str}")
            else:
                print(f"{size_diff:>+10} B  {stat_str}")
            total += size_diff
        print(f"Total diff: {total // 1024} KB ({total} B)")


def count_garbage() -> dict:
    gc.collect()
    counts = defaultdict(int)
    for obj in gc.get_objects():
        counts[type(obj).__name__] += 1
    return dict(counts)


def print_garbage_diff(before: dict, after: dict, top: int = 20):
    leaked = {}
    for name, count in after.items():
        diff = count - before.get(name, 0)
        if diff > 0:
            leaked[name] = diff
    sorted_leaked = sorted(leaked.items(), key=lambda x: -x[1])[:top]
    if not sorted_leaked:
        print("No leaked objects detected")
        return
    print(f"\n--- Garbage collector diff (top {top}) ---")
    for name, diff in sorted_leaked:
        print(f"  {name}: +{diff}")
