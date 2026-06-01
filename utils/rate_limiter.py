import time
import threading
from collections import defaultdict


class RateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str, max_requests: int, window_seconds: int = 60) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            timestamps = self._windows[key]
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if len(timestamps) >= max_requests:
                return False
            timestamps.append(now)
            return True

    def cleanup(self, max_age: int = 300):
        cutoff = time.time() - max_age
        with self._lock:
            for key in list(self._windows.keys()):
                self._windows[key][:] = [t for t in self._windows[key] if t > cutoff]
                if not self._windows[key]:
                    del self._windows[key]


_rate_limiter = RateLimiter()


def get_rate_limiter() -> RateLimiter:
    return _rate_limiter
