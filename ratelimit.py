"""Small in-memory abuse controls: a sliding-window rate limiter and a failure lockout.

State is per-process, which is fine for a single-worker deployment.
"""
import time
from collections import defaultdict, deque


class RateLimiter:
    """At most `limit` events per `window` seconds for each key."""

    def __init__(self, limit: int, window: float, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self.clock()
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def prune(self) -> None:
        now = self.clock()
        for key in [k for k, q in self._hits.items() if not q or now - q[-1] > self.window]:
            del self._hits[key]


class Lockout:
    """Locks a key for `lock_for` seconds after `max_fails` failures within `window` seconds."""

    def __init__(self, max_fails: int, window: float, lock_for: float, clock=time.monotonic):
        self.max_fails, self.window, self.lock_for, self.clock = max_fails, window, lock_for, clock
        self._fails = defaultdict(deque)
        self._locked_until = {}

    def is_locked(self, key: str) -> bool:
        until = self._locked_until.get(key)
        if until is None:
            return False
        if self.clock() >= until:
            del self._locked_until[key]
            self._fails.pop(key, None)
            return False
        return True

    def record_failure(self, key: str) -> bool:
        """Record a failure. Returns True if this failure just triggered a lock."""
        now = self.clock()
        q = self._fails[key]
        while q and now - q[0] > self.window:
            q.popleft()
        q.append(now)
        if len(q) >= self.max_fails:
            self._locked_until[key] = now + self.lock_for
            q.clear()
            return True
        return False

    def prune(self) -> None:
        now = self.clock()
        for key in [k for k, until in self._locked_until.items() if now >= until]:
            del self._locked_until[key]
        for key in [k for k, q in self._fails.items() if not q or now - q[-1] > self.window]:
            del self._fails[key]
