"""Token-bucket rate limiter and concurrent-connection counter, bounded in memory."""
from __future__ import annotations

import threading
import time
from collections import OrderedDict


class TokenBucketLimiter:
    """Per-key token bucket. State is bounded: when full, the least-recently-used key is evicted
    (an attacker with many source addresses can therefore reset a stale key's history)."""

    def __init__(self, rate: float, burst: float, max_keys: int = 100_000, clock=time.monotonic):
        if rate <= 0 or burst < 1 or max_keys < 1:
            raise ValueError("rate must be >0, burst >=1, max_keys >=1")
        self.rate, self.burst, self.max_keys, self._clock = float(rate), float(burst), max_keys, clock
        self._b: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key, cost: float = 1.0) -> bool:
        now = self._clock()
        with self._lock:
            ent = self._b.get(key)
            if ent is None:
                if len(self._b) >= self.max_keys:
                    self._b.popitem(last=False)
                tokens = self.burst
            else:
                tokens = min(self.burst, ent[0] + (now - ent[1]) * self.rate)
            ok = tokens >= cost
            if ok:
                tokens -= cost
            self._b[key] = (tokens, now)
            self._b.move_to_end(key)
            return ok

    def __len__(self):
        return len(self._b)


class ConnectionCounter:
    """Caps concurrent connections per key."""

    def __init__(self, limit: int):
        self.limit = limit
        self._n: dict = {}
        self._lock = threading.Lock()

    def acquire(self, key) -> bool:
        with self._lock:
            n = self._n.get(key, 0)
            if n >= self.limit:
                return False
            self._n[key] = n + 1
            return True

    def release(self, key) -> None:
        with self._lock:
            n = self._n.get(key, 0) - 1
            if n <= 0:
                self._n.pop(key, None)
            else:
                self._n[key] = n

    def current(self, key) -> int:
        return self._n.get(key, 0)
