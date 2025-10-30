import time
from typing import Dict, Tuple


class TokenBucket:
    def __init__(self, capacity: float, refill_per_sec: float):
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.refill_per_sec = float(refill_per_sec)
        self.last = time.time()
        self.limited_count = 0

    def _refill(self, now: float) -> None:
        dt = max(0.0, now - self.last)
        self.tokens = min(self.capacity, self.tokens + dt * self.refill_per_sec)
        self.last = now

    def allow(self, cost: float = 1.0) -> bool:
        now = time.time()
        self._refill(now)
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        self.limited_count += 1
        return False


class AdaptiveRateLimiter:
    def __init__(self, default_capacity: float = 30.0, default_refill_per_sec: float = 1.0):
        self.default_capacity = default_capacity
        self.default_refill = default_refill_per_sec
        self.buckets: Dict[str, TokenBucket] = {}
        self.enabled = True

    def bucket_for(self, ip: str) -> TokenBucket:
        b = self.buckets.get(ip)
        if not b:
            b = TokenBucket(self.default_capacity, self.default_refill)
            self.buckets[ip] = b
        return b

    def should_limit(self, ip: str, cost: float = 1.0) -> bool:
        if not self.enabled:
            return False
        return not self.bucket_for(ip).allow(cost)

    def adjust(self, ip: str, more_strict: bool) -> None:
        # tighten or relax per IP based on detections
        b = self.bucket_for(ip)
        if more_strict:
            b.capacity = max(5.0, b.capacity * 0.8)
            b.refill_per_sec = max(0.2, b.refill_per_sec * 0.8)
        else:
            b.capacity = min(200.0, b.capacity * 1.1)
            b.refill_per_sec = min(10.0, b.refill_per_sec * 1.1)

    def snapshot(self, k: int = 20):
        items: Dict[str, Tuple[float, float, float, int]] = {}
        for ip, b in self.buckets.items():
            items[ip] = (b.capacity, b.refill_per_sec, b.tokens, b.limited_count)
        # sort by limited_count then lowest tokens
        return sorted(items.items(), key=lambda x: (x[1][3], -x[1][2]), reverse=True)[:k]


rate_limiter = AdaptiveRateLimiter()


