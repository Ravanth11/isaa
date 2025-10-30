import time
from typing import Dict, List, Tuple


class ReputationStore:
    def __init__(self, decay_per_minute: float = 1.0, ban_threshold: float = 10.0):
        self.scores: Dict[str, float] = {}
        self.last_update: Dict[str, float] = {}
        self.banned: Dict[str, float] = {}
        self.decay_per_minute = decay_per_minute
        self.ban_threshold = ban_threshold

    def _apply_decay(self, ip: str, now: float) -> None:
        if ip not in self.scores:
            return
        last = self.last_update.get(ip, now)
        dt_min = max(0.0, (now - last) / 60.0)
        self.scores[ip] = max(0.0, self.scores[ip] - dt_min * self.decay_per_minute)
        self.last_update[ip] = now

    def update(self, ip: str, delta: float) -> float:
        now = time.time()
        self._apply_decay(ip, now)
        self.scores[ip] = self.scores.get(ip, 0.0) + delta
        self.last_update[ip] = now
        if self.scores[ip] >= self.ban_threshold:
            self.banned[ip] = now
        return self.scores[ip]

    def is_banned(self, ip: str) -> bool:
        return ip in self.banned

    def ban(self, ip: str) -> None:
        self.banned[ip] = time.time()

    def unban(self, ip: str) -> None:
        if ip in self.banned:
            del self.banned[ip]

    def set_params(self, decay_per_minute: float = None, ban_threshold: float = None):
        if decay_per_minute is not None:
            self.decay_per_minute = float(decay_per_minute)
        if ban_threshold is not None:
            self.ban_threshold = float(ban_threshold)

    def top(self, k: int = 20) -> List[Tuple[str, float]]:
        # Apply a light decay on access so scores stay fresh
        now = time.time()
        for ip in list(self.scores.keys()):
            self._apply_decay(ip, now)
            if self.scores.get(ip, 0.0) <= 0.0 and ip not in self.banned:
                self.scores.pop(ip, None)
                self.last_update.pop(ip, None)
        return sorted(self.scores.items(), key=lambda x: x[1], reverse=True)[:k]


reputation = ReputationStore()


