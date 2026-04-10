from collections import defaultdict

class SessionTracker:
    def __init__(self, max_per_ip: int = 50):
        self.max_per_ip = max_per_ip
        self._c = defaultdict(int)

    def allow(self, ip: str) -> bool:
        if self._c[ip] >= self.max_per_ip:
            return False
        self._c[ip] += 1
        return True

    def release(self, ip: str):
        if self._c[ip] > 0:
            self._c[ip] -= 1
