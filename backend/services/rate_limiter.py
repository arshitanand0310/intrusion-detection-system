# backend/services/rate_limiter.py

import time
from collections import defaultdict, deque

REQUEST_LIMIT = 30
WINDOW_SECONDS = 10

request_log = defaultdict(deque)
rate_limit_alerted = set()   # 🔥 NEW


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window_start = now - WINDOW_SECONDS

    timestamps = request_log[ip]

    while timestamps and timestamps[0] < window_start:
        timestamps.popleft()

    timestamps.append(now)

    return len(timestamps) > REQUEST_LIMIT


def should_log_rate_limit(ip: str) -> bool:
    """
    Ensures rate limit alert is logged only ONCE per IP.
    """
    if ip in rate_limit_alerted:
        return False

    rate_limit_alerted.add(ip)
    return True
