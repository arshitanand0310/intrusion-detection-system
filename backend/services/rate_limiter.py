# backend/services/rate_limiter.py

import time
from collections import defaultdict, deque

# Track timestamps of requests per IP
request_log = defaultdict(deque)

# Prevent repeated block spam
rate_limit_alerted = set()

# CONFIG
WINDOW_SECONDS = 5          # sliding window
LOW_RPS = 10
MEDIUM_RPS = 20
HIGH_RPS = 30


def get_rps(ip: str) -> int:
    """Return requests-per-second for given IP"""
    now = time.time()
    q = request_log[ip]

    # Remove old timestamps
    while q and q[0] < now - WINDOW_SECONDS:
        q.popleft()

    return int(len(q) / WINDOW_SECONDS)


def register_request(ip: str):
    request_log[ip].append(time.time())


def is_rate_limited(ip: str) -> bool:
    register_request(ip)
    rps = get_rps(ip)

    return rps >= LOW_RPS


def get_ddos_severity(ip: str) -> str:
    rps = get_rps(ip)

    if rps >= HIGH_RPS:
        return "HIGH"
    elif rps >= MEDIUM_RPS:
        return "MEDIUM"
    elif rps >= LOW_RPS:
        return "LOW"
    else:
        return "NONE"


def should_log_rate_limit(ip: str) -> bool:
    """Log/block only once per IP"""
    if ip in rate_limit_alerted:
        return False

    rate_limit_alerted.add(ip)
    return True
