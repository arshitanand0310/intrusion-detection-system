# backend/live_ids.py

import re
from fastapi import Request
from backend.services.ip_blocker import block_ip

# SQL & XSS signatures (simplified WAF rules)
SQL_PATTERNS = [
    r"union\s+select",
    r"or\s+1=1",
    r"drop\s+table",
    r"--"
]

XSS_PATTERNS = [
    r"<script",
    r"onerror=",
    r"onload=",
    r"javascript:"
]


def detect_sql_xss_live(payload: str) -> str | None:
    payload = payload.lower()

    for pattern in SQL_PATTERNS:
        if re.search(pattern, payload):
            return "SQL Injection"

    for pattern in XSS_PATTERNS:
        if re.search(pattern, payload):
            return "XSS"

    return None
