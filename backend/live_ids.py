
import re

XSS_PATTERNS = [
    r"<script",
    r"onerror=",
    r"onload=",
    r"javascript:",
    r"<svg",
]

SQL_PATTERNS = [
    r"union\s+select",
    r"or\s+1=1",
    r"drop\s+table",
    r"--",
]

def detect_live_attack(payload: str):
    payload = payload.lower()

    for p in SQL_PATTERNS:
        if re.search(p, payload):
            return "SQL Injection", "RULE"

    for p in XSS_PATTERNS:
        if re.search(p, payload):
            return "XSS", "RULE"

    return None, None
