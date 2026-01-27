

import re
from backend.detector.access_log import parse_access_log


SQL_PATTERNS = [
    r"union\s+select",
    r"select\s+\*",
    r"drop\s+table",
    r"or\s+1=1",
    r"--",
    r";"
]


XSS_PATTERNS = [
    r"<script.*?>",
    r"</script>",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:"
]


def detect_sql_xss():
    logs = parse_access_log()
    alerts = []

    for log in logs:
        request = log.get("request", "").lower() if "request" in log else ""

       
        for pattern in SQL_PATTERNS:
            if re.search(pattern, request):
                alerts.append({
                    "ip": log["ip"],
                    "attack": "SQL Injection",
                    "attempts": 1,
                    "time_window": "N/A",
                    "detected_at": log["timestamp"]
                })
                break

        
        for pattern in XSS_PATTERNS:
            if re.search(pattern, request):
                alerts.append({
                    "ip": log["ip"],
                    "attack": "XSS",
                    "attempts": 1,
                    "time_window": "N/A",
                    "detected_at": log["timestamp"]
                })
                break

    return alerts
