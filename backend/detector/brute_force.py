
from collections import defaultdict
from datetime import timedelta
from backend.detector.access_log import parse_access_log

TIME_WINDOW_MINUTES = 1
MIN_BRUTEFORCE_ATTEMPTS = 5  


def detect_bruteforce():
    logs = parse_access_log()

    failed_attempts = defaultdict(list)
    alerts = []

    # collect failed login timestamps per IP
    for log in logs:
        if log["endpoint"] == "/login" and log["status"] == "FAIL":
            failed_attempts[log["ip"]].append(log["timestamp"])

    for ip, timestamps in failed_attempts.items():
        timestamps.sort()

        # sliding window
        for i in range(len(timestamps)):
            window = []
            for t in timestamps:
                if timestamps[i] <= t <= timestamps[i] + timedelta(minutes=TIME_WINDOW_MINUTES):
                    window.append(t)

            attempt_count = len(window)

            if attempt_count >= MIN_BRUTEFORCE_ATTEMPTS:
                alerts.append({
                    "ip": ip,
                    "attack": "Brute Force",
                    "attempts": attempt_count,   
                    "time_window": "1 minute",
                    "detected_at": window[-1]
                })
                break

    return alerts
