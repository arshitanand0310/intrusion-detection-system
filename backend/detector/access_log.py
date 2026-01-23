# backend/detector/access_log.py

from datetime import datetime

LOG_FILE = "backend/logs/access.log"


def parse_access_log():
    logs = []

    with open(LOG_FILE, "r") as file:
        for line in file:
            try:
                parts = line.strip().split("|")

                timestamp = datetime.strptime(
                    parts[0].strip(), "%Y-%m-%d %H:%M:%S"
                )

                # split ONLY on first '=' to preserve payloads
                ip = parts[1].split("=", 1)[1].strip()
                endpoint = parts[2].split("=", 1)[1].strip()
                status = parts[3].split("=", 1)[1].strip()

                request = ""
                if len(parts) > 4:
                    request = parts[4].split("=", 1)[1].strip()

                logs.append({
                    "timestamp": timestamp,
                    "ip": ip,
                    "endpoint": endpoint,
                    "status": status,
                    "request": request
                })

            except Exception:
                # skip malformed lines safely
                continue

    return logs
