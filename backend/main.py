from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# ---- Rate limiting ----
from backend.services.rate_limiter import (
    is_rate_limited,
    should_log_rate_limit,
    request_log,
    rate_limit_alerted
)

# ---- Live IDS ----
from backend.live_ids import detect_sql_xss_live
from backend.services.ip_blocker import block_ip

# ---- Alerts & logging ----
from backend.services.alert_service import save_alert, save_live_alert
from backend.services.event_logger import log_event

# ---- Database ----
from backend.database import engine, SessionLocal
from backend.models import Base, Alert, BlockedIP

# ---- Log-based detectors ----
from backend.detector.brute_force import detect_bruteforce
from backend.detector.sql_xss import detect_sql_xss


app = FastAPI(title="IDS Backend")

# ---- CORS ----
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- DB init ----
Base.metadata.create_all(bind=engine)


# =========================================================
# 🔥 LIVE IDS + RATE LIMITING
# =========================================================
@app.middleware("http")
async def live_ids_middleware(request: Request, call_next):

    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        request.headers.get("X-Test-IP")
        or (forwarded.split(",")[0] if forwarded else None)
        or (request.client.host if request.client else "unknown")
    )

    # ================= RATE LIMIT =================
    if is_rate_limited(ip):
        save_live_alert(ip, "Rate Limit / DDoS")

        if should_log_rate_limit(ip):
            log_event(
                ip=ip,
                attack="Rate Limit / DDoS",
                action="BLOCKED",
                source="RATE_LIMITER"
            )
            block_ip(ip, "Rate Limit / DDoS")

        return JSONResponse(
            status_code=429,
            content={
                "error": "Too many requests",
                "reason": "Rate limit exceeded",
                "ip": ip
            }
        )

    # ================= LIVE SQL/XSS =================
    query = request.url.query
    path = request.url.path
    body = (await request.body()).decode(errors="ignore")

    payload = f"{path} {query} {body}".lower()
    attack = detect_sql_xss_live(payload)

    if attack:
        log_event(
            ip=ip,
            attack=attack,
            action="BLOCKED",
            source="LIVE_IDS"
        )

        save_live_alert(ip, attack)
        block_ip(ip, f"{attack} (Live Detection)")

        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by Live IDS",
                "reason": attack,
                "ip": ip
            }
        )

    return await call_next(request)


# =========================================================
# 🟢 MANUAL UNBLOCK
# =========================================================
@app.post("/unblock-ip")
def unblock_ip_api(data: dict):
    ip = data.get("ip")
    if not ip:
        return {"error": "IP address required"}

    db = SessionLocal()
    blocked = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()

    if not blocked:
        db.close()
        return {"status": "not_blocked", "ip": ip}

    db.delete(blocked)
    db.commit()
    db.close()

    request_log.pop(ip, None)
    rate_limit_alerted.discard(ip)

    return {"status": "unblocked", "ip": ip}


# =========================================================
# ROUTES
# =========================================================
@app.get("/")
def root():
    return {"message": "IDS Backend is running"}


@app.get("/detect/bruteforce")
def run_bruteforce_detection():
    alerts = detect_bruteforce()
    for alert in alerts:
        save_alert(alert)
    return {"status": "completed", "alerts_detected": len(alerts)}


@app.get("/detect/sql-xss")
def run_sql_xss_detection():
    alerts = detect_sql_xss()
    for alert in alerts:
        save_alert(alert)
    return {"status": "completed", "alerts_detected": len(alerts)}


@app.get("/alerts")
def get_alerts():
    db = SessionLocal()
    alerts = db.query(Alert).order_by(Alert.detected_at.desc()).all()
    db.close()
    return [
        {
            "id": a.id,
            "ip_address": a.ip_address,
            "attack_type": a.attack_type,
            "attempts": a.attempts,
            "severity": a.severity,
            "detected_at": a.detected_at.isoformat()
        }
        for a in alerts
    ]


@app.get("/blocked-ips")
def get_blocked_ips():
    db = SessionLocal()
    ips = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    db.close()
    return [
        {
            "ip_address": ip.ip_address,
            "reason": ip.reason,
            "blocked_at": ip.blocked_at.isoformat()
        }
        for ip in ips
    ]

