from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware


from backend.services.rate_limiter import (
    is_rate_limited,
    should_log_rate_limit,
    request_log,
    rate_limit_alerted,
    get_ddos_severity
)


from backend.live_ids import detect_live_attack
from backend.ml.anomaly_detector import is_anomalous
from backend.services.ip_blocker import block_ip


from backend.services.alert_service import save_alert, save_live_alert
from backend.services.event_logger import log_event


from backend.database import engine, SessionLocal
from backend.models import Base, Alert, BlockedIP


from backend.detector.brute_force import detect_bruteforce
from backend.detector.sql_xss import detect_sql_xss


app = FastAPI(title="IDS Backend")


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)


@app.middleware("http")
async def live_ids_middleware(request: Request, call_next):


    TRUSTED_PATHS = (
        "/alerts",
        "/blocked-ips",
        "/unblock-ip",
        "/detect",
    )

    if request.url.path.startswith(TRUSTED_PATHS):
        return await call_next(request)


    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        request.headers.get("X-Test-IP")
        or (forwarded.split(",")[0] if forwarded else None)
        or (request.client.host if request.client else "unknown")
    )

    print(f"\n{'='*60}")
    print(f"[REQUEST] IP: {ip} | Path: {request.url.path}")
    print(f"{'='*60}")

  
    if is_rate_limited(ip):
        severity = get_ddos_severity(ip)
        print(f"[RATE_LIMIT] IP {ip} is rate limited | Severity: {severity}")

        save_live_alert(ip, "Rate Limit / DDoS")

        if severity == "HIGH" and should_log_rate_limit(ip):
            log_event(
                ip=ip,
                attack="Rate Limit / DDoS",
                action="BLOCKED",
                source="RATE_LIMITER"
            )
            block_ip(ip, "Rate Limit / DDoS")

        if severity == "HIGH":
            return JSONResponse(
                status_code=429,
                content={
                    "error": "DDoS detected",
                    "severity": severity,
                    "ip": ip
                }
            )


    try:
        query = str(request.url.query) if request.url.query else ""
        path = str(request.url.path)
        body = ""
        
        try:
            body_bytes = await request.body()
            body = body_bytes.decode(errors="ignore")
        except Exception as body_error:
            print(f"[MIDDLEWARE] Could not read body: {body_error}")
            body = ""
        
        payload = f"{path} {query} {body}".lower()
        
        print(f"[PAYLOAD] {payload[:200]}")
        
        attack, source = detect_live_attack(payload)
        
        if attack:
            print(f"[DETECTION] ⚠️  Attack detected: {attack} | Source: {source}")
            
            log_event(
                ip=ip,
                attack=attack,
                action="DETECTED",
                source=f"LIVE_{source}"
            )
            
            
            save_live_alert(ip, attack)
            
            
            db = SessionLocal()
            try:
                alert = (
                    db.query(Alert)
                    .filter(Alert.ip_address == ip, Alert.attack_type == attack)
                    .order_by(Alert.detected_at.desc())
                    .first()
                )
                
                if alert:
                    severity = alert.severity
                    print(f"[SEVERITY] {severity} for {attack}")
                    
                    
                    if severity == "HIGH":
                        print(f"[BLOCKING] 🔒 Blocking IP {ip} for {attack}")
                        block_ip(ip, f"{attack} (Live Detection)")
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "Request blocked",
                                "reason": attack,
                                "severity": severity,
                                "ip": ip
                            }
                        )
                    
                    
                    print(f"[MONITORING] 👁️  Monitoring {attack} from {ip}")
                    return JSONResponse(
                        status_code=200,
                        content={
                            "status": "monitoring",
                            "attack": attack,
                            "severity": severity,
                            "ip": ip
                        }
                    )
                else:
                    print(f"[WARNING] Alert not found in DB after save_live_alert")
                    return JSONResponse(
                        status_code=200,
                        content={
                            "status": "monitoring",
                            "attack": attack,
                            "severity": "UNKNOWN",
                            "ip": ip
                        }
                    )
            finally:
                db.close()
                
    except Exception as detection_error:
        print(f"[MIDDLEWARE] Error in SQL/XSS detection: {str(detection_error)}")
        import traceback
        traceback.print_exc()


    try:
        print(f"[ML] Checking payload for anomalies...")
        
        if is_anomalous(payload):
            print(f"[ML] ⚠️  ANOMALY DETECTED!")
            
            log_event(
                ip=ip,
                attack="ML Anomaly",
                action="DETECTED",
                source="ML_IDS"
            )

            
            save_live_alert(ip, "ML Anomaly")
            
            
            print(f"[ML] 🔒 Blocking IP {ip} for ML Anomaly")
            block_ip(ip, "ML Anomaly")

            return JSONResponse(
                status_code=403,
                content={
                    "error": "Zero-day / anomalous behavior detected",
                    "reason": "ML Anomaly",
                    "severity": "HIGH",
                    "ip": ip
                }
            )
        else:
            print(f"[ML] No anomaly detected")
            
    except Exception as ml_error:
        print(f"[ML] Error in ML detection: {str(ml_error)}")
        import traceback
        traceback.print_exc()

    return await call_next(request)



@app.get("/search")
def search(q: str = ""):
    return {"status": "ok", "query": q}


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

    print(f"[UNBLOCK] Unblocked IP: {ip}")
    return {"status": "unblocked", "ip": ip}


@app.get("/")
def root():
    return {"message": "IDS Backend is running"}

@app.get("/detect/bruteforce")
def run_bruteforce_detection():
    print(f"[DETECT] Running brute force detection...")
    alerts = detect_bruteforce()
    for alert in alerts:
        save_alert(alert)
    print(f"[DETECT] Brute force detection completed: {len(alerts)} alerts")
    return {"status": "completed", "alerts_detected": len(alerts)}

@app.get("/detect/sql-xss")
def run_sql_xss_detection():
    print(f"[DETECT] Running SQL/XSS detection...")
    alerts = detect_sql_xss()
    for alert in alerts:
        save_alert(alert)
    print(f"[DETECT] SQL/XSS detection completed: {len(alerts)} alerts")
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

    
    @app.post("/login")
    def login(username: str = "", password: str = ""):
    
        return JSONResponse(
            status_code=401,
            content={"error": "Invalid credentials"}
    )
