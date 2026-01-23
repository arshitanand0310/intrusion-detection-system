from datetime import datetime
from backend.database import SessionLocal
from backend.models import Alert
from backend.detector.severity import calculate_severity
from backend.services.ip_blocker import block_ip


# =========================================================
# LOG-BASED ALERTS (FROM access.log)
# =========================================================
def save_alert(alert_data):
    db = SessionLocal()
    try:
        alert = (
            db.query(Alert)
            .filter(
                Alert.ip_address == alert_data["ip"],
                Alert.attack_type == alert_data["attack"]
            )
            .first()
        )

        if alert:
            # ✅ Aggregate attempts
            alert.attempts += alert_data["attempts"]
            alert.severity = calculate_severity(
                alert.attack_type,
                alert.attempts
            )
            db.commit()
            return

        # 🆕 First time alert
        severity = calculate_severity(
            alert_data["attack"],
            alert_data["attempts"]
        )

        alert = Alert(
            ip_address=alert_data["ip"],
            attack_type=alert_data["attack"],
            attempts=alert_data["attempts"],
            severity=severity,
            detected_at=alert_data["detected_at"]
        )

        db.add(alert)
        db.commit()

        if severity == "HIGH":
            block_ip(
                alert_data["ip"],
                f"{alert_data['attack']} attack"
            )

    finally:
        db.close()



# =========================================================
# LIVE IDS ALERTS (REAL-TIME, AGGREGATED)
# =========================================================
def save_live_alert(ip, attack):
    db = SessionLocal()
    try:
        alert = (
            db.query(Alert)
            .filter(
                Alert.ip_address == ip,
                Alert.attack_type == attack
            )
            .first()
        )

        if alert:
            alert.attempts += 1
            db.commit()
            return

        alert = Alert(
            ip_address=ip,
            attack_type=attack,
            attempts=1,
            severity="HIGH",
            detected_at=datetime.utcnow()
        )

        db.add(alert)
        db.commit()

    finally:
        db.close()
