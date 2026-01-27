from datetime import datetime
from backend.database import SessionLocal
from backend.models import Alert
from backend.detector.severity import calculate_severity
from backend.services.ip_blocker import block_ip


def save_alert(alert_data):
    """
    Aggregates log-based alerts per (IP + attack).
    Prevents duplicate rows and updates attempts correctly.
    """
    db = SessionLocal()
    try:
        ip = alert_data["ip"]
        attack = alert_data["attack"]
        attempts = alert_data["attempts"]

        print(f"[SAVE_ALERT] IP: {ip} | Attack: {attack} | Attempts: {attempts}")

        alert = (
            db.query(Alert)
            .filter(
                Alert.ip_address == ip,
                Alert.attack_type == attack
            )
            .first()
        )

        if alert:
            alert.attempts = max(alert.attempts, attempts)
            alert.severity = calculate_severity(attack, alert.attempts)
            alert.detected_at = datetime.utcnow()
            print(f"[SAVE_ALERT] Updated existing alert | Severity: {alert.severity}")
        else:
            alert = Alert(
                ip_address=ip,
                attack_type=attack,
                attempts=attempts,
                severity=calculate_severity(attack, attempts),
                detected_at=alert_data["detected_at"]
            )
            db.add(alert)
            print(f"[SAVE_ALERT] Created new alert | Severity: {alert.severity}")

        db.commit()
        print(f"[SAVE_ALERT] SUCCESS - Committed to database")

        if alert.severity == "HIGH":
            print(f"[SAVE_ALERT] BLOCKING IP {ip} - HIGH severity")
            block_ip(ip, f"{attack} attack")

    except Exception as e:
        print(f"[SAVE_ALERT] ERROR: {str(e)}")
        db.rollback()
    finally:
        db.close()


def save_live_alert(ip, attack):
    """
    Aggregates live IDS alerts per (IP + attack).
    """
    db = SessionLocal()
    try:
        print(f"[SAVE_LIVE_ALERT] IP: {ip} | Attack: {attack}")
        
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
            alert.severity = calculate_severity(attack, alert.attempts)
            alert.detected_at = datetime.utcnow()
            print(f"[SAVE_LIVE_ALERT] Updated | Attempts: {alert.attempts} | Severity: {alert.severity}")
        else:
            severity = calculate_severity(attack, 1)
            alert = Alert(
                ip_address=ip,
                attack_type=attack,
                attempts=1,
                severity=severity,
                detected_at=datetime.utcnow()
            )
            db.add(alert)
            print(f"[SAVE_LIVE_ALERT] Created | Attempts: 1 | Severity: {severity}")

        db.commit()
        print(f"[SAVE_LIVE_ALERT] SUCCESS - Committed to database")

        if alert.severity == "HIGH":
            print(f"[SAVE_LIVE_ALERT] BLOCKING IP {ip} - HIGH severity")
            block_ip(ip, f"{attack} (Live Detection)")

    except Exception as e:
        print(f"[SAVE_LIVE_ALERT] ERROR: {str(e)}")
        db.rollback()
    finally:
        db.close()