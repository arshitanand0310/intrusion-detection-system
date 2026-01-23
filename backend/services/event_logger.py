from datetime import datetime
from backend.database import SessionLocal
from backend.models import SecurityEvent


def log_event(ip, attack, action, source):
    """
    Logs security events for forensics / audit trail.
    """
    db = SessionLocal()
    try:
        event = SecurityEvent(
            ip_address=ip,
            attack_type=attack,
            action=action,
            source=source,
            timestamp=datetime.utcnow()
        )
        db.add(event)
        db.commit()
    finally:
        db.close()
