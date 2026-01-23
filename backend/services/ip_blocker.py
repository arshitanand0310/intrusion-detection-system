# backend/services/ip_blocker.py

from backend.database import SessionLocal
from backend.models import BlockedIP


def block_ip(ip: str, reason: str):
    db = SessionLocal()

    # Check if already blocked
    existing = db.query(BlockedIP).filter(
        BlockedIP.ip_address == ip
    ).first()

    if existing:
        db.close()
        return False  # already blocked

    blocked = BlockedIP(
        ip_address=ip,
        reason=reason
    )

    db.add(blocked)
    db.commit()
    db.close()

    print(f"🚫 BLOCKED IP: {ip} | Reason: {reason}")
    return True
