# backend/models.py

from sqlalchemy import Column, Integer, String, DateTime, Index
from datetime import datetime
from backend.database import Base


# =========================================================
# ALERTS TABLE (SOC Alerts: log-based + live IDS)
# =========================================================
class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True, nullable=False)
    attack_type = Column(String, nullable=False)
    attempts = Column(Integer, nullable=False, default=1)
    severity = Column(String, nullable=False)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("idx_alert_ip_time", "ip_address", "detected_at"),
    )


# =========================================================
# BLOCKED IPS TABLE (Enforcement / WAF-style)
# =========================================================
class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    reason = Column(String, nullable=False)
    blocked_at = Column(DateTime, default=datetime.utcnow, index=True)


# =========================================================
# OPTIONAL: SECURITY EVENTS TABLE (FORENSICS / AUDIT)
# =========================================================
class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True, nullable=False)
    attack_type = Column(String, nullable=False)
    action = Column(String, nullable=False)          # BLOCKED / ALERTED
    source = Column(String, nullable=False)          # LIVE_IDS / LOG_IDS
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)

    __table_args__ = (
        Index("idx_event_ip_time", "ip_address", "timestamp"),
    )
