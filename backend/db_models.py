"""
SQLAlchemy ORM modelleri
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    username      = Column(String(50), unique=True, nullable=False, index=True)
    full_name     = Column(String(100), nullable=True)
    hashed_password = Column(String(200), nullable=False)
    role          = Column(String(20), default="readonly")   # "admin" | "readonly"
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime, default=datetime.utcnow)


class ScanSession(Base):
    """Her tarama çalışması bir session oluşturur."""
    __tablename__ = "scan_sessions"

    id             = Column(Integer, primary_key=True, index=True)
    started_at     = Column(DateTime, default=datetime.utcnow)
    finished_at    = Column(DateTime, nullable=True)
    triggered_by   = Column(String(100), default="manual")   # username | "scheduler"
    status         = Column(String(20), default="running")   # running | completed | failed
    total_devices  = Column(Integer, default=0)
    total_rules    = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)

    results = relationship("ScanResult", back_populates="session", cascade="all, delete-orphan")


class ScanResult(Base):
    """Bir session içinde tek bir cihazın (ADOM/VSYS) tarama sonucu."""
    __tablename__ = "scan_results"

    id           = Column(Integer, primary_key=True, index=True)
    session_id   = Column(Integer, ForeignKey("scan_sessions.id"), nullable=False)
    device_id    = Column(String(100))
    device_name  = Column(String(200))
    device_label = Column(String(200), default="")   # "FortiManager-Istanbul" gibi
    device_host  = Column(String(100), default="")   # "172.30.33.31" gibi
    platform     = Column(String(50))
    customer     = Column(String(200))
    total_rules  = Column(Integer, default=0)
    scanned_at   = Column(DateTime, default=datetime.utcnow)

    session  = relationship("ScanSession", back_populates="results")
    findings = relationship("FindingRecord", back_populates="scan_result", cascade="all, delete-orphan")


class FindingRecord(Base):
    """Tek bir zafiyet bulgusu."""
    __tablename__ = "findings"

    id             = Column(Integer, primary_key=True, index=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False)
    fingerprint    = Column(String(64), index=True)   # SHA-256 — platform|device|rule_id|check_name
    platform       = Column(String(50))
    device_name    = Column(String(200))
    customer       = Column(String(200))
    rule_id        = Column(String(100))
    rule_name      = Column(String(200))
    severity       = Column(String(20))               # critical | high | medium | low
    check_name     = Column(String(200))
    description    = Column(Text)
    recommendation = Column(Text)
    rule_details   = Column(JSON)
    detected_at    = Column(DateTime, default=datetime.utcnow)

    scan_result = relationship("ScanResult", back_populates="findings")


class FindingStatus(Base):
    """
    Fingerprint bazlı bulgu durum takibi.
    Taramalar arası kalıcıdır — aynı bulgu tekrar çıksa da durumu korunur.
    """
    __tablename__ = "finding_statuses"

    id          = Column(Integer, primary_key=True, index=True)
    fingerprint = Column(String(64), unique=True, index=True, nullable=False)
    status      = Column(String(30), default="open")
    # open | acknowledged | in_progress | resolved
    comment     = Column(Text, nullable=True)
    assigned_to = Column(String(100), nullable=True)
    updated_at  = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by  = Column(String(100), nullable=True)
