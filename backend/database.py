"""
Veritabanı bağlantısı — SQLite (geliştirme) / PostgreSQL (production)
DATABASE_URL env değişkeni ile override edilebilir.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./firewall_audit.db")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency — her request için yeni oturum açar, sonunda kapatır."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Tabloları oluşturur (yoksa) ve eksik sütunları ekler. Uygulama başlangıcında çağrılır."""
    from . import db_models  # noqa: F401 — modellerin Base'e kayıt olması için
    Base.metadata.create_all(bind=engine)
    _migrate()


def _migrate():
    """
    Yeni sütunları mevcut DB'ye güvenle ekler.
    SQLite ALTER TABLE yalnızca ADD COLUMN destekler — bu yeterli.
    """
    if not DATABASE_URL.startswith("sqlite"):
        return  # PostgreSQL için Alembic kullan

    migrations = [
        # (tablo, sütun, tanım)
        ("scan_results",     "device_label",     "VARCHAR(200) DEFAULT ''"),
        ("scan_results",     "device_host",       "VARCHAR(100) DEFAULT ''"),
        # FindingStatus — çözüldü değişiklik takibi
        ("finding_statuses", "rule_snapshot",     "TEXT"),
        ("finding_statuses", "is_rule_changed",   "BOOLEAN DEFAULT 0"),
        ("finding_statuses", "rule_changed_at",   "DATETIME"),
    ]

    with engine.connect() as conn:
        for table, column, definition in migrations:
            # Sütun zaten var mı kontrol et
            result = conn.execute(
                __import__("sqlalchemy").text(f"PRAGMA table_info({table})")
            )
            existing = {row[1] for row in result}
            if column not in existing:
                conn.execute(
                    __import__("sqlalchemy").text(
                        f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                    )
                )
                conn.commit()

        # Performans için ek indeksler (varsa atla)
        sa = __import__("sqlalchemy")
        indices = [
            # Adı,                           DDL
            ("ix_findings_scan_result_id",   "CREATE INDEX IF NOT EXISTS ix_findings_scan_result_id ON findings (scan_result_id)"),
            ("ix_findings_severity",         "CREATE INDEX IF NOT EXISTS ix_findings_severity ON findings (severity)"),
            ("ix_findings_platform",         "CREATE INDEX IF NOT EXISTS ix_findings_platform ON findings (platform)"),
            ("ix_findings_check_name",       "CREATE INDEX IF NOT EXISTS ix_findings_check_name ON findings (check_name)"),
            ("ix_scan_results_session_id",   "CREATE INDEX IF NOT EXISTS ix_scan_results_session_id ON scan_results (session_id)"),
            ("ix_scan_results_device_id",    "CREATE INDEX IF NOT EXISTS ix_scan_results_device_id ON scan_results (device_id)"),
            ("ix_findingstatus_status",      "CREATE INDEX IF NOT EXISTS ix_findingstatus_status ON finding_statuses (status)"),
        ]
        for _name, ddl in indices:
            try:
                conn.execute(sa.text(ddl))
                conn.commit()
            except Exception:
                pass
