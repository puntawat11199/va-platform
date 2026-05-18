"""
SQLAlchemy 2.0 ORM models — mirrors db/init.sql exactly.
All tables use UUID PKs, server-side defaults where possible.
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Python enums — kept in sync with PostgreSQL enum types in init.sql
# ---------------------------------------------------------------------------

class ScanStatus(str, enum.Enum):
    PENDING   = "PENDING"
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ScannerTool(str, enum.Enum):
    ZAP     = "ZAP"
    NUCLEI  = "NUCLEI"
    TESTSSL = "TESTSSL"
    NMAP    = "NMAP"


# ---------------------------------------------------------------------------
# Model: Asset
# ---------------------------------------------------------------------------

class Asset(Base):
    __tablename__ = "assets"

    id:         Mapped[uuid.UUID]  = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain:     Mapped[str]        = mapped_column(Text, nullable=False)
    url:        Mapped[str]        = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime]   = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime]   = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    scans: Mapped[list["Scan"]] = relationship("Scan", back_populates="asset")

    __table_args__ = (
        Index("idx_assets_domain",     "domain"),
        Index("idx_assets_created_at", "created_at"),
    )


# ---------------------------------------------------------------------------
# Model: Scan
# ---------------------------------------------------------------------------

class Scan(Base):
    __tablename__ = "scans"

    id:          Mapped[uuid.UUID]        = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id:    Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    target:      Mapped[str]              = mapped_column(Text, nullable=False)
    status:      Mapped[ScanStatus]       = mapped_column(Enum(ScanStatus, name="scan_status", create_type=False), nullable=False, default=ScanStatus.PENDING)
    active_scan: Mapped[bool]             = mapped_column(Boolean, nullable=False, default=False)
    started_at:  Mapped[datetime | None]  = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None]  = mapped_column(DateTime(timezone=True), nullable=True)
    error:          Mapped[str | None]       = mapped_column(Text, nullable=True)
    celery_task_id: Mapped[str | None]       = mapped_column(Text, nullable=True)
    created_at:     Mapped[datetime]         = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    asset:           Mapped["Asset | None"]          = relationship("Asset", back_populates="scans")
    vulnerabilities: Mapped[list["Vulnerability"]]   = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_asset_id",   "asset_id"),
        Index("idx_scans_status",     "status"),
        Index("idx_scans_created_at", "created_at"),
    )


# ---------------------------------------------------------------------------
# Model: Vulnerability
# ---------------------------------------------------------------------------

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id:          Mapped[uuid.UUID]    = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id:     Mapped[uuid.UUID]    = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    tool:        Mapped[ScannerTool]  = mapped_column(Enum(ScannerTool, name="scanner_tool", create_type=False), nullable=False)
    severity:    Mapped[SeverityLevel]= mapped_column(Enum(SeverityLevel, name="severity_level", create_type=False), nullable=False)
    title:       Mapped[str]          = mapped_column(Text, nullable=False)
    description: Mapped[str | None]   = mapped_column(Text, nullable=True)
    target:      Mapped[str]          = mapped_column(Text, nullable=False)
    path:        Mapped[str | None]   = mapped_column(Text, nullable=True)
    parameter:   Mapped[str | None]   = mapped_column(Text, nullable=True)
    evidence:    Mapped[str | None]   = mapped_column(Text, nullable=True)
    hash:        Mapped[str]          = mapped_column(String(64), nullable=False)
    first_seen:  Mapped[datetime]     = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen:   Mapped[datetime]     = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    raw:         Mapped[dict | None]  = mapped_column(JSONB, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="vulnerabilities")

    __table_args__ = (
        Index("idx_vuln_scan_id",    "scan_id"),
        Index("idx_vuln_severity",   "severity"),
        Index("idx_vuln_tool",       "tool"),
        Index("idx_vuln_hash",       "hash"),
        Index("idx_vuln_first_seen", "first_seen"),
    )
