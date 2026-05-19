"""
CRUD helpers — all database writes and reads go through these functions.
Each function accepts an AsyncSession and is called from FastAPI routes
(via Depends) or from the Celery worker (via async_session_factory()).
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload

from db.models import Asset, Scan, ScannerTool, ScanStatus, SeverityLevel, Vulnerability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _vuln_hash(target: str, title: str, parameter: str | None, evidence: str | None) -> str:
    """SHA-256 deduplication key — matches the comment in init.sql."""
    raw = f"{target}|{title}|{parameter or ''}|{evidence or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------

async def create_scan(
    db: AsyncSession,
    scan_id: str,
    target_url: str,
    active_scan: bool = False,
    asset_id: str | None = None,
) -> Scan:
    """
    Insert a new scan row in PENDING status.
    scan_id comes from the API layer (already a UUID string).
    """
    scan = Scan(
        id=uuid.UUID(scan_id),
        asset_id=uuid.UUID(asset_id) if asset_id else None,
        target=target_url,
        status=ScanStatus.PENDING,
        active_scan=active_scan,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def update_scan_status(
    db: AsyncSession,
    scan_id: str,
    status: ScanStatus,
    error: str | None = None,
) -> Scan | None:
    """
    Transition a scan to a new status.
    Sets started_at on RUNNING, finished_at on COMPLETED/FAILED.
    """
    result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = result.scalar_one_or_none()
    if scan is None:
        return None

    scan.status = status

    if status == ScanStatus.RUNNING:
        scan.started_at = _utcnow()
    elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        scan.finished_at = _utcnow()

    if error is not None:
        scan.error = error

    await db.commit()
    await db.refresh(scan)
    return scan


async def get_scan(db: AsyncSession, scan_id: str) -> Scan | None:
    """Fetch a single scan by UUID, eagerly loading its vulnerabilities."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .where(Scan.id == uuid.UUID(scan_id))
    )
    return result.scalar_one_or_none()


async def get_scan_status(db: AsyncSession, scan_id: str) -> Scan | None:
    """Lightweight fetch — no relationship loading. Used by the worker guard check."""
    result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    return result.scalar_one_or_none()


async def set_scan_task_id(db: AsyncSession, scan_id: str, celery_task_id: str) -> None:
    """Store the Celery task ID on the scan row so it can be revoked later."""
    result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = result.scalar_one_or_none()
    if scan:
        scan.celery_task_id = celery_task_id
        await db.commit()


async def get_active_scan_for_target(db: AsyncSession, target_url: str) -> Scan | None:
    """Return the most recent PENDING or RUNNING scan for a target, if any."""
    result = await db.execute(
        select(Scan)
        .where(
            Scan.target == target_url,
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def delete_scan(db: AsyncSession, scan_id: str) -> bool:
    """Delete a scan and its findings (CASCADE). Returns False if not found."""
    result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
    scan = result.scalar_one_or_none()
    if scan is None:
        return False
    await db.delete(scan)
    await db.commit()
    return True


async def list_scans(
    db: AsyncSession,
    limit: int = 50,
    offset: int = 0,
) -> list[Scan]:
    """Return scans ordered newest-first with vulnerability counts loaded."""
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.vulnerabilities))
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Findings normalisation + persistence
# ---------------------------------------------------------------------------

def _clean(value: str | None) -> str | None:
    """Strip null bytes that PostgreSQL rejects in text/varchar columns."""
    if value is None:
        return None
    return value.replace("\x00", "")


def _clean_raw(obj: Any) -> Any:
    """Recursively strip null bytes from a raw finding dict before storing as JSONB."""
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    if isinstance(obj, dict):
        return {k: _clean_raw(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_raw(i) for i in obj]
    return obj


def _normalise_zap(finding: dict[str, Any], scan_id: str) -> Vulnerability:
    """Map a raw ZAP alert dict to a Vulnerability row."""
    target    = _clean(finding.get("url") or finding.get("cweid") or "")
    title     = _clean(finding.get("name") or finding.get("alert") or "Unknown")
    parameter = _clean(finding.get("param") or None)
    evidence  = _clean((finding.get("evidence") or "")[:500] or None)

    raw_severity = (finding.get("riskdesc") or finding.get("risk") or "").upper()
    severity = _map_severity_zap(raw_severity)

    return Vulnerability(
        scan_id=uuid.UUID(scan_id),
        tool=ScannerTool.ZAP,
        severity=severity,
        title=title,
        description=_clean(finding.get("desc") or finding.get("description") or None),
        target=target,
        path=_clean(finding.get("uri") or None),
        parameter=parameter,
        evidence=evidence,
        hash=_vuln_hash(target, title, parameter, evidence),
        raw=_clean_raw(finding),
    )


def _normalise_nuclei(finding: dict[str, Any], scan_id: str) -> Vulnerability:
    """Map a raw Nuclei finding dict to a Vulnerability row."""
    info      = finding.get("info") or {}
    target    = _clean(finding.get("host") or finding.get("url") or finding.get("matched-at") or "")
    title     = _clean(info.get("name") or finding.get("template-id") or "Unknown")
    evidence  = _clean((finding.get("extracted-results") or [""])[0][:500]) if finding.get("extracted-results") else None
    parameter = None

    raw_severity = (info.get("severity") or "").upper()
    severity = _map_severity_nuclei(raw_severity)

    return Vulnerability(
        scan_id=uuid.UUID(scan_id),
        tool=ScannerTool.NUCLEI,
        severity=severity,
        title=title,
        description=_clean(info.get("description") or None),
        target=target,
        path=_clean(finding.get("matched-at") or None),
        parameter=parameter,
        evidence=evidence,
        hash=_vuln_hash(target, title, parameter, evidence),
        raw=_clean_raw(finding),
    )


def _map_severity_zap(risk: str) -> SeverityLevel:
    mapping = {
        "HIGH":          SeverityLevel.HIGH,
        "HIGH (HIGH)":   SeverityLevel.HIGH,
        "MEDIUM":        SeverityLevel.MEDIUM,
        "MEDIUM (MEDIUM)": SeverityLevel.MEDIUM,
        "LOW":           SeverityLevel.LOW,
        "LOW (LOW)":     SeverityLevel.LOW,
        "INFORMATIONAL": SeverityLevel.INFO,
        "INFO":          SeverityLevel.INFO,
        "CRITICAL":      SeverityLevel.CRITICAL,
    }
    for key, val in mapping.items():
        if key in risk:
            return val
    return SeverityLevel.INFO


def _map_severity_nuclei(severity: str) -> SeverityLevel:
    return {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH":     SeverityLevel.HIGH,
        "MEDIUM":   SeverityLevel.MEDIUM,
        "LOW":      SeverityLevel.LOW,
        "INFO":     SeverityLevel.INFO,
    }.get(severity, SeverityLevel.INFO)


def _normalise_testssl(finding: dict[str, Any], scan_id: str) -> Vulnerability:
    """Map a raw testssl.sh finding dict to a Vulnerability row."""
    target    = _clean(finding.get("ip") or "")
    title     = _clean(finding.get("id") or "Unknown")
    evidence  = _clean((finding.get("finding") or "")[:500] or None)
    parameter = None

    raw_severity = (finding.get("severity") or "").upper()
    severity = _map_severity_testssl(raw_severity)

    return Vulnerability(
        scan_id=uuid.UUID(scan_id),
        tool=ScannerTool.TESTSSL,
        severity=severity,
        title=title,
        description=_clean(finding.get("finding") or None),
        target=target,
        path=None,
        parameter=parameter,
        evidence=evidence,
        hash=_vuln_hash(target, title, parameter, evidence),
        raw=_clean_raw(finding),
    )


def _map_severity_testssl(severity: str) -> SeverityLevel:
    return {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH":     SeverityLevel.HIGH,
        "MEDIUM":   SeverityLevel.MEDIUM,
        "LOW":      SeverityLevel.LOW,
        "WARN":     SeverityLevel.LOW,
        "INFO":     SeverityLevel.INFO,
    }.get(severity, SeverityLevel.INFO)


def _normalise_nmap(finding: dict[str, Any], scan_id: str) -> Vulnerability:
    """Map a raw nmap finding dict to a Vulnerability row."""
    target    = finding.get("target") or finding.get("ip") or ""
    port      = finding.get("port", 0)
    protocol  = finding.get("protocol", "tcp").upper()
    service   = _clean(finding.get("service", "unknown"))
    title     = f"Open {protocol} port {port}/{service}"
    evidence  = _clean((finding.get("finding") or "")[:500] or None)
    parameter = str(port) if port else None

    raw_severity = (finding.get("severity") or "").upper()
    severity = _map_severity_nmap(raw_severity)

    return Vulnerability(
        scan_id=uuid.UUID(scan_id),
        tool=ScannerTool.NMAP,
        severity=severity,
        title=title,
        description=_clean(finding.get("finding") or None),
        target=target,
        path=None,
        parameter=parameter,
        evidence=evidence,
        hash=_vuln_hash(target, title, parameter, evidence),
        raw=_clean_raw(finding),
    )


def _map_severity_nmap(severity: str) -> SeverityLevel:
    return {
        "CRITICAL": SeverityLevel.CRITICAL,
        "HIGH":     SeverityLevel.HIGH,
        "MEDIUM":   SeverityLevel.MEDIUM,
        "LOW":      SeverityLevel.LOW,
        "INFO":     SeverityLevel.INFO,
    }.get(severity, SeverityLevel.LOW)


async def save_findings(
    db: AsyncSession,
    scan_id: str,
    zap_findings: list[dict[str, Any]],
    nuclei_findings: list[dict[str, Any]],
    testssl_findings: list[dict[str, Any]] | None = None,
    nmap_findings: list[dict[str, Any]] | None = None,
) -> int:
    """
    Normalise and upsert all findings for a scan.

    On hash conflict within the same scan, last_seen is updated instead of
    inserting a duplicate row. Returns the number of rows processed.
    """
    rows: list[Vulnerability] = []

    for f in zap_findings:
        try:
            rows.append(_normalise_zap(f, scan_id))
        except Exception:
            pass

    for f in nuclei_findings:
        try:
            rows.append(_normalise_nuclei(f, scan_id))
        except Exception:
            pass

    for f in (testssl_findings or []):
        try:
            rows.append(_normalise_testssl(f, scan_id))
        except Exception:
            pass

    for f in (nmap_findings or []):
        try:
            rows.append(_normalise_nmap(f, scan_id))
        except Exception:
            pass

    if not rows:
        return 0

    # Deduplicate within the batch — PostgreSQL cannot upsert the same hash twice
    seen: set[str] = set()
    unique_rows: list[Vulnerability] = []
    for r in rows:
        if r.hash not in seen:
            seen.add(r.hash)
            unique_rows.append(r)
    rows = unique_rows

    values = [
        {
            "id":          uuid.uuid4(),
            "scan_id":     r.scan_id,
            "tool":        r.tool,
            "severity":    r.severity,
            "title":       r.title,
            "description": r.description,
            "target":      r.target,
            "path":        r.path,
            "parameter":   r.parameter,
            "evidence":    r.evidence,
            "hash":        r.hash,
            "raw":         r.raw,
        }
        for r in rows
    ]

    stmt = (
        pg_insert(Vulnerability)
        .values(values)
        .on_conflict_do_update(
            constraint="uq_vuln_scan_hash",
            set_={"last_seen": _utcnow()},
        )
    )
    await db.execute(stmt)
    await db.commit()

    return len(rows)


# ---------------------------------------------------------------------------
# Vulnerability reads
# ---------------------------------------------------------------------------

async def list_vulnerabilities(
    db: AsyncSession,
    scan_id: str | None = None,
    severity: str | None = None,
    tool: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Vulnerability]:
    """
    Return vulnerabilities with optional filters.
    Results are ordered by severity (critical first) then first_seen desc.
    """
    severity_order = {
        SeverityLevel.CRITICAL: 0,
        SeverityLevel.HIGH:     1,
        SeverityLevel.MEDIUM:   2,
        SeverityLevel.LOW:      3,
        SeverityLevel.INFO:     4,
    }

    q = select(Vulnerability)

    if scan_id is not None:
        q = q.where(Vulnerability.scan_id == uuid.UUID(scan_id))

    if severity is not None:
        q = q.where(Vulnerability.severity == SeverityLevel(severity.upper()))

    if tool is not None:
        q = q.where(Vulnerability.tool == ScannerTool(tool.upper()))

    q = q.order_by(Vulnerability.first_seen.desc()).limit(limit).offset(offset)

    result = await db.execute(q)
    return list(result.scalars().all())


async def get_vulnerability(db: AsyncSession, vuln_id: str) -> Vulnerability | None:
    """Fetch a single vulnerability by UUID."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.id == uuid.UUID(vuln_id))
    )
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# Asset CRUD
# ---------------------------------------------------------------------------

async def create_asset(db: AsyncSession, url: str) -> Asset:
    """Insert a new asset. Raises if the URL already exists."""
    asset = Asset(domain=_extract_domain(url), url=url)
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return asset


async def get_asset_by_url(db: AsyncSession, url: str) -> Asset | None:
    result = await db.execute(select(Asset).where(Asset.url == url))
    return result.scalar_one_or_none()


async def get_asset(db: AsyncSession, asset_id: str) -> Asset | None:
    result = await db.execute(select(Asset).where(Asset.id == uuid.UUID(asset_id)))
    return result.scalar_one_or_none()


async def list_assets(
    db: AsyncSession,
    limit: int = 100,
    offset: int = 0,
) -> list[Asset]:
    result = await db.execute(
        select(Asset).order_by(Asset.created_at.desc()).limit(limit).offset(offset)
    )
    return list(result.scalars().all())


async def get_or_create_asset(db: AsyncSession, url: str) -> Asset:
    """
    Return the existing asset for this URL or create one if it doesn't exist.
    Used by POST /scan to auto-register assets without requiring a separate call.
    """
    asset = await get_asset_by_url(db, url)
    if asset is None:
        asset = await create_asset(db, url)
    return asset
