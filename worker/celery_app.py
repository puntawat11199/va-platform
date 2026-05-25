"""
celery_app.py — Celery application and task definitions for the VA Platform.

Processes async scan jobs from the 'scans' queue.
Redis is used as both the message broker and result backend.
"""

import asyncio
import logging
import os
import sys

# /app      → worker source (this file's directory)
# /app/backend → backend package (crud, db.models, db.database)
# /app/scanner → scanner package (zap_runner, nuclei_runner)
sys.path.insert(0, "/app")
sys.path.insert(0, "/app/backend")

from celery import Celery
from celery.signals import worker_ready, worker_shutdown
from celery.utils.log import get_task_logger

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = get_task_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REDIS_URL: str    = os.getenv("REDIS_URL",    "redis://redis:6379/0")
DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql://va_user:va_dev_password_2024@postgres:5432/va_platform")

# ---------------------------------------------------------------------------
# Celery application
# ---------------------------------------------------------------------------
celery_app = Celery("va_platform", broker=REDIS_URL, backend=REDIS_URL)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    result_expires=86400,
    task_ignore_result=False,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_concurrency=2,
    worker_prefetch_multiplier=1,
    task_default_queue="scans",
    task_queues={"scans": {"exchange": "scans", "routing_key": "scans"}},
    broker_connection_retry_on_startup=True,
    broker_connection_max_retries=10,

    # ---------------------------------------------------------------------------
    # Beat schedule — recurring scans for all registered assets.
    # Dispatches a scan_all_assets task every 24 hours by default.
    # Adjust the schedule here; assets are read from the DB at task runtime.
    # ---------------------------------------------------------------------------
    beat_schedule={
        "scheduled-scan-all-assets": {
            "task":     "worker.celery_app.scan_all_assets",
            "schedule": 86400,   # every 24 hours (seconds)
            "options":  {"queue": "scans"},
        },
    },
)


# ---------------------------------------------------------------------------
# Worker lifecycle signals
# ---------------------------------------------------------------------------

@worker_ready.connect
def on_worker_ready(**kwargs: object) -> None:
    logger.info("VA Platform Celery worker ready — broker: %s", REDIS_URL)


@worker_shutdown.connect
def on_worker_shutdown(**kwargs: object) -> None:
    logger.info("VA Platform Celery worker shutting down")


# ---------------------------------------------------------------------------
# Async DB helpers (called via asyncio.run() from the sync Celery task)
#
# Each helper creates its own NullPool engine so asyncpg connections are
# never reused across event loops. asyncio.run() creates a new loop every
# call — a shared pool would bind connections to the first loop and crash
# on every subsequent call with "Future attached to a different loop".
# ---------------------------------------------------------------------------

import os as _os
import re as _re
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool


def _make_engine():
    url = _os.getenv(
        "DATABASE_URL",
        "postgresql://va_user:va_dev_password_2024@postgres:5432/va_platform",
    )
    url = _re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    url = _re.sub(r"^postgres://",   "postgresql+asyncpg://", url)
    return create_async_engine(url, poolclass=NullPool)


async def _run_db(coro_fn):
    """Create a fresh engine + session, run coro_fn(session), then dispose."""
    engine = _make_engine()
    try:
        session_factory = async_sessionmaker(
            bind=engine, class_=AsyncSession, expire_on_commit=False
        )
        async with session_factory() as db:
            return await coro_fn(db)
    finally:
        await engine.dispose()


async def _db_get_scan_status(scan_id: str):
    import crud
    return await _run_db(lambda db: crud.get_scan_status(db, scan_id))


async def _db_store_task_id(scan_id: str, celery_task_id: str) -> None:
    import crud
    await _run_db(lambda db: crud.set_scan_task_id(db, scan_id, celery_task_id))


async def _db_mark_running(scan_id: str) -> None:
    from db.models import ScanStatus
    import crud
    await _run_db(lambda db: crud.update_scan_status(db, scan_id, ScanStatus.RUNNING))


async def _db_mark_completed(scan_id: str) -> None:
    from db.models import ScanStatus
    import crud
    await _run_db(lambda db: crud.update_scan_status(db, scan_id, ScanStatus.COMPLETED))


async def _db_mark_failed(scan_id: str, error: str) -> None:
    from db.models import ScanStatus
    import crud
    await _run_db(lambda db: crud.update_scan_status(db, scan_id, ScanStatus.FAILED, error=error))


async def _db_save_findings(scan_id: str, zap_findings: list[dict], nuclei_findings: list[dict], testssl_findings: list[dict], nmap_findings: list[dict]) -> int:
    import crud
    return await _run_db(lambda db: crud.save_findings(db, scan_id, zap_findings, nuclei_findings, testssl_findings, nmap_findings))


# ---------------------------------------------------------------------------
# Core scan task
# ---------------------------------------------------------------------------

@celery_app.task(
    bind=True,
    name="worker.celery_app.run_scan",
    max_retries=3,
    default_retry_delay=30,
    throws=(ValueError,),
)
def run_scan(self, scan_id: str, target_url: str, active_scan: bool = False) -> dict:
    """
    Orchestrate a full vulnerability scan against target_url.

    Steps:
      1. Mark scan RUNNING in PostgreSQL
      2. Run ZAP — spider + passive + (opt-in) active scan
      3. Run Nuclei — CVE / misconfiguration scan
      4. Persist normalised findings to PostgreSQL
      5. Mark scan COMPLETED / FAILED
    """
    logger.info(
        "run_scan started | scan_id=%s target=%s active=%s attempt=%d",
        scan_id, target_url, active_scan, self.request.retries + 1,
    )

    # Guard: abort if the scan record is gone or already in a terminal state.
    # Prevents orphaned retries from attacking the target after a scan is
    # superseded, manually deleted, or already finished.
    from db.models import ScanStatus
    scan = asyncio.run(_db_get_scan_status(scan_id))
    if scan is None:
        logger.warning("run_scan aborted | scan_id=%s not found in DB — orphaned task discarded", scan_id)
        return {"scan_id": scan_id, "status": "ABORTED", "findings_count": 0}
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        logger.warning("run_scan aborted | scan_id=%s already %s — retry discarded", scan_id, scan.status)
        return {"scan_id": scan_id, "status": scan.status.value, "findings_count": 0}

    nmap_findings: list[dict] = []
    nuclei_findings: list[dict] = []
    testssl_findings: list[dict] = []
    zap_findings: list[dict] = []

    try:
        asyncio.run(_db_store_task_id(scan_id, self.request.id))
        asyncio.run(_db_mark_running(scan_id))

        # Scan order: fastest → slowest
        # 1. nmap   (~5–30s)   — port/service discovery
        # 2. Nuclei (~20–60s)  — CVE / misconfiguration templates
        # 3. testssl (~30–120s) — TLS/SSL analysis (HTTPS only)
        # 4. ZAP    (2–20 min) — full web spider + vulnerability scan

        # --- 1. nmap — non-fatal ---
        from scanner.nmap_runner import run_nmap_scan
        try:
            nmap_findings = run_nmap_scan(scan_id=scan_id, target_url=target_url)
            logger.info("run_scan | scan_id=%s nmap_findings=%d", scan_id, len(nmap_findings))
        except Exception as nmap_exc:
            logger.warning("run_scan | scan_id=%s nmap failed (non-fatal): %s", scan_id, nmap_exc)

        # --- 2. Nuclei ---
        from scanner.nuclei_runner import run_nuclei_scan
        nuclei_findings = run_nuclei_scan(scan_id=scan_id, target_url=target_url)
        logger.info("run_scan | scan_id=%s nuclei_findings=%d", scan_id, len(nuclei_findings))

        # --- 3. testssl.sh (HTTPS targets only) — non-fatal ---
        from scanner.testssl_runner import run_testssl_scan
        try:
            testssl_findings = run_testssl_scan(scan_id=scan_id, target_url=target_url)
            logger.info("run_scan | scan_id=%s testssl_findings=%d", scan_id, len(testssl_findings))
        except Exception as testssl_exc:
            logger.warning("run_scan | scan_id=%s testssl failed (non-fatal): %s", scan_id, testssl_exc)
            testssl_findings = []

        # --- 4. ZAP (slowest) ---
        from scanner.zap_runner import run_zap_scan
        zap_findings = run_zap_scan(
            scan_id=scan_id,
            target_url=target_url,
            active_scan=active_scan,
        )
        logger.info("run_scan | scan_id=%s zap_findings=%d", scan_id, len(zap_findings))

        # --- Persist ---
        saved = asyncio.run(_db_save_findings(scan_id, zap_findings, nuclei_findings, testssl_findings, nmap_findings))
        logger.info("run_scan | scan_id=%s saved=%d findings to DB", scan_id, saved)

        asyncio.run(_db_mark_completed(scan_id))
        logger.info("run_scan completed | scan_id=%s total=%d", scan_id, saved)

        return {"scan_id": scan_id, "status": "COMPLETED", "findings_count": saved}

    except Exception as exc:
        logger.exception("run_scan failed | scan_id=%s error=%s", scan_id, exc)

        try:
            raise self.retry(exc=exc, countdown=2 ** self.request.retries * 10)
        except self.MaxRetriesExceededError:
            asyncio.run(_db_mark_failed(scan_id, str(exc)))
            return {"scan_id": scan_id, "status": "FAILED", "findings_count": 0, "error": str(exc)}


# ---------------------------------------------------------------------------
# Scheduled task — triggered by Celery Beat every 24 hours
# ---------------------------------------------------------------------------

async def _db_list_assets() -> list[dict]:
    from db.database import async_session_factory
    import crud
    async with async_session_factory() as db:
        assets = await crud.list_assets(db, limit=1000)
        return [{"id": str(a.id), "url": a.url} for a in assets]


async def _db_create_scheduled_scan(url: str) -> str:
    """Create a PENDING scan row for a scheduled run; returns the scan_id."""
    import uuid as _uuid
    from db.database import async_session_factory
    import crud
    scan_id = str(_uuid.uuid4())
    async with async_session_factory() as db:
        asset = await crud.get_or_create_asset(db, url)
        await crud.create_scan(db, scan_id=scan_id, target_url=url, asset_id=str(asset.id))
    return scan_id


@celery_app.task(name="worker.celery_app.scan_all_assets")
def scan_all_assets() -> dict:
    """
    Periodic task dispatched by Celery Beat.
    Reads all registered assets from the DB and enqueues a run_scan task for each.
    Active scan is disabled for scheduled runs to avoid unintended attack traffic.
    """
    assets = asyncio.run(_db_list_assets())
    logger.info("scan_all_assets: found %d assets to scan", len(assets))

    dispatched = 0
    for asset in assets:
        scan_id = asyncio.run(_db_create_scheduled_scan(asset["url"]))
        celery_app.send_task(
            "worker.celery_app.run_scan",
            args=[scan_id, asset["url"], False],
            queue="scans",
        )
        logger.info("scan_all_assets: dispatched scan_id=%s for %s", scan_id, asset["url"])
        dispatched += 1

    return {"dispatched": dispatched}
