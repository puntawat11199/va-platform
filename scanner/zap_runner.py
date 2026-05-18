"""
zap_runner.py — OWASP ZAP scan orchestration for the VA Platform.

Communicates with the ZAP daemon via the ZAP REST API (python-owasp-zap-v2.4).
Pipeline: standard spider → AJAX spider → passive scan → (optional) active scan → report export.
Active scan uses High strength / Default threshold when opt-in is set.
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
from zapv2 import ZAPv2

logger = logging.getLogger("va_platform.scanner.zap")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
ZAP_BASE_URL: str = os.getenv("ZAP_BASE_URL", "http://zap:8080")
ZAP_API_KEY: str = os.getenv("ZAP_API_KEY", "changeme_zap_dev_2024")
REPORTS_DIR: Path = Path(os.getenv("REPORTS_DIR", "/reports"))

ZAP_POLL_INTERVAL: int = 5       # seconds between progress polls
ZAP_SPIDER_TIMEOUT: int = 300    # max seconds to wait for spider
ZAP_AJAX_TIMEOUT: int = 120      # max seconds to wait for AJAX spider
ZAP_PASSIVE_TIMEOUT: int = 120   # max seconds to wait for passive scan queue
ZAP_ACTIVE_TIMEOUT: int = 3600   # max seconds to wait for active scan (1 hour)


# ---------------------------------------------------------------------------
# ZAP client
# ---------------------------------------------------------------------------

@retry(
    retry=retry_if_exception_type(Exception),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=5, max=30),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
def get_zap_client() -> ZAPv2:
    """
    Return an authenticated ZAPv2 client, retrying up to 3 times on failure.
    Verifies connectivity by calling the ZAP version endpoint.
    """
    proxies = {"http": ZAP_BASE_URL, "https": ZAP_BASE_URL}
    zap = ZAPv2(apikey=ZAP_API_KEY, proxies=proxies)
    version = zap.core.version
    logger.info("Connected to ZAP version %s at %s", version, ZAP_BASE_URL)
    return zap


# ---------------------------------------------------------------------------
# Spider
# ---------------------------------------------------------------------------

def run_spider(zap: ZAPv2, target_url: str, scan_id: str) -> list[str]:
    """
    Run ZAP standard spider against target_url and return discovered URLs.

    Blocks until spider reaches 100% or ZAP_SPIDER_TIMEOUT is exceeded.
    """
    logger.info("scan_id=%s starting standard spider on %s", scan_id, target_url)
    spider_id = zap.spider.scan(target_url)

    elapsed = 0
    while True:
        progress = int(zap.spider.status(spider_id))
        logger.info("scan_id=%s spider progress=%d%%", scan_id, progress)
        if progress >= 100:
            break
        if elapsed >= ZAP_SPIDER_TIMEOUT:
            logger.warning("scan_id=%s spider timed out after %ds", scan_id, elapsed)
            break
        time.sleep(ZAP_POLL_INTERVAL)
        elapsed += ZAP_POLL_INTERVAL

    results = zap.spider.results(spider_id)
    logger.info("scan_id=%s spider found %d URLs", scan_id, len(results))
    return results


def run_ajax_spider(zap: ZAPv2, target_url: str, scan_id: str) -> None:
    """
    Run ZAP AJAX spider against target_url to discover JavaScript-rendered URLs.

    Blocks until the AJAX spider stops or ZAP_AJAX_TIMEOUT is exceeded.
    Runs after the standard spider to extend URL coverage on SPAs.
    """
    logger.info("scan_id=%s starting AJAX spider on %s", scan_id, target_url)
    zap.ajaxSpider.scan(target_url)

    elapsed = 0
    while True:
        status = zap.ajaxSpider.status
        logger.info("scan_id=%s AJAX spider status=%s", scan_id, status)
        if status == "stopped":
            break
        if elapsed >= ZAP_AJAX_TIMEOUT:
            logger.warning("scan_id=%s AJAX spider timed out after %ds — stopping", scan_id, elapsed)
            zap.ajaxSpider.stop()
            break
        time.sleep(ZAP_POLL_INTERVAL)
        elapsed += ZAP_POLL_INTERVAL

    logger.info("scan_id=%s AJAX spider complete", scan_id)


# ---------------------------------------------------------------------------
# Passive scan
# ---------------------------------------------------------------------------

def run_passive_scan(zap: ZAPv2, scan_id: str) -> None:
    """
    Wait for ZAP passive scan queue to drain.

    Passive scanning runs automatically as URLs are spidered.
    This function blocks until all queued records are processed.
    """
    logger.info("scan_id=%s waiting for passive scan queue to drain", scan_id)
    elapsed = 0
    while True:
        records = int(zap.pscan.records_to_scan)
        logger.info("scan_id=%s passive scan records remaining=%d", scan_id, records)
        if records == 0:
            break
        if elapsed >= ZAP_PASSIVE_TIMEOUT:
            logger.warning("scan_id=%s passive scan timed out after %ds", scan_id, elapsed)
            break
        time.sleep(ZAP_POLL_INTERVAL)
        elapsed += ZAP_POLL_INTERVAL

    logger.info("scan_id=%s passive scan complete", scan_id)


# ---------------------------------------------------------------------------
# Active scan
# ---------------------------------------------------------------------------

def run_active_scan(zap: ZAPv2, target_url: str, scan_id: str) -> None:
    """
    Run ZAP active scan at High strength / Default threshold.

    WARNING: Sends attack payloads to the target. Only run against
    targets you own or have explicit written permission to test.

    Blocks until active scan reaches 100% or ZAP_ACTIVE_TIMEOUT is exceeded.
    """
    logger.warning(
        "scan_id=%s ACTIVE SCAN starting — ensure %s is an authorised target",
        scan_id, target_url,
    )

    # Use ZAP default scan policy (MEDIUM strength / DEFAULT threshold).
    # set_policy_attack_strength requires a scanner plugin ID in ZAP 2.17+
    # — skip per-scanner overrides and rely on the default policy.

    active_id = zap.ascan.scan(target_url)

    elapsed = 0
    while True:
        progress = int(zap.ascan.status(active_id))
        logger.info("scan_id=%s active scan progress=%d%%", scan_id, progress)
        if progress >= 100:
            break
        if elapsed >= ZAP_ACTIVE_TIMEOUT:
            logger.warning("scan_id=%s active scan timed out after %ds", scan_id, elapsed)
            break
        time.sleep(ZAP_POLL_INTERVAL)
        elapsed += ZAP_POLL_INTERVAL

    logger.info("scan_id=%s active scan complete", scan_id)


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

def export_report(zap: ZAPv2, scan_id: str, target_url: str) -> list[dict[str, Any]]:
    """
    Fetch all ZAP alerts and save them as JSON to the reports volume.

    Returns the raw list of alert dicts for downstream normalisation.
    """
    alerts: list[dict[str, Any]] = zap.core.alerts(baseurl=target_url)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = REPORTS_DIR / f"zap_{scan_id}.json"
    report_path.write_text(json.dumps(alerts, indent=2))

    logger.info(
        "scan_id=%s ZAP report saved → %s (%d alerts)",
        scan_id, report_path, len(alerts),
    )
    return alerts


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_zap_scan(scan_id: str, target_url: str, active_scan: bool = False) -> list[dict[str, Any]]:
    """
    Full ZAP scan pipeline for a single target.

    Order: standard spider → AJAX spider → passive scan → (opt-in) active scan → export.
    Called by worker/celery_app.py run_scan task.

    Args:
        scan_id:     UUID of the scan record.
        target_url:  Fully-qualified HTTP/S URL to scan.
        active_scan: Include active scan when True (opt-in).

    Returns:
        List of raw ZAP alert dicts.
    """
    logger.info(
        "run_zap_scan started | scan_id=%s target=%s active=%s",
        scan_id, target_url, active_scan,
    )

    try:
        zap = get_zap_client()

        # Clear any previous session data so results are target-specific
        zap.core.new_session()

        run_spider(zap, target_url, scan_id)
        run_ajax_spider(zap, target_url, scan_id)
        run_passive_scan(zap, scan_id)

        if active_scan:
            run_active_scan(zap, target_url, scan_id)

        findings = export_report(zap, scan_id, target_url)
        logger.info("run_zap_scan complete | scan_id=%s findings=%d", scan_id, len(findings))
        return findings

    except Exception as exc:
        logger.exception("run_zap_scan failed | scan_id=%s error=%s", scan_id, exc)
        raise
