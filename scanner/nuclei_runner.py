"""
nuclei_runner.py — Nuclei CVE/misconfiguration scan orchestration for the VA Platform.

Executes Nuclei as a subprocess inside the worker container (nuclei binary is
available via the shared Docker network / exec approach).
Writes JSONL output to the shared reports volume, then parses findings.
"""

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("va_platform.scanner.nuclei")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPORTS_DIR: Path = Path(os.getenv("REPORTS_DIR", "/reports"))
NUCLEI_TEMPLATES_PATH: str = os.getenv("NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates")

DEFAULT_TEMPLATE_TAGS: list[str] = ["cves", "misconfigurations", "exposures", "technologies", "sqli", "xss", "lfi", "ssrf", "rce"]
DEFAULT_SEVERITIES: list[str] = ["critical", "high", "medium", "low", "info"]

NUCLEI_TIMEOUT: int = 3600         # max seconds per scan (1 hour hard limit)
NUCLEI_RATE_LIMIT: int = 50        # max requests per second (Cloudflare-safe burst rate)
NUCLEI_BULK_SIZE: int = 25         # templates executed in parallel per host
NUCLEI_CONCURRENCY: int = 10       # hosts scanned in parallel
NUCLEI_RETRIES: int = 2            # retries for transient network/WAF failures
NUCLEI_CONNECT_TIMEOUT: int = 10   # seconds per request (low = detect unresponsive hosts faster)


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------

def build_nuclei_command(
    target_url: str,
    output_file: str,
    tags: list[str] | None = None,
    severities: list[str] | None = None,
) -> list[str]:
    """
    Build the nuclei CLI command list.

    Args:
        target_url:  Target URL to scan.
        output_file: Absolute path for JSONL output.
        tags:        Template tag categories to include.
        severities:  Severity levels to report.

    Returns:
        List of command tokens ready for subprocess.run().
    """
    tags = tags or DEFAULT_TEMPLATE_TAGS
    severities = severities or DEFAULT_SEVERITIES

    cmd = [
        "nuclei",
        "-u", target_url,
        "-t", NUCLEI_TEMPLATES_PATH,        # explicit path required in nuclei v3
        "-severity", ",".join(severities),
        "-json-export", output_file,
        "-no-color",
        "-timeout", str(NUCLEI_CONNECT_TIMEOUT),
        "-retries", str(NUCLEI_RETRIES),    # retry transient WAF/network failures
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-bulk-size", str(NUCLEI_BULK_SIZE),
        "-concurrency", str(NUCLEI_CONCURRENCY),
        "-ni",                              # disable interactsh (prevents OAST templates marking target as unresponsive)
        "-nh",                              # disable redirects that probe external hosts
        "-disable-update-check",            # prevent mid-scan template auto-update (updates run at worker startup)
        "-exclude-id", "hpe-autopass-panel,apachespark-ui-exposed,apache-kyuubi-config",
    ]

    logger.debug("nuclei command: %s", " ".join(cmd))
    return cmd


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------

def parse_nuclei_output(output_file: str, scan_id: str) -> list[dict[str, Any]]:
    """
    Parse Nuclei's JSON export file into a list of finding dicts.

    Nuclei's -json-export writes one JSON object per line (JSONL).
    Lines that fail JSON parsing are logged and skipped rather than
    crashing the scan — raw output is preserved on disk for manual review.

    Args:
        output_file: Path to the nuclei output file.
        scan_id:     Used for log correlation.

    Returns:
        List of raw Nuclei finding dicts.
    """
    findings: list[dict[str, Any]] = []
    path = Path(output_file)

    if not path.exists():
        logger.warning("scan_id=%s nuclei output file not found: %s", scan_id, output_file)
        return findings

    content = path.read_text(encoding="utf-8").strip()
    if not content or content == "[]":
        logger.info("scan_id=%s nuclei found 0 results", scan_id)
        return findings

    # nuclei v3 -json-export writes a JSON array [...]; older versions write JSONL
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            findings = parsed
        else:
            findings = [parsed]
    except json.JSONDecodeError:
        # Fallback: try JSONL (one object per line)
        for i, line in enumerate(content.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning(
                    "scan_id=%s skipping malformed line %d: %s — %s",
                    scan_id, i, line[:120], exc,
                )

    logger.info("scan_id=%s parsed %d nuclei findings from %s", scan_id, len(findings), output_file)
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_nuclei_scan(
    scan_id: str,
    target_url: str,
    tags: list[str] | None = None,
    severities: list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Full Nuclei scan pipeline for a single target.

    Runs nuclei CLI as a subprocess, writes JSONL output to the shared
    reports volume, then parses and returns findings.
    Called by worker/celery_app.py run_scan task.

    Args:
        scan_id:    UUID of the scan record.
        target_url: Fully-qualified HTTP/S URL to scan.
        tags:       Override default template tag categories.
        severities: Override default severity filter.

    Returns:
        List of raw Nuclei finding dicts.
    """
    logger.info("run_nuclei_scan started | scan_id=%s target=%s", scan_id, target_url)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output_file = str(REPORTS_DIR / f"nuclei_{scan_id}.jsonl")

    cmd = build_nuclei_command(target_url, output_file, tags, severities)

    start_time = time.time()
    unresponsive_count = 0
    templates_loaded = 0

    try:
        # Stream nuclei stderr (progress/info lines) to worker logs in real time
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Read stderr line by line so progress is visible in docker logs
        stderr_lines: list[str] = []
        for line in process.stderr:
            line = line.rstrip()
            if not line:
                continue
            stderr_lines.append(line)
            logger.info("scan_id=%s nuclei: %s", scan_id, line)

            # Structured detection — permanently unresponsive host (WAF/Cloudflare block)
            if "found unresponsive permanently" in line:
                unresponsive_count += 1
                logger.warning(
                    "scan_id=%s nuclei marked host permanently unresponsive "
                    "(WAF/Cloudflare likely blocking scan traffic) — elapsed=%.0fs",
                    scan_id, time.time() - start_time,
                )

            # Track template count for diagnostics
            if "Templates loaded for current scan:" in line:
                try:
                    templates_loaded = int(line.split("Templates loaded for current scan:")[-1].strip())
                except ValueError:
                    pass

        process.wait(timeout=NUCLEI_TIMEOUT)
        result_returncode = process.returncode
        elapsed = time.time() - start_time

        if result_returncode not in (0, 1):
            logger.error(
                "scan_id=%s nuclei exited %d elapsed=%.0fs", scan_id, result_returncode, elapsed,
            )
            raise RuntimeError(
                f"nuclei exited with unexpected code {result_returncode}"
            )

        if unresponsive_count:
            logger.warning(
                "run_nuclei_scan | scan_id=%s %d host(s) permanently unresponsive "
                "— findings may be incomplete (WAF/rate-limit interference) elapsed=%.0fs templates=%d",
                scan_id, unresponsive_count, elapsed, templates_loaded,
            )

        findings = parse_nuclei_output(output_file, scan_id)
        logger.info(
            "run_nuclei_scan complete | scan_id=%s findings=%d elapsed=%.0fs templates=%d",
            scan_id, len(findings), elapsed, templates_loaded,
        )
        return findings

    except subprocess.TimeoutExpired:
        process.kill()
        logger.error(
            "run_nuclei_scan timed out after %ds | scan_id=%s",
            NUCLEI_TIMEOUT, scan_id,
        )
        raise

    except Exception as exc:
        logger.exception("run_nuclei_scan failed | scan_id=%s error=%s", scan_id, exc)
        raise
