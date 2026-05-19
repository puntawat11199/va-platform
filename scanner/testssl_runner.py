"""
testssl_runner.py — SSL/TLS configuration scanner for the VA Platform.

Runs drwetter/testssl.sh as a one-shot Docker container via the mounted
Docker socket. Produces a JSON report of TLS findings (weak ciphers,
missing HSTS, certificate issues, protocol support, etc.).

Only runs against HTTPS targets — HTTP-only targets return empty findings.
"""

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("va_platform.scanner.testssl")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPORTS_DIR: Path    = Path(os.getenv("REPORTS_DIR", "/reports"))
REPORTS_VOLUME: str  = os.getenv("REPORTS_VOLUME", "va_reports")
TESTSSL_IMAGE: str   = os.getenv("TESTSSL_IMAGE", "drwetter/testssl.sh:3.2")
TESTSSL_TIMEOUT: int = int(os.getenv("TESTSSL_TIMEOUT", "600"))  # 10 min max


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------

def build_testssl_command(target: str, output_file: str) -> list[str]:
    """
    Build the docker run command that executes testssl.sh.

    Args:
        target:      Hostname:port string (e.g. example.com:443).
        output_file: Absolute path inside the container for JSON output.

    Returns:
        List of command tokens for subprocess.run().
    """
    return [
        "docker", "run", "--rm",
        "--user", "root",           # run as root so it can write to the root-owned reports volume
        "-v", f"{REPORTS_VOLUME}:/reports",
        TESTSSL_IMAGE,
        "--jsonfile", output_file,
        "--color",    "0",          # no ANSI colour codes
        "--warnings", "batch",      # non-interactive, suppress prompts
        "-q",                       # quiet — suppress banner
        "--ip",       "one",        # only test first resolved IP (faster)
        target,
    ]


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------

def parse_testssl_output(output_file: str, scan_id: str) -> list[dict[str, Any]]:
    """
    Parse testssl.sh JSON output into a list of finding dicts.

    testssl.sh --jsonfile writes a JSON array.  OK-severity entries are
    filtered out — they mean the control passed and are not actionable.

    Args:
        output_file: Path to the testssl JSON output file (inside container).
        scan_id:     Used for log correlation.

    Returns:
        List of raw testssl finding dicts (non-OK findings only).
    """
    # output_file path is inside the container (/reports/...); map to host path
    filename   = Path(output_file).name
    host_path  = REPORTS_DIR / filename

    if not host_path.exists():
        logger.warning("scan_id=%s testssl output file not found: %s", scan_id, host_path)
        return []

    content = host_path.read_text(encoding="utf-8").strip()
    if not content or content == "[]":
        logger.info("scan_id=%s testssl found 0 results", scan_id)
        return []

    try:
        findings = json.loads(content)
        if not isinstance(findings, list):
            logger.warning("scan_id=%s unexpected testssl JSON structure", scan_id)
            return []
    except json.JSONDecodeError as exc:
        logger.error("scan_id=%s failed to parse testssl JSON: %s", scan_id, exc)
        return []

    # Filter out OK findings — they are passing controls, not vulnerabilities
    actionable = [f for f in findings if (f.get("severity") or "").upper() != "OK"]

    logger.info(
        "scan_id=%s parsed %d testssl findings (%d total, %d OK skipped) from %s",
        scan_id, len(actionable), len(findings), len(findings) - len(actionable), host_path,
    )
    return actionable


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_testssl_scan(scan_id: str, target_url: str) -> list[dict[str, Any]]:
    """
    Run testssl.sh against an HTTPS target and return findings.

    Skips HTTP-only targets (no TLS to test). Called by
    worker/celery_app.py run_scan task after Nuclei.

    Args:
        scan_id:    UUID of the scan record.
        target_url: Fully-qualified HTTP/S URL.

    Returns:
        List of raw testssl finding dicts, or [] for HTTP targets.
    """
    parsed = urlparse(target_url)

    if parsed.scheme != "https":
        logger.info(
            "scan_id=%s testssl skipped — target is HTTP-only (no TLS to test): %s",
            scan_id, target_url,
        )
        return []

    # Build host:port target for testssl (it doesn't accept full URLs)
    host = parsed.hostname or ""
    port = parsed.port or 443
    target = f"{host}:{port}"

    logger.info("run_testssl_scan started | scan_id=%s target=%s", scan_id, target)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output_file = f"/reports/testssl_{scan_id}.json"  # path inside container

    cmd = build_testssl_command(target, output_file)
    logger.debug("scan_id=%s testssl command: %s", scan_id, " ".join(cmd))

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr into stdout for clean logging
            text=True,
        )

        for line in process.stdout:
            line = line.rstrip()
            if line:
                logger.info("scan_id=%s testssl: %s", scan_id, line)

        process.wait(timeout=TESTSSL_TIMEOUT)

        if process.returncode not in (0, 1):
            raise RuntimeError(f"testssl exited with code {process.returncode}")

        findings = parse_testssl_output(output_file, scan_id)
        logger.info(
            "run_testssl_scan complete | scan_id=%s findings=%d",
            scan_id, len(findings),
        )
        return findings

    except subprocess.TimeoutExpired:
        process.kill()
        logger.error("run_testssl_scan timed out after %ds | scan_id=%s", TESTSSL_TIMEOUT, scan_id)
        raise

    except Exception as exc:
        logger.exception("run_testssl_scan failed | scan_id=%s error=%s", scan_id, exc)
        raise
