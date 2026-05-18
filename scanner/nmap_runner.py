"""
nmap_runner.py — Port and service scanner for the VA Platform.

Runs nmap as a one-shot Docker container via the mounted Docker socket.
Produces an XML report of open ports and detected services, then normalises
each open port into a finding for storage.

Scan profile: top-100 ports, TCP connect (-sT), service version detection (-sV).
No raw-socket or SYN scan is used — TCP connect works without elevated privileges
on the host and produces reliable results for web-facing targets.
"""

import logging
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("va_platform.scanner.nmap")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPORTS_DIR: Path   = Path(os.getenv("REPORTS_DIR", "/reports"))
REPORTS_VOLUME: str = os.getenv("REPORTS_VOLUME", "va_reports")
NMAP_IMAGE: str     = os.getenv("NMAP_IMAGE", "instrumentisto/nmap:latest")
NMAP_TIMEOUT: int   = int(os.getenv("NMAP_TIMEOUT", "300"))  # 5 min max

# Ports known to be high-risk when exposed publicly
_HIGH_RISK_PORTS: frozenset[int] = frozenset({
    1433,   # MSSQL
    1521,   # Oracle
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    9200,   # Elasticsearch HTTP
    9300,   # Elasticsearch transport
    27017,  # MongoDB
    27018,  # MongoDB shard
    2181,   # ZooKeeper
    5984,   # CouchDB
    7474,   # Neo4j
    8500,   # Consul
})

_MEDIUM_RISK_PORTS: frozenset[int] = frozenset({
    21,     # FTP
    22,     # SSH
    23,     # Telnet
    25,     # SMTP
    3389,   # RDP
    5900,   # VNC
    8080,   # HTTP alt / admin panels
    8443,   # HTTPS alt
    8888,   # Jupyter / dev servers
    4848,   # GlassFish admin
    9090,   # Cockpit / Prometheus
    9000,   # SonarQube / Portainer
    9090,   # Portainer
})


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------

def build_nmap_command(hostname: str, output_file: str) -> list[str]:
    """
    Build the docker run command that executes nmap.

    Args:
        hostname:    Target hostname or IP.
        output_file: Absolute path inside the container for XML output.

    Returns:
        List of command tokens for subprocess.Popen().
    """
    return [
        "docker", "run", "--rm",
        "-v", f"{REPORTS_VOLUME}:/reports",
        "--add-host", "host.docker.internal:host-gateway",
        NMAP_IMAGE,
        "-sT",          # TCP connect scan (no raw socket needed)
        "-sV",          # service/version detection
        "--open",       # only report open ports
        "-T4",          # aggressive timing (faster without being reckless)
        "-F",           # fast mode — top 100 ports
        "-oX", output_file,
        hostname,
    ]


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------

def _port_severity(portid: int, service_name: str) -> str:
    """Return a severity string based on port number and service name."""
    if portid in _HIGH_RISK_PORTS:
        return "HIGH"
    if portid in _MEDIUM_RISK_PORTS:
        return "MEDIUM"
    # Telnet and FTP are always at least medium regardless of port
    if service_name in ("telnet", "ftp"):
        return "MEDIUM"
    return "LOW"


def parse_nmap_xml(output_file: str, scan_id: str, target_url: str) -> list[dict[str, Any]]:
    """
    Parse nmap XML output into a list of finding dicts.

    Each open port becomes one finding. Closed/filtered ports are ignored.

    Args:
        output_file: Path to the nmap XML file (host path).
        scan_id:     Used for log correlation.
        target_url:  Original scan URL (used to populate target field).

    Returns:
        List of nmap finding dicts, one per open port.
    """
    host_path = REPORTS_DIR / Path(output_file).name

    if not host_path.exists():
        logger.warning("scan_id=%s nmap output file not found: %s", scan_id, host_path)
        return []

    try:
        tree = ET.parse(str(host_path))
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.error("scan_id=%s failed to parse nmap XML: %s", scan_id, exc)
        return []

    findings: list[dict[str, Any]] = []

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']") or host.find("address")
        ip = addr_el.get("addr", "") if addr_el is not None else ""

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid   = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")

            svc_el   = port_el.find("service")
            svc_name    = svc_el.get("name", "unknown")   if svc_el is not None else "unknown"
            svc_product = svc_el.get("product", "")       if svc_el is not None else ""
            svc_version = svc_el.get("version", "")       if svc_el is not None else ""

            service_str = " ".join(filter(None, [svc_name, svc_product, svc_version])).strip()
            severity    = _port_severity(portid, svc_name)

            findings.append({
                "port":     portid,
                "protocol": protocol,
                "service":  svc_name,
                "product":  svc_product,
                "version":  svc_version,
                "ip":       ip,
                "target":   target_url,
                "severity": severity,
                "finding":  f"Open {protocol.upper()} port {portid}/{svc_name}: {service_str}".strip(": "),
            })

    logger.info(
        "scan_id=%s parsed %d nmap findings (open ports) from %s",
        scan_id, len(findings), host_path,
    )
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_nmap_scan(scan_id: str, target_url: str) -> list[dict[str, Any]]:
    """
    Run nmap against the hostname extracted from target_url.

    Called by worker/celery_app.py run_scan task after testssl.

    Args:
        scan_id:    UUID of the scan record.
        target_url: Fully-qualified HTTP/S URL.

    Returns:
        List of nmap finding dicts (one per open port).
    """
    parsed   = urlparse(target_url)
    hostname = parsed.hostname or ""

    if not hostname:
        logger.warning("scan_id=%s nmap skipped — could not extract hostname from %s", scan_id, target_url)
        return []

    logger.info("run_nmap_scan started | scan_id=%s hostname=%s", scan_id, hostname)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    output_file = f"/reports/nmap_{scan_id}.xml"   # path inside container

    cmd = build_nmap_command(hostname, output_file)
    logger.debug("scan_id=%s nmap command: %s", scan_id, " ".join(cmd))

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        for line in process.stdout:
            line = line.rstrip()
            if line:
                logger.info("scan_id=%s nmap: %s", scan_id, line)

        process.wait(timeout=NMAP_TIMEOUT)

        if process.returncode != 0:
            raise RuntimeError(f"nmap exited with code {process.returncode}")

        findings = parse_nmap_xml(output_file, scan_id, target_url)
        logger.info("run_nmap_scan complete | scan_id=%s findings=%d", scan_id, len(findings))
        return findings

    except subprocess.TimeoutExpired:
        process.kill()
        logger.error("run_nmap_scan timed out after %ds | scan_id=%s", NMAP_TIMEOUT, scan_id)
        raise

    except Exception as exc:
        logger.exception("run_nmap_scan failed | scan_id=%s error=%s", scan_id, exc)
        raise
