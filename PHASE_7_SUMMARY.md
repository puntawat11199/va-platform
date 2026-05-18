# Phase 7 Summary — Additional Scanners (testssl.sh + nmap)

Completed: 2026-05-18

---

## Overview

Phase 7 added two new scanners to the pipeline, both running as ephemeral Docker containers via the mounted Docker socket. The scan sequence is now:

```
ZAP → Nuclei → testssl.sh → nmap → persist findings
```

---

## testssl.sh

**Purpose:** SSL/TLS configuration analysis — weak ciphers, protocol versions, certificate issues, HSTS, BEAST/POODLE/HEARTBLEED etc.

**Implementation:** `scanner/testssl_runner.py`

| Detail | Value |
|--------|-------|
| Image | `drwetter/testssl.sh:3.2` |
| Invocation | `docker run --rm -v va_reports:/reports` |
| Output | JSON (`/reports/testssl_{scan_id}.json`) |
| Timeout | 600s |
| HTTP targets | Skipped immediately — no TLS to test |
| OK severity | Filtered out (passing controls, not findings) |
| WARN severity | Mapped to LOW |

**DB enum value:** `TESTSSL` (migration `0003_add_testssl_scanner_tool.py`)

**Normalisation:** `_normalise_testssl()` + `_map_severity_testssl()` in `crud.py`

---

## nmap

**Purpose:** Port/service discovery — exposed database ports, admin panels, unexpected services.

**Implementation:** `scanner/nmap_runner.py`

| Detail | Value |
|--------|-------|
| Image | `instrumentisto/nmap:latest` |
| Invocation | `docker run --rm -v va_reports:/reports --add-host host.docker.internal:host-gateway` |
| Scan flags | `-sT -sV --open -T4 -F` (TCP connect, service detection, top 100 ports) |
| Output | XML (`/reports/nmap_{scan_id}.xml`) |
| Timeout | 300s |

**Severity classification:**

| Severity | Ports |
|----------|-------|
| HIGH | 1433 (MSSQL), 1521 (Oracle), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 9200/9300 (Elasticsearch), 27017/27018 (MongoDB), 2181 (ZooKeeper), 5984 (CouchDB), 7474 (Neo4j), 8500 (Consul) |
| MEDIUM | 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 3389 (RDP), 5900 (VNC), 8080, 8443, 8888 (Jupyter), 4848 (GlassFish), 9090 (Cockpit/Prometheus), 9000 (SonarQube/Portainer) |
| LOW | All other open ports (including 80, 443) |

**DB enum value:** `NMAP` (migration `0004_add_nmap_scanner_tool.py`)

**Normalisation:** `_normalise_nmap()` + `_map_severity_nmap()` in `crud.py`

---

## Infrastructure changes

### Docker socket access (worker)
- Mounted `/var/run/docker.sock` in `docker-compose.yml` worker service
- Static Docker CLI binary installed in worker Dockerfile:
  ```dockerfile
  curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-27.5.1.tgz" \
    | tar xz --strip-components=1 -C /usr/local/bin docker/docker
  ```
  > `docker.io` Debian package installs the daemon only — CLI binary must be fetched separately.

### Named volume
- Added `name: va_reports` to `reports_data` volume in `docker-compose.yml`
- Required for predictable `docker run -v va_reports:/reports` in testssl/nmap commands

### Environment variables added to worker service
```yaml
REPORTS_VOLUME: va_reports
TESTSSL_IMAGE: drwetter/testssl.sh:3.2
NMAP_IMAGE: instrumentisto/nmap:latest
```

---

## Files changed

| File | Change |
|------|--------|
| `scanner/testssl_runner.py` | New — full testssl.sh integration |
| `scanner/nmap_runner.py` | New — full nmap integration |
| `backend/db/models.py` | Added `TESTSSL`, `NMAP` to `ScannerTool` enum |
| `backend/crud.py` | Added `_normalise_testssl`, `_normalise_nmap`, `_map_severity_testssl`, `_map_severity_nmap`; updated `save_findings()` |
| `worker/celery_app.py` | Added testssl + nmap steps in `run_scan`; updated `_db_save_findings()` |
| `worker/Dockerfile` | Static docker CLI binary + docker-host group |
| `docker-compose.yml` | Docker socket mount, named volume, env vars |
| `db/init.sql` | `TESTSSL`, `NMAP` added to `scanner_tool` enum |
| `migrations/versions/0003_add_testssl_scanner_tool.py` | New |
| `migrations/versions/0004_add_nmap_scanner_tool.py` | New |
