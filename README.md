# VA Automation Platform

A self-hosted Web Vulnerability Assessment (VA) platform that orchestrates **OWASP ZAP**, **Nuclei**, **testssl.sh**, and **nmap** scans via a REST API, processes results asynchronously with Celery, stores findings in PostgreSQL, and visualises them in a Grafana dashboard.

**Current version:** `0.3.0`

---

## Architecture

```
┌─────────────┐     POST /scan      ┌─────────────────┐
│   Client    │ ─────────────────▶  │  FastAPI (8000) │
└─────────────┘                     └────────┬────────┘
                                             │ enqueue
                                    ┌────────▼────────┐
                                    │  Redis (6379)   │◀── Celery Beat
                                    └────────┬────────┘    (scheduler)
                                             │ consume
                                    ┌────────▼────────────────────────┐
                                    │        Celery Worker            │
                                    │  1. ZAP runner   (web vulns)    │
                                    │  2. Nuclei runner (CVEs/misconf)│
                                    │  3. testssl runner (TLS/SSL)    │
                                    │  4. nmap runner  (open ports)   │
                                    └──────────────┬──────────────────┘
                                                   │
                                    ┌──────────────▼──────────────────┐
                                    │         PostgreSQL (5432)       │
                                    └──────────────┬──────────────────┘
                                                   │
                                    ┌──────────────▼──────────────────┐
                                    │        Grafana (3000)           │
                                    └─────────────────────────────────┘
```

---

## Services

| Service    | Image                              | Port | Description                              |
|------------|------------------------------------|------|------------------------------------------|
| `backend`  | local build                        | 8000 | FastAPI REST API                         |
| `worker`   | local build                        | —    | Celery async scan worker (4 scanners)    |
| `beat`     | local build                        | —    | Celery Beat — scheduled rescans          |
| `postgres` | postgres:15-alpine                 | 5432 | Primary database                         |
| `redis`    | redis:7-alpine                     | 6379 | Celery broker + result backend           |
| `zap`      | ghcr.io/zaproxy/zaproxy:stable     | 8090 | OWASP ZAP daemon (host 8090→8080)        |
| `nuclei`   | projectdiscovery/nuclei:latest     | —    | CVE / misconfiguration scanner           |
| `grafana`  | grafana/grafana:latest             | 3000 | Vulnerability dashboard                  |

---

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac) or Docker Engine + Compose v2 (Linux)
- Git

See [how_to_install.md](how_to_install.md) for full step-by-step instructions on both Windows and Linux.

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/puntawat11199/va-platform.git
cd va-platform
```

### 2. Configure environment

**Windows:**
```powershell
Copy-Item .env.example .env
```
**Linux:**
```bash
cp .env.example .env
```

Edit `.env` — at minimum change `API_KEY`, `ZAP_API_KEY`, and `DB_PASSWORD` before any non-local use.

### 3. Start the stack

```bash
docker compose up -d
```

First run pulls all images and builds containers — takes 5–10 minutes. ZAP needs ~60s to load.

### 4. Verify all services are healthy

```bash
docker compose ps
```

All services should show `healthy` or `running`.

### 5. Check the API

```powershell
# Windows
(Invoke-WebRequest -Uri "http://localhost:8000/health").Content

# Linux
curl -s http://localhost:8000/health
```

Expected: `{"status":"ok","version":"0.3.0","timestamp":"..."}`

### 6. Open the dashboard

Go to [http://localhost:3000](http://localhost:3000) — login: `admin` / `admin_dev_2024`

---

## API Usage

All endpoints (except `/health`, `/docs`, `/redoc`) require the `X-API-Key` header.

### Using Swagger UI (easiest — browser, no curl needed)

1. Open [http://localhost:8000/docs](http://localhost:8000/docs)
2. Click the **Authorize** button (top right)
3. Enter your API key from `.env` → click **Authorize**
4. Use **Try it out** on any endpoint — the key is sent automatically
5. After executing, the **Snippets** section shows ready-to-copy commands in three formats:
   - `cURL (Linux/Mac)`
   - `cURL (Windows CMD)`
   - `Invoke-WebRequest (PS)` — native PowerShell, no curl needed

### Submit a scan

**Windows (PowerShell):**
```powershell
$headers = @{"X-API-Key" = "your_api_key"; "Content-Type" = "application/json"}

# Passive scan (safe — no attack payloads)
Invoke-WebRequest -Uri "http://localhost:8000/scan" `
  -Method POST `
  -Headers $headers `
  -Body '{"target_url": "http://host.docker.internal:5000", "active_scan": false}'

# Active scan (sends attack payloads — only use on targets you own)
Invoke-WebRequest -Uri "http://localhost:8000/scan" `
  -Method POST `
  -Headers $headers `
  -Body '{"target_url": "http://host.docker.internal:5000", "active_scan": true}'
```

**Linux:**
```bash
curl -s -X POST http://localhost:8000/scan \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://example.com", "active_scan": false}'
```

### Poll scan status

```powershell
# Windows
Invoke-WebRequest -Uri "http://localhost:8000/scan/<scan_id>" `
  -Headers @{"X-API-Key" = "your_api_key"}
```
```bash
# Linux
curl -s http://localhost:8000/scan/<scan_id> -H "X-API-Key: your_api_key"
```

Poll until `"status"` is `"COMPLETED"` or `"FAILED"`. Typical durations:

| Scan type | Duration |
|-----------|----------|
| Passive only | 2–5 min |
| Active scan | 5–20 min |

### Download PDF report

```powershell
# Windows — saves PDF to disk
Invoke-WebRequest -Uri "http://localhost:8000/scan/<scan_id>/report.pdf" `
  -Headers @{"X-API-Key" = "your_api_key"} `
  -OutFile "report.pdf"
```
```bash
# Linux
curl -s "http://localhost:8000/scan/<scan_id>/report.pdf" \
  -H "X-API-Key: your_api_key" -o report.pdf
```

### List vulnerabilities

```powershell
# Windows — all findings for a scan
Invoke-WebRequest -Uri "http://localhost:8000/vulnerabilities?scan_id=<scan_id>" `
  -Headers @{"X-API-Key" = "your_api_key"}

# Filter by severity or tool
Invoke-WebRequest -Uri "http://localhost:8000/vulnerabilities?severity=CRITICAL" `
  -Headers @{"X-API-Key" = "your_api_key"}
Invoke-WebRequest -Uri "http://localhost:8000/vulnerabilities?tool=NMAP" `
  -Headers @{"X-API-Key" = "your_api_key"}
```

### Delete a scan

```powershell
# Windows
Invoke-WebRequest -Uri "http://localhost:8000/scan/<scan_id>" `
  -Method DELETE `
  -Headers @{"X-API-Key" = "your_api_key"}
# Returns HTTP 204 on success. Cancels the Celery task if still running.
```
```bash
# Linux
curl -s -X DELETE http://localhost:8000/scan/<scan_id> \
  -H "X-API-Key: your_api_key" -w "%{http_code}"
```

### Full API reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Platform health check (no auth) |
| `POST` | `/scan` | Submit a new scan job |
| `GET` | `/scan/{id}` | Get scan status + findings |
| `DELETE` | `/scan/{id}` | Delete scan (revokes task if running) |
| `GET` | `/scan/{id}/report.pdf` | Download PDF report |
| `GET` | `/scans` | List all scans (paginated) |
| `GET` | `/vulnerabilities` | List findings (filter by scan/severity/tool) |
| `GET` | `/vulnerabilities/{id}` | Get single vulnerability |
| `POST` | `/assets` | Register a target asset |
| `GET` | `/assets` | List registered assets |
| `GET` | `/assets/{id}` | Get single asset |

---

## Development

### View logs

```bash
docker compose logs -f           # all services
docker compose logs -f worker    # worker only
docker compose logs -f backend   # backend only
```

### Rebuild after code changes

Source code is volume-mounted — Python changes are picked up by hot-reload automatically.
Only rebuild when `requirements.txt` or a Dockerfile changes:

```bash
docker compose build backend worker
docker compose up -d --no-deps backend worker
```

### Run database migrations

```bash
docker exec va_backend alembic upgrade head
```

### Connect to PostgreSQL directly

```bash
docker exec va_postgres psql -U va_user -d va_platform
```

---

## Project Structure

```
va-platform/
├── backend/
│   ├── main.py               # FastAPI routes, middleware, schemas
│   ├── crud.py               # Database CRUD + finding normalisation
│   ├── pdf_report.py         # PDF report generator (fpdf2)
│   ├── requirements.txt
│   ├── Dockerfile
│   └── db/
│       ├── models.py         # SQLAlchemy models
│       ├── database.py       # Async engine + session
│       └── migrations/       # Alembic migrations (0001–0004)
├── worker/
│   ├── celery_app.py         # Celery task definitions
│   └── Dockerfile
├── scanner/
│   ├── zap_runner.py         # OWASP ZAP orchestration
│   ├── nuclei_runner.py      # Nuclei orchestration
│   ├── testssl_runner.py     # testssl.sh via Docker socket
│   └── nmap_runner.py        # nmap via Docker socket
├── db/
│   └── init.sql              # PostgreSQL schema (auto-run on first start)
├── grafana/
│   └── provisioning/
│       ├── datasources/      # Auto-configured PostgreSQL connection
│       └── dashboards/       # Pre-built VA dashboard JSON
├── docker-compose.yml
├── .env.example
├── how_to_install.md         # Full installation guide (Windows + Linux)
├── QA_TEST_CASES_GENERATED.md # 137 test cases across 10 categories
└── README.md
```

---

## Stopping the Stack

```bash
docker compose down          # stop (keep data)
docker compose down -v       # stop + delete all data (full reset)
```

---

## Build Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | Done | Project setup, Docker Compose stack |
| 1 | Done | ZAP + Nuclei scan integration |
| 2 | Done | PostgreSQL models + async CRUD |
| 3 | Done | Result normalisation + deduplication |
| 4 | Done | Grafana dashboard (auto-provisioned) |
| 5 | Done | Asset management + Celery Beat scheduled scans |
| 6 | Done | API hardening (rate limiting, API key auth, input validation) |
| 7 | Done | Additional scanners: testssl.sh + nmap |
| Post-launch | Done | PDF reports, DELETE endpoint, Swagger UI improvements |
| 8 | Planned | Enterprise features (JWT auth, Slack/email alerts, Jira) |

---

## Security Notice

- This platform is designed for **authorised security testing only**.
- Never run scans against targets you do not own or have explicit written permission to test.
- Change all default credentials in `.env` before any non-local deployment.
- Do not expose ports 8000, 5432, or 6379 to the public internet in development mode.
