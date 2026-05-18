# VA Automation Platform

A Web Vulnerability Assessment (VA) Automation Platform that orchestrates OWASP ZAP and Nuclei scans via a REST API, processes results asynchronously with Celery, stores findings in PostgreSQL, and visualises them in Grafana.

---

## Architecture

```
┌─────────────┐     POST /scan      ┌─────────────────┐
│   Client    │ ─────────────────▶  │  FastAPI (8000) │
└─────────────┘                     └────────┬────────┘
                                             │ enqueue
                                    ┌────────▼────────┐
                                    │  Redis (6379)   │
                                    └────────┬────────┘
                                             │ consume
                                    ┌────────▼────────┐
                                    │  Celery Worker  │
                                    └──┬──────────┬───┘
                                       │          │
                              ┌────────▼──┐  ┌────▼───────┐
                              │ ZAP (8080)│  │   Nuclei   │
                              └────────┬──┘  └────┬───────┘
                                       │          │
                                    ┌──▼──────────▼──┐
                                    │  PostgreSQL    │
                                    │    (5432)      │
                                    └────────┬───────┘
                                             │
                                    ┌────────▼───────┐
                                    │ Grafana (3000) │
                                    └────────────────┘
```

---

## Services

| Service    | Image                              | Port | Description                     |
|------------|------------------------------------|------|---------------------------------|
| `backend`  | local build                        | 8000 | FastAPI REST API                |
| `worker`   | local build                        | —    | Celery async scan worker        |
| `postgres` | postgres:15-alpine                 | 5432 | Primary database                |
| `redis`    | redis:7-alpine                     | 6379 | Celery broker + result backend  |
| `zap`      | ghcr.io/zaproxy/zaproxy:stable     | 8080 | OWASP ZAP daemon                |
| `nuclei`   | projectdiscovery/nuclei:latest     | —    | CVE / misconfiguration scanner  |
| `grafana`  | grafana/grafana:latest             | 3000 | Vulnerability dashboard         |

---

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/Mac) or Docker Engine + Compose v2 (Linux)
- Git

---

## Quick Start

### 1. Clone the repository

```bash
git clone <repo-url>
cd va-platform
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` if you want to change any defaults. The dev defaults work out of the box.

> **Important:** Change `ZAP_API_KEY` and `SECRET_KEY` before exposing this platform on any network.

### 3. Start the stack

```bash
docker compose up -d
```

First run pulls all images and builds the backend/worker containers — this takes a few minutes.

### 4. Verify all services are healthy

```bash
docker compose ps
```

All services should show `healthy` or `running`. ZAP takes ~60 seconds to fully start.

### 5. Check the API

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{"status": "ok", "version": "0.1.0", "timestamp": "..."}
```

### 6. Open the dashboard

Navigate to [http://localhost:3000](http://localhost:3000) and log in with:
- Username: `admin`
- Password: `admin_dev_2024` (or your `GRAFANA_PASSWORD` value)

---

## API Usage

### Submit a scan

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://testphp.vulnweb.com",
    "active_scan": false
  }'
```

Response:
```json
{
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "target_url": "http://testphp.vulnweb.com",
  "active_scan": false,
  "status": "PENDING",
  "created_at": "2026-05-15T10:00:00"
}
```

> Set `"active_scan": true` to include ZAP active scanning.
> **Only scan targets you own or have written permission to test.**

### Poll scan status

```bash
curl http://localhost:8000/scan/3fa85f64-5717-4562-b3fc-2c963f66afa6
```

### List all scans

```bash
curl http://localhost:8000/scans
```

### Interactive API docs

FastAPI auto-generates docs at:
- Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
- ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## Development

### View logs

```bash
# All services
docker compose logs -f

# Single service
docker compose logs -f backend
docker compose logs -f worker
docker compose logs -f zap
```

### Rebuild after code changes

The backend and worker mount source code as volumes — changes are picked up immediately (hot-reload enabled for the backend). If you change `requirements.txt` or the Dockerfile:

```bash
docker compose up -d --build backend worker
```

### Connect to PostgreSQL directly

```bash
docker compose exec postgres psql -U va_user -d va_platform
```

### Connect to Redis directly

```bash
docker compose exec redis redis-cli
```

### Run Celery worker manually (for debugging)

```bash
docker compose exec worker celery -A celery_app.celery_app worker --loglevel=debug
```

### Monitor Celery tasks

```bash
docker compose exec worker celery -A celery_app.celery_app inspect active
docker compose exec worker celery -A celery_app.celery_app inspect stats
```

---

## Project Structure

```
va-platform/
├── backend/                  # FastAPI application
│   ├── main.py               # API routes and schemas
│   ├── requirements.txt      # Python dependencies
│   └── Dockerfile
├── worker/                   # Celery worker
│   ├── celery_app.py         # Task definitions
│   └── Dockerfile
├── scanner/                  # Scanner integrations
│   ├── zap_runner.py         # OWASP ZAP orchestration
│   └── nuclei_runner.py      # Nuclei orchestration
├── db/
│   └── init.sql              # PostgreSQL schema (auto-run on first start)
├── reports/                  # Scan output files (JSON/JSONL)
├── frontend/                 # Placeholder (Phase 4+)
├── grafana/                  # Grafana provisioning (Phase 4)
│   └── provisioning/
│       ├── datasources/
│       └── dashboards/
├── docker-compose.yml
├── .env.example              # Copy to .env before running
└── README.md
```

---

## Stopping the Stack

```bash
# Stop containers (keep volumes)
docker compose down

# Stop and delete all data volumes (full reset)
docker compose down -v
```

---

## Build Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | Done | Project setup, Docker Compose stack |
| 1 | Pending | ZAP + Nuclei scan integration |
| 2 | Pending | PostgreSQL models + CRUD |
| 3 | Pending | Result normalisation + deduplication |
| 4 | Pending | Grafana dashboard |
| 5 | Pending | Full workflow engine |
| 6 | Pending | CI/CD integration |
| 7 | Pending | Advanced tools (subfinder, katana, ffuf) |
| 8 | Pending | Enterprise features (auth, alerts, Jira) |

---

## Security Notice

- This platform is designed for **authorised security testing only**.
- Never run scans against targets you do not own or have explicit written permission to test.
- Change all default credentials and API keys in `.env` before any non-local deployment.
- Do not expose ports 8000, 8080, or 5432 to the public internet in development mode.
