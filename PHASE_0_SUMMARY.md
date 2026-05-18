# Phase 0 Summary — Project Setup

**Completed:** 2026-05-15
**Status:** Done

---

## What Was Built

Phase 0 established the full project skeleton — every file and directory needed to bring the entire Docker stack up with a single `docker compose up -d`.

---

## Files Created

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Orchestrates all 7 services on a shared bridge network |
| `backend/main.py` | FastAPI skeleton with `/health`, `POST /scan`, `GET /scan/{id}`, `GET /scans` |
| `backend/requirements.txt` | Pinned Python dependencies for the backend and worker |
| `backend/Dockerfile` | Multi-stage build — slim runtime image, non-root user |
| `worker/celery_app.py` | Celery app config + `run_scan` task skeleton with retry logic |
| `worker/Dockerfile` | Multi-stage build — project-root build context, no exposed port |
| `scanner/zap_runner.py` | ZAP scan pipeline skeleton (spider → passive → active → report) |
| `scanner/nuclei_runner.py` | Nuclei scan pipeline skeleton (command builder + JSONL parser) |
| `scanner/__init__.py` | Makes `scanner/` a Python package |
| `db/init.sql` | Full PostgreSQL schema — tables, enums, indexes, views, triggers |
| `.env.example` | All environment variables with safe dev defaults |
| `.gitignore` | Excludes `.env`, `__pycache__`, reports output |
| `README.md` | Setup guide, API usage, architecture diagram, dev commands |
| `process.txt` | Session state tracker — phases, decisions, next tasks |

### Directories

```
va-platform/
├── backend/
├── worker/
├── scanner/
├── db/
├── frontend/       ← placeholder
└── reports/        ← placeholder
```

---

## Key Decisions Made

| Decision | Choice | Reason |
|----------|--------|--------|
| Deployment target | Local dev only | Docker bridge network, no TLS, default ports |
| Tool execution | All tools in Docker containers | No host dependencies required |
| ZAP mode | Daemon mode | Simpler API-driven automation |
| Active scanning | Opt-in (`active_scan: true`) | Prevents accidental aggressive scanning |
| ZAP API key | `changeme_zap_dev_2024` | Dev default — must be changed before any real use |
| PostgreSQL credentials | `va_platform` / `va_user` / `va_dev_password_2024` | Safe dev defaults in `.env.example` |
| Python version | 3.12-slim | Latest stable, minimal image size |
| Pydantic | v2 | Required by coding standards |
| SQLAlchemy | 2.0 | Required by coding standards |

---

## Docker Stack

| Service | Image | Port | Healthcheck |
|---------|-------|------|-------------|
| `postgres` | postgres:15-alpine | 5432 | `pg_isready` |
| `redis` | redis:7-alpine | 6379 | `redis-cli ping` |
| `backend` | local build | 8000 | `GET /health` |
| `worker` | local build | — | `celery inspect ping` |
| `zap` | ghcr.io/zaproxy/zaproxy:stable | 8080 | ZAP version API |
| `nuclei` | projectdiscovery/nuclei:latest | — | — |
| `grafana` | grafana/grafana:latest | 3000 | Grafana health API |

---

## Database Schema

Three tables created in `db/init.sql`:

- **`assets`** — registered target domains/URLs
- **`scans`** — one row per scan job, tracks status lifecycle (`PENDING → RUNNING → COMPLETED/FAILED`)
- **`vulnerabilities`** — normalised findings with SHA-256 dedup hash and raw JSONB payload

Two Grafana-ready views:

- **`scan_summary`** — per-scan finding counts by severity + duration
- **`asset_risk_summary`** — per-asset risk rollup across all scans

---

## What Is Stubbed (Implemented in Later Phases)

| Stub | Location | Implemented In |
|------|----------|----------------|
| Celery task dispatch | `backend/main.py` `POST /scan` | Phase 1 |
| ZAP spider / passive / active scan | `scanner/zap_runner.py` | Phase 1 |
| Nuclei subprocess execution | `scanner/nuclei_runner.py` | Phase 1 |
| PostgreSQL CRUD | `backend/main.py` (uses in-memory dict) | Phase 2 |
| Result normalisation + dedup | `worker/celery_app.py` `run_scan` | Phase 3 |
| Grafana provisioning files | — | Phase 4 |

---

## How to Start the Stack

```bash
cd va-platform
cp .env.example .env
docker compose up -d
```

Then verify:

```bash
docker compose ps
curl http://localhost:8000/health
```
