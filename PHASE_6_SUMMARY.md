# Phase 6 — API Hardening: Summary

**Status:** COMPLETED  
**Date:** 2026-05-18  
**Session:** 3

---

## What Was Done

### 1. Rate Limiting (slowapi)
- Global default: 200 requests/minute per IP
- Tighter per-route limits: POST /scan → 10/min, POST /assets → 30/min, all GET routes → 60/min
- `/health` is exempt from rate limiting

### 2. X-API-Key Authentication Middleware
- All routes except `/health`, `/docs`, `/openapi.json`, `/redoc` require `X-API-Key` header
- Key is read from `API_KEY` environment variable (set in `.env`)
- Wrong or missing key → **403 Forbidden**
- Every rejected request is logged with path and client IP
- Default dev key: `changeme_api_key_dev_2024` — must be changed before any real deployment

### 3. Request Body Size Limit
- Maximum request body size: **64 KB**
- Checked via `Content-Length` header before the body is read
- Oversized request → **413 Request Entity Too Large**

### 4. Stricter Input Validation

**URL fields** (`POST /scan` → `target_url`, `POST /assets` → `url`):
- Max length: 2048 characters
- Scheme must be `http` or `https`
- Hostname must be present
- URL fragments (`#`) are rejected

**UUID path parameters** (`/scan/{scan_id}`, `/vulnerabilities/{vuln_id}`, `/assets/{asset_id}`):
- Changed from `str` to `uuid.UUID` type — FastAPI validates automatically
- Non-UUID values → **422 Unprocessable Entity** (previously caused unhandled `ValueError` / 500)

**Query parameter bounds:**
| Parameter | Endpoint | Constraint |
|-----------|----------|------------|
| `limit` | `/scans`, `/assets` | `1 ≤ limit ≤ 500` |
| `limit` | `/vulnerabilities` | `1 ≤ limit ≤ 1000` |
| `offset` | all list endpoints | `offset ≥ 0` |
| `severity` | `/vulnerabilities` | must be `CRITICAL\|HIGH\|MEDIUM\|LOW\|INFO` |
| `tool` | `/vulnerabilities` | must be `ZAP\|NUCLEI` |
| `scan_id` | `/vulnerabilities` | must be a valid UUID |

---

## Bug Fixes & Improvements (also landed in Session 3)

These were blocking scan completion and were fixed before Phase 6 hardening:

| Bug | Cause | Fix |
|-----|-------|-----|
| `NotNullViolationError` on findings insert | `uuid.uuid4()` not called per row in `save_findings()` | Generate fresh UUID per row in values dict |
| `CardinalityViolationError` on upsert | Duplicate hashes in same batch INSERT | Deduplicate rows by hash before building VALUES list |
| ZAP returning CDN/browser alerts | `zap.core.alerts()` returns all session alerts | Added `baseurl=target_url` parameter to scope results |
| Grafana "No data" | `${VAR:-default}` bash syntax unsupported in provisioning YAML | Hardcoded credentials in `postgres.yml` |

---

## Orphaned Task Guard & Scan Supersession

Added to prevent stale Celery retries from continuing to attack a target:

- **Worker guard**: at the start of every `run_scan` attempt, the scan record is fetched from DB. If the record is missing or already `COMPLETED`/`FAILED`, the task exits immediately without running ZAP or Nuclei.
- **Cancel-on-submit**: when `POST /scan` is called for a target that already has a `PENDING` or `RUNNING` scan, the old Celery task is revoked (`SIGTERM`) and the old scan record is marked `FAILED` with reason `"Superseded by new scan submission"` before the new scan is created.
- **`celery_task_id` column** added to the `scans` table (via `ALTER TABLE`) and `Scan` model to enable targeted task revocation.

---

## Files Changed

| File | Change |
|------|--------|
| `backend/main.py` | Rate limiting, X-API-Key middleware, body size middleware, UUID path params, Annotated query constraints, URL validator |
| `backend/crud.py` | `get_scan_status()`, `set_scan_task_id()`, `get_active_scan_for_target()` helpers; `uuid.uuid4()` fix in `save_findings()` |
| `backend/db/models.py` | `celery_task_id` column on `Scan` model |
| `worker/celery_app.py` | Worker guard check, `_db_get_scan_status()`, `_db_store_task_id()` helpers |
| `scanner/zap_runner.py` | `baseurl=target_url` in `export_report()` |
| `grafana/provisioning/datasources/postgres.yml` | Hardcoded credentials (removed bash variable syntax) |
| `grafana/provisioning/dashboards/va_platform.json` | Added Vulnerability Details panel (severity-coloured, filterable table) |
| `.env` / `.env.example` | Added `API_KEY` variable |

---

## Usage After Phase 6

Every API request (except `/health`) requires the header:

```
X-API-Key: changeme_api_key_dev_2024
```

Example:
```bash
# Submit a scan
curl -X POST http://localhost:8000/scan \
  -H "X-API-Key: changeme_api_key_dev_2024" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://your-target.com/", "active_scan": false}'

# List vulnerabilities filtered by severity
curl http://localhost:8000/vulnerabilities?severity=HIGH \
  -H "X-API-Key: changeme_api_key_dev_2024"
```
