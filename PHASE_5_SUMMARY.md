# Phase 5 Summary — Scheduled Scans & Asset Management

## What was built

Phase 5 added asset management endpoints, wired asset auto-creation into the scan submission flow, and added Celery Beat for recurring scheduled scans.

### Asset endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/assets` | Register a new target URL (409 on duplicate) |
| GET | `/assets` | List all assets, newest first, paginated |
| GET | `/assets/{asset_id}` | Fetch a single asset by UUID |

Assets track `domain` (extracted from URL), `url`, `created_at`, and `updated_at`.

### Asset auto-creation in POST /scan

`submit_scan` now calls `get_or_create_asset()` before creating the scan row. Every submitted scan is automatically linked to its asset via `scan.asset_id`. No separate `POST /assets` call is required — assets are registered transparently on first scan.

### Celery Beat service (docker-compose)

A new `beat` service was added sharing the same Docker image as the worker. It runs:

```
celery -A celery_app.celery_app beat --loglevel=info --scheduler celery.beat:PersistentScheduler
```

The beat service is kept separate from the worker intentionally — running beat inside the worker process is not recommended for production.

### scan_all_assets periodic task

Scheduled to run every 24 hours via `beat_schedule` in `celery_app.py`. At runtime it:

1. Reads all registered assets from PostgreSQL
2. Creates a PENDING scan row for each
3. Dispatches `run_scan` tasks onto the `scans` queue

Active scan is always `False` for scheduled runs to avoid sending attack payloads automatically.

To start the beat service:

```
docker compose up -d --build beat
```

To trigger the scheduled task manually for testing:

```
docker compose exec worker celery -A celery_app.celery_app call worker.celery_app.scan_all_assets
```

## What's next

Phase 6 — API hardening: input validation improvements, rate limiting, and basic API key authentication.
