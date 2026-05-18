# Phase 2 Summary — Database Design

## What was built

Phase 2 replaced the temporary in-memory `_scan_store` with a real PostgreSQL-backed persistence layer using SQLAlchemy 2.0 async.

### backend/db/models.py

Three ORM models mirroring `db/init.sql` exactly:

- `Asset` — target domains/URLs
- `Scan` — one row per scan job, with status transitions and timestamps
- `Vulnerability` — normalised findings from ZAP and Nuclei, deduplicated by SHA-256 hash

All enum columns use `create_type=False` so SQLAlchemy never tries to recreate the PostgreSQL enum types that `init.sql` already created.

### backend/db/database.py

- Async engine using `asyncpg` driver (`postgresql+asyncpg://`)
- Auto-rewrites `DATABASE_URL` env var — no second env var needed
- `pool_pre_ping=True` to silently drop stale connections after container restarts
- `get_db()` FastAPI dependency yields a session per request

### backend/crud.py

Five public functions:

| Function | Description |
|---|---|
| `create_scan` | Insert PENDING scan row |
| `update_scan_status` | Transition status, auto-set `started_at` / `finished_at` |
| `get_scan` | Fetch one scan with vulnerabilities eagerly loaded |
| `list_scans` | Newest-first paginated list |
| `save_findings` | Normalise ZAP + Nuclei raw dicts → `Vulnerability` rows, bulk insert |

`_normalise_zap` and `_normalise_nuclei` map raw scanner output to the common schema. `_vuln_hash` generates the SHA-256 dedup key (`target|title|parameter|evidence`).

### backend/migrations/ (Alembic)

- `alembic.ini` — configured to run from `backend/` directory
- `migrations/env.py` — strips `+asyncpg` from `DATABASE_URL` at runtime for sync psycopg2 migrations
- `migrations/versions/0001_initial_schema.py` — creates all tables, enums, indexes, and the `updated_at` trigger; uses idempotent `DO $$ ... EXCEPTION WHEN duplicate_object $$` for enums so it's safe to run alongside `init.sql`

Run migrations:
```
docker compose exec backend alembic upgrade head
```

### backend/main.py

- `_scan_store` dict removed entirely
- All routes use `db: AsyncSession = Depends(get_db)`
- `lifespan` runs `Base.metadata.create_all` on startup as a safety net
- `list_scans` gained `limit`/`offset` pagination query params
- Version bumped to `0.2.0`

### worker/celery_app.py

- `./backend` mounted into worker at `/app/backend`; added to `sys.path`
- Three async DB helpers (`_db_mark_running`, `_db_mark_completed`, `_db_mark_failed`, `_db_save_findings`) called via `asyncio.run()` from the sync Celery task
- `run_scan` now persists status transitions and all findings to PostgreSQL

## Dependency added

`asyncpg==0.30.0` added to `backend/requirements.txt` — required for SQLAlchemy async engine. `psycopg2-binary` is kept for Alembic (sync).

## What's next

Phase 3 — Finding Normalisation & Deduplication: deduplicate findings across scans by hash, add severity scoring, implement `GET /vulnerabilities` endpoint.
