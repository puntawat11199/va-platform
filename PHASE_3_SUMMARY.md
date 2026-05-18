# Phase 3 Summary — Finding Normalisation & Deduplication

## What was built

Phase 3 added vulnerability query endpoints and deduplication logic so repeated scans of the same target don't accumulate duplicate rows.

### GET /vulnerabilities

New endpoint with four optional query params:

| Param | Example | Effect |
|---|---|---|
| `scan_id` | `?scan_id=<uuid>` | Filter to one scan |
| `severity` | `?severity=HIGH` | Filter by severity level |
| `tool` | `?tool=ZAP` | Filter by scanner |
| `limit` / `offset` | `?limit=50&offset=100` | Pagination |

Params can be combined freely. Results ordered by `first_seen` descending.

### GET /vulnerabilities/{vuln_id}

Returns a single vulnerability by UUID with all normalised fields plus the original raw scanner payload.

### VulnerabilityResponse schema

Returned by both endpoints — exposes all normalised fields (`vuln_id`, `scan_id`, `tool`, `severity`, `title`, `description`, `target`, `path`, `parameter`, `evidence`, `hash`, `first_seen`, `last_seen`). Raw scanner payload excluded from the list/detail response to keep payloads manageable.

### Deduplication — migration 0002

Added unique constraint `uq_vuln_scan_hash` on `(scan_id, hash)` via Alembic migration `0002_vuln_dedup_constraint.py`.

Run with:
```
docker compose exec backend alembic upgrade head
```

### Deduplication — save_findings upsert

`save_findings` in `crud.py` now uses PostgreSQL `INSERT ... ON CONFLICT DO UPDATE` instead of a plain bulk insert:

```python
pg_insert(Vulnerability)
  .values(values)
  .on_conflict_do_update(
      constraint="uq_vuln_scan_hash",
      set_={"last_seen": _utcnow()},
  )
```

Re-scanning the same target updates `last_seen` on existing findings rather than inserting duplicates. `first_seen` is preserved as the original discovery timestamp.

## What's next

Phase 4 — Grafana Dashboard: wire up the `scan_summary` and `asset_risk_summary` views (already created in `init.sql`) to Grafana panels for real-time scan visibility.
