# Phase 1 Summary — Real Scanner Implementation

## What was built

Phase 1 replaced the Phase 0 skeleton stubs with fully working scanner implementations and wired them end-to-end through the Celery worker.

### scanner/zap_runner.py

Full ZAP scan pipeline:

1. `get_zap_client()` — connects to the ZAP daemon via `python-owasp-zap-v2.4`, retries up to 3× with exponential backoff (tenacity)
2. `run_spider()` — standard ZAP spider, polls until 100% or timeout
3. `run_ajax_spider()` — AJAX spider for JavaScript-rendered pages, polls until stopped
4. `run_passive_scan()` — waits for passive scan queue to drain (runs automatically during spidering)
5. `run_active_scan()` — opt-in active scan at High strength / Default threshold (WARNING: sends attack payloads)
6. `export_report()` — fetches all alerts via `zap.core.alerts()`, saves to `/reports/zap_{scan_id}.json`

Key fix: removed `apikey=` kwarg from all ZAP API method calls — the constructor handles auth.

### scanner/nuclei_runner.py

Full Nuclei scan pipeline:

1. `build_nuclei_command()` — builds CLI command with explicit `-t NUCLEI_TEMPLATES_PATH` (required in nuclei v3), all default template tags, rate limit 50 req/s
2. `parse_nuclei_output()` — handles nuclei v3 JSON array format (`[{...}]`) with JSONL fallback for older versions; skips malformed lines gracefully
3. `run_nuclei_scan()` — runs nuclei via `subprocess.Popen` (not `run`) so stderr progress lines stream to Docker logs in real time

### worker/Dockerfile

Multi-stage build:
- Stage 1 (`deps`): installs Python packages
- Stage 2 (`nuclei-src`): pulls `projectdiscovery/nuclei:latest` for the binary
- Stage 3 (`runtime`): copies packages + nuclei binary, creates non-root user `va` with real home directory at `/home/va`

The non-root user with a real home was required because nuclei writes config/cache files to `$HOME`.

### worker/celery_app.py

`run_scan` task wired to call both scanners sequentially (ZAP first, then Nuclei) and aggregate findings. `sys.path.insert(0, "/app")` added at module top for Celery forked process imports.

## Verified working

- End-to-end scan runs and reaches COMPLETED status
- ZAP: ~90–96 alerts per scan (spider → AJAX spider → passive scan)
- Nuclei: findings parsed correctly from JSON array output (nuclei v3 format)
- Real-time nuclei progress visible in Docker worker logs via Popen stderr streaming
- Reports written to `/reports/` shared volume: `zap_{scan_id}.json`, `nuclei_{scan_id}.jsonl`
- Typical scan time: 74–556s depending on whether active scan is enabled and nuclei template count

## Key decisions

| Decision | Rationale |
|---|---|
| ZAP + Nuclei sequential | Simpler than parallel; ZAP spider results can benefit nuclei coverage |
| Active scan opt-in | Active scan sends attack payloads — must never run without authorization |
| Nuclei Popen (not subprocess.run) | Real-time stderr streaming to Docker logs for progress visibility |
| Worker-private nuclei templates volume | Separate from the `va_nuclei` container volume to avoid root-ownership conflicts |
| Non-root `va` user with real home | Nuclei requires `$HOME` writable for config and cache |

## What's next

Phase 2 — Database Design: replace the in-memory `_scan_store` with PostgreSQL, implement SQLAlchemy 2.0 async models, and persist scan status/findings from the worker.
