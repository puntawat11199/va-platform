# Phase 4 Summary — Grafana Dashboard

## What was built

Phase 4 provisioned a fully automated Grafana dashboard wired directly to the PostgreSQL database. No manual setup required — the dashboard loads automatically when the Grafana container starts.

## Files created

### grafana/provisioning/datasources/postgres.yml

Provisions the `VA Platform DB` PostgreSQL datasource with uid `va_postgres`. Reads credentials from environment variables (`DB_USER`, `DB_PASSWORD`, `DB_NAME`) so no secrets are hardcoded.

### grafana/provisioning/dashboards/dashboard.yml

Tells Grafana to scan `/etc/grafana/provisioning/dashboards` for JSON files every 30 seconds. New dashboard files dropped into that directory are picked up automatically.

### grafana/provisioning/dashboards/va_platform.json

Nine panels across four rows:

| Panel | Type | Data source |
|---|---|---|
| Total Scans | Stat | `SELECT COUNT(*) FROM scans` |
| Total Findings | Stat (red threshold at 50) | `SELECT COUNT(*) FROM vulnerabilities` |
| Critical / High Findings | Stat (red threshold at 5) | severity filter |
| Completed Scans | Stat | status filter |
| Findings by Severity | Donut chart | severity GROUP BY |
| Scans by Status | Donut chart | status GROUP BY |
| Findings by Scanner | Donut chart | tool GROUP BY |
| Recent Scans | Table (colour-coded status + severity columns) | `scan_summary` view |
| Asset Risk Summary | Table (colour-coded critical/high) | `asset_risk_summary` view |

The `scan_summary` and `asset_risk_summary` views were pre-built in `db/init.sql` during Phase 0 specifically for these panels.

## Access

Navigate to `http://localhost:3000` — credentials from `.env` (`GRAFANA_USER` / `GRAFANA_PASSWORD`, defaults `admin` / `admin_dev_2024`).

The dashboard auto-refreshes every 30 seconds. After running a scan, findings appear in the panels within one refresh cycle.

## What's next

Phase 5 — Scheduled Scans & Asset Management: add an assets table API, schedule recurring scans via Celery Beat, and surface asset history in the dashboard.
