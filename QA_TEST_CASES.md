# VA Platform — QA Test Cases

**Generated:** 2026-05-18  
**Based on:** process.md (Phase 6 complete)  
**Stack:** FastAPI · Celery · PostgreSQL · Redis · ZAP · Nuclei · Docker Compose · Grafana

---

## 1. API Tests

### 1.1 POST /scan

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| API-001 | Submit valid passive scan | Verify scan is created and queued | Platform running, valid API key | POST /scan with `{"target_url":"http://host.docker.internal:5000/","active_scan":false}` + `X-API-Key` header | HTTP 202, JSON body with `scan_id`, `status: PENDING` | Non-202 status, missing scan_id, no DB row created | Critical |
| API-002 | Submit active scan opt-in | Verify active_scan flag is stored | Platform running, valid API key | POST /scan with `active_scan: true` | HTTP 202, `active_scan: true` in response | Flag not stored; passive scan runs instead | High |
| API-003 | Missing API key | Verify 403 on unauthenticated request | Platform running | POST /scan without `X-API-Key` header | HTTP 403, `{"detail":"Invalid or missing X-API-Key"}` | Request accepted without key | Critical |
| API-004 | Wrong API key | Verify 403 on bad key | Platform running | POST /scan with `X-API-Key: wrongkey` | HTTP 403 | Request accepted with wrong key | Critical |
| API-005 | Invalid URL scheme (ftp://) | Reject non-http/https URL | Platform running, valid API key | POST /scan with `target_url: ftp://example.com` | HTTP 422 with validation error | Scan created for invalid scheme | High |
| API-006 | URL with fragment | Reject URLs containing # | Platform running, valid API key | POST /scan with `target_url: http://example.com/#section` | HTTP 422 | Scan created with fragment URL | Medium |
| API-007 | URL exceeds 2048 chars | Reject oversized URL | Platform running, valid API key | POST /scan with URL of 2049 characters | HTTP 422 | Scan created with oversized URL | Medium |
| API-008 | Body over 64 KB | Reject oversized request body | Platform running, valid API key | POST /scan with `Content-Length: 65537` | HTTP 413, `{"detail":"Request body too large (max 64 KB)"}` | Request processed despite large body | High |
| API-009 | Duplicate target — cancel old scan | New scan supersedes existing RUNNING scan | Active scan in RUNNING state for target | POST /scan for same target_url | HTTP 202 new scan; old scan transitions to FAILED with reason "Superseded"; old Celery task revoked | Two scans run in parallel for same target | Critical |
| API-010 | Missing target_url field | Reject request with no target | Platform running, valid API key | POST /scan with `{}` | HTTP 422 | Scan created with null target | High |
| API-011 | Rate limit on POST /scan | Enforce 10 req/min per IP | Platform running, valid API key | POST /scan 11 times within 1 minute from same IP | First 10 return 202; 11th returns 429 | Rate limit not enforced | Medium |
| API-012 | target_url with no hostname | Reject URL with empty host | Platform running, valid API key | POST /scan with `target_url: http:///path` | HTTP 422 | Scan created with no-hostname URL | High |

---

### 1.2 GET /scan/{scan_id}

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| API-013 | Get existing scan | Retrieve scan by valid UUID | Scan exists in DB | GET /scan/{valid_uuid} with API key | HTTP 200, full scan object with status, timestamps, findings_count | 404 or missing fields | High |
| API-014 | Get non-existent scan | 404 for unknown UUID | Platform running | GET /scan/00000000-0000-0000-0000-000000000000 with API key | HTTP 404 | 500 or wrong scan returned | High |
| API-015 | Get scan with invalid UUID | 422 for malformed path param | Platform running | GET /scan/not-a-uuid with API key | HTTP 422 | 500 from unhandled ValueError | High |
| API-016 | Completed scan has findings | Verify findings returned after scan | Completed scan with vulnerabilities | GET /scan/{completed_scan_id} with API key | `findings_count > 0`, `findings` array populated, `status: COMPLETED` | Empty findings on completed scan | High |
| API-017 | Get scan without API key | Auth enforced on GET | Platform running | GET /scan/{valid_uuid} without X-API-Key | HTTP 403 | Scan data returned without auth | Critical |

---

### 1.3 GET /scans

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| API-018 | List scans default pagination | Return scans newest-first | At least one scan exists | GET /scans with API key | HTTP 200, array of scan objects ordered by created_at DESC | Wrong order, missing fields | Medium |
| API-019 | Pagination limit/offset | Correct page slicing | 5+ scans exist | GET /scans?limit=2&offset=2 | HTTP 200, exactly 2 items, different from first page | Wrong items returned | Medium |
| API-020 | limit=0 rejected | Enforce lower bound | Platform running | GET /scans?limit=0 with API key | HTTP 422 | Results returned for limit=0 | Medium |
| API-021 | limit=9999 rejected | Enforce upper bound (500) | Platform running | GET /scans?limit=9999 with API key | HTTP 422 | All scans returned unbound | Medium |
| API-022 | Negative offset rejected | Enforce offset ≥ 0 | Platform running | GET /scans?offset=-1 with API key | HTTP 422 | DB error or wrong results | Low |

---

### 1.4 GET /vulnerabilities

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| API-023 | Filter by valid severity | Return only matching severity | Completed scan with findings | GET /vulnerabilities?severity=MEDIUM with API key | HTTP 200, all items have `severity: MEDIUM` | Items with other severities returned | High |
| API-024 | Filter by invalid severity | Reject unknown severity values | Platform running | GET /vulnerabilities?severity=CRITICAL'; DROP TABLE-- | HTTP 422 | SQL executed or results returned | Critical |
| API-025 | Filter by valid tool | Return only ZAP or NUCLEI findings | Completed scan with both tools | GET /vulnerabilities?tool=ZAP | HTTP 200, all items have `tool: ZAP` | Nuclei findings mixed in | Medium |
| API-026 | Filter by invalid tool | Reject unknown tool values | Platform running | GET /vulnerabilities?tool=NMAP | HTTP 422 | Results returned for unsupported tool | Medium |
| API-027 | Filter by scan_id | Scope results to one scan | Two completed scans | GET /vulnerabilities?scan_id={uuid} | Only findings from that scan returned | Findings from other scans returned | High |
| API-028 | Filter by invalid scan_id | Reject non-UUID scan_id filter | Platform running | GET /vulnerabilities?scan_id=notauuid | HTTP 422 | DB error or empty results silently | Medium |

---

### 1.5 POST /assets

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| API-029 | Register new asset | Asset created in DB | Platform running, valid API key | POST /assets with `{"url":"http://example.com/"}` | HTTP 201, asset_id returned, domain extracted correctly | 500 or wrong domain | Medium |
| API-030 | Duplicate asset rejected | 409 on duplicate URL | Asset already registered | POST /assets with same URL | HTTP 409 Conflict | Duplicate row created | Medium |
| API-031 | GET /assets lists assets | All assets returned | 3 assets registered | GET /assets with API key | HTTP 200, array with all 3 assets | Assets missing or extra | Medium |
| API-032 | GET /assets/{asset_id} valid | Fetch asset by UUID | Asset exists | GET /assets/{uuid} | HTTP 200, correct asset data | 404 or wrong asset | Medium |
| API-033 | GET /assets/{asset_id} bad UUID | 422 for non-UUID | Platform running | GET /assets/not-a-uuid | HTTP 422 | 500 from ValueError | Medium |

---

## 2. Scan Pipeline Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| PIPE-001 | Full passive scan pipeline | Verify end-to-end ZAP→Nuclei→DB | All containers healthy | POST /scan, poll GET /scan/{id} until terminal | Status transitions: PENDING→RUNNING→COMPLETED; findings_count > 0; DB row with severity breakdown | Stuck in RUNNING; 0 findings; FAILED | Critical |
| PIPE-002 | ZAP executes before Nuclei | Enforce sequential order | Platform running | Submit scan, observe worker logs | Logs show ZAP spider, AJAX spider, passive scan complete before Nuclei starts | Nuclei runs before ZAP finishes | High |
| PIPE-003 | ZAP standard + AJAX spider both run | Both spiders execute | Platform running | Submit scan, check worker logs | Logs show both `starting standard spider` and `starting AJAX spider` | Only one spider runs | Medium |
| PIPE-004 | ZAP report saved to volume | JSON report file created | Platform running | Submit scan, check /reports volume after COMPLETED | `/reports/zap_{scan_id}.json` exists with valid JSON array | File missing or malformed | Medium |
| PIPE-005 | Nuclei report saved to volume | JSONL report file created | Platform running | Submit scan, check /reports volume after COMPLETED | `/reports/nuclei_{scan_id}.jsonl` exists | File missing | Medium |
| PIPE-006 | Findings persist to DB | Vulnerabilities written to DB | Completed scan | Query `SELECT COUNT(*) FROM vulnerabilities WHERE scan_id='{id}'` | Count matches findings_count from API | 0 rows despite COMPLETED status | Critical |
| PIPE-007 | Scan cancellation via new submission | Old scan killed, new one starts | Scan RUNNING for target | POST /scan for same target while first is RUNNING | Old scan → FAILED ("Superseded"); new scan → PENDING then RUNNING; only one ZAP process runs | Both scans run in parallel | Critical |
| PIPE-008 | Worker guard — orphaned retry aborted | Task exits if scan missing from DB | Scan row deleted from DB while task running | Manually DELETE scan row; wait for next retry attempt | Worker logs show "orphaned task discarded"; no ZAP/Nuclei traffic generated | ZAP continues running after scan deleted | High |
| PIPE-009 | Worker guard — completed scan retry skipped | Retry skipped if scan already COMPLETED | Scan is COMPLETED; retry queued | Force-requeue task for COMPLETED scan_id | Worker logs show "retry discarded — scan already COMPLETED"; no scanning starts | Scan runs again after COMPLETED | High |
| PIPE-010 | Retry on transient ZAP failure | Scan retries on ZAP connection error | ZAP temporarily unavailable | Stop ZAP container for 30s then restart; submit scan | Scan retries (up to 3 attempts); COMPLETED after ZAP recovers | Permanently FAILED after one transient error | High |
| PIPE-011 | Max retries exhausted → FAILED | Scan marked FAILED after 3 attempts | ZAP permanently unavailable | Stop ZAP; submit scan; wait | After 3 attempts scan status = FAILED, error field populated | Scan stuck in RUNNING forever | High |
| PIPE-012 | Duplicate findings deduplicated | Same finding not inserted twice | Platform running | Submit two scans for same target; compare vulnerability rows | No duplicate hashes in `vulnerabilities` table across scans | Duplicate rows with same hash | Medium |
| PIPE-013 | ZAP alerts scoped to target | No CDN/browser alerts in results | Platform running | Submit scan, check findings | All findings have target URL matching scan target; no external CDN domains | Firefox/CDN URLs appear in findings | Medium |
| PIPE-014 | Active scan sends attack payloads | Active scan runs when opt-in | Authorised test target | POST /scan with active_scan=true; check worker logs | Log shows "ACTIVE SCAN starting"; ascan.scan() called; more findings than passive | Active scan silently skipped | High |
| PIPE-015 | Status timestamps accurate | started_at / finished_at set correctly | Platform running | Submit scan; poll until COMPLETED; check timestamps | started_at set when RUNNING; finished_at set when COMPLETED; finished_at > started_at | Null timestamps on COMPLETED scan | Medium |

---

## 3. Database Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| DB-001 | Finding deduplication — same hash same scan | Upsert updates last_seen, no duplicate row | Platform running | Insert two identical findings in save_findings(); query DB | One row per hash; `last_seen` updated on second encounter | Two rows with same hash | Critical |
| DB-002 | Finding deduplication — same hash different scans | Cross-scan dedup via hash constraint | Two scans of same target | Run two scans; query `SELECT hash, COUNT(*) FROM vulnerabilities GROUP BY hash HAVING COUNT(*)>1` | No duplicate hashes within the same scan | Cardinality error or duplicate rows | High |
| DB-003 | Cascade delete — scan deletes findings | Vulnerabilities deleted when scan deleted | Scan with findings in DB | `DELETE FROM scans WHERE id='{id}'` | All related vulnerability rows also deleted (CASCADE) | Orphaned vulnerability rows remain | Medium |
| DB-004 | Foreign key — scan_id in vulnerabilities | Cannot insert finding for non-existent scan | Platform running | Attempt INSERT into vulnerabilities with fake scan_id | PostgreSQL raises foreign key violation | Orphaned finding inserted | High |
| DB-005 | scan_summary view accuracy | View returns correct counts per scan | Completed scan with known findings | `SELECT * FROM scan_summary WHERE scan_id='{id}'` | total_findings, medium_count, low_count, info_count match direct COUNT queries | View returns wrong numbers | Medium |
| DB-006 | asset_risk_summary view accuracy | View aggregates correctly across scans | Asset with multiple scans | `SELECT * FROM asset_risk_summary WHERE url='{url}'` | total_scans, total_findings match actual data | View returns stale or wrong data | Medium |
| DB-007 | Persistence after PostgreSQL restart | Data survives DB container restart | Completed scan with findings | `docker restart va_postgres`; query scans and vulnerabilities | All rows still present; no data loss | Data lost after restart (volume issue) | Critical |
| DB-008 | celery_task_id stored on scan | Task ID saved when scan starts | Platform running | Submit scan; query `SELECT celery_task_id FROM scans WHERE id='{id}'` after RUNNING | celery_task_id is a valid UUID string, not NULL | NULL celery_task_id on RUNNING scan | High |
| DB-009 | Migration idempotency | Re-running init.sql is safe | Database already initialised | `docker exec va_postgres psql -U va_user -d va_platform -f /docker-entrypoint-initdb.d/init.sql` | No errors; no duplicate tables/enums | Errors on second run | Low |
| DB-010 | uq_vuln_scan_hash constraint exists | Constraint enforces dedup | Platform running | `SELECT conname FROM pg_constraint WHERE conname='uq_vuln_scan_hash'` | Constraint present | Constraint missing (dedup would silently fail) | Critical |
| DB-011 | Async session isolation | Concurrent DB writes don't interfere | Platform running | Trigger two scans simultaneously; both complete | Both scans have correct independent finding sets | Findings mixed between scans | High |

---

## 4. Security Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| SEC-001 | SSRF via internal metadata URL | Prevent scanning cloud metadata endpoints | Platform running | POST /scan with `target_url: http://169.254.169.254/latest/meta-data/` | Scan submitted (currently no SSRF block) — **document as known gap**; verify no credentials in findings | N/A (gap documented) | High |
| SEC-002 | SSRF via localhost | Scan against localhost accepted (by design for dev) | Platform running | POST /scan with `target_url: http://localhost/` | Scan runs (dev-mode expectation); note for production hardening | — | Info |
| SEC-003 | API key brute force blocked by rate limit | 429 after 10 failed attempts | Platform running | POST /scan with wrong API key 11 times in 1 minute | 11th request returns 429 before auth is even checked | No rate limit on failed auth attempts | High |
| SEC-004 | SQL injection via severity filter | Pattern validation blocks injection | Platform running | GET /vulnerabilities?severity=HIGH' OR '1'='1 | HTTP 422; query never reaches DB | SQL executed; all rows returned | Critical |
| SEC-005 | SQL injection via tool filter | Pattern validation blocks injection | Platform running | GET /vulnerabilities?tool=ZAP'; DELETE FROM vulnerabilities;-- | HTTP 422 | SQL executed | Critical |
| SEC-006 | Command injection via target_url | URL is passed to ZAP/Nuclei as argument | Platform running | POST /scan with `target_url: http://example.com/;rm -rf /` | ZAP/Nuclei treats entire string as URL; no shell execution | Shell command executed | Critical |
| SEC-007 | Oversized JSON body rejected | 413 before body is parsed | Platform running | POST /scan with Content-Length: 100000 | HTTP 413 | Request body parsed; potential DoS | High |
| SEC-008 | Request without Content-Type | Graceful rejection | Platform running | POST /scan without Content-Type header | HTTP 422 (FastAPI rejects unparseable body) | 500 server error | Medium |
| SEC-009 | /docs accessible without API key | Swagger UI publicly available | Platform running | GET /docs without X-API-Key | HTTP 200 (public by design) | 403 (breaks usability) or 500 | Low |
| SEC-010 | /health accessible without API key | Health check is public | Platform running | GET /health without X-API-Key | HTTP 200 `{"status":"ok"}` | 403 (breaks load balancer health checks) | High |
| SEC-011 | Rejected request logged | Auth failures are auditable | Platform running | POST /scan with wrong API key | Worker/backend logs show path + client IP | No log entry for rejected request | Medium |
| SEC-012 | UUID path param rejects path traversal | No ../../ in path param | Platform running | GET /scan/../../etc/passwd | HTTP 422 (UUID validation rejects it) | File read or 500 | High |

---

## 5. Failure & Recovery Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| FAIL-001 | Worker container crash mid-scan | Scan recovers after worker restart | Scan in RUNNING state | `docker stop va_worker` while scan running; `docker start va_worker` | task_acks_late + task_reject_on_worker_lost causes task to re-queue; scan retries up to 3 times; eventually COMPLETED or FAILED | Scan stuck in RUNNING forever | Critical |
| FAIL-002 | Worker crash — orphaned retry guard | Requeued task aborts if scan already terminal | Scan was marked FAILED before worker restarts | `docker restart va_worker` with a FAILED scan in queue | Worker logs show "retry discarded — scan already FAILED"; no scanning | ZAP/Nuclei runs for already-failed scan | High |
| FAIL-003 | Redis restart — task queue survives | Tasks not lost on Redis restart | Scan queued but not yet started | `docker restart va_redis` | Task re-delivered from persistent queue; scan eventually starts | Task lost; scan stuck in PENDING forever | Critical |
| FAIL-004 | PostgreSQL restart mid-scan | Worker reconnects via NullPool | Scan in RUNNING state | `docker restart va_postgres` | Worker creates new DB connection on next DB call (NullPool); scan continues or retries cleanly | Worker crashes with "connection attached to different loop" | Critical |
| FAIL-005 | ZAP unavailable at scan start | Scan retries until ZAP recovers | ZAP container stopped | `docker stop va_zap`; submit scan; `docker start va_zap` after 60s | Scan retries (tenacity: 3 attempts, 5–30s backoff); COMPLETED after ZAP restores | Permanently FAILED before ZAP recovers | High |
| FAIL-006 | ZAP unavailable — max retries exceeded | Scan marked FAILED after 3 attempts | ZAP container stopped permanently | Submit scan with ZAP down | After 3 attempts: status=FAILED, error field has connection error message | Scan stuck in RUNNING; no FAILED transition | High |
| FAIL-007 | Nuclei templates missing | Graceful handling of missing templates | Nuclei templates volume empty | Clear nuclei templates volume; submit scan | Nuclei downloads templates on first run (expected); scan eventually COMPLETED | 500 / scan FAILED with unhandled exception | Medium |
| FAIL-008 | Nuclei container unreachable | Worker handles nuclei exec failure | Nuclei container stopped | `docker stop va_nuclei`; submit scan | ZAP findings still saved; scan FAILED with nuclei error OR retried | No findings saved even though ZAP succeeded | High |
| FAIL-009 | Partial scan — ZAP succeeds, Nuclei fails | ZAP findings preserved | Nuclei crashes mid-run | Kill nuclei process mid-scan | Scan retries; if max retries exceeded → FAILED; ZAP report JSON file still present on volume | ZAP report file deleted on failure | Medium |
| FAIL-010 | Backend restart — in-flight requests | No data corruption on backend restart | Requests being processed | `docker restart va_backend` during active requests | In-flight scans continue in worker (unaffected); new requests served after ~5s restart | DB in inconsistent state after restart | High |
| FAIL-011 | Grafana restart — dashboard persists | Provisioned dashboard survives restart | Grafana running with data | `docker restart va_grafana` | Dashboard present after restart; datasource connected; panels show data | Dashboard gone; datasource disconnected | Medium |
| FAIL-012 | Beat scheduler restart — no duplicate scans | Missed beat tick not replayed | Celery Beat running | `docker restart va_beat` | Next scheduled scan fires on next interval; no backlog of duplicate tasks | Dozens of catch-up scans queued | High |
| FAIL-013 | DB connection pool exhausted | NullPool prevents stale connections | Platform running | Run 10 concurrent scans | All scans complete; no "Future attached to a different loop" errors | asyncpg loop-binding error crashes worker | Critical |
| FAIL-014 | Concurrent scan submission race | Only one scan active per target | Platform running | POST /scan for same target 3 times simultaneously | Only one scan ends up RUNNING; others FAILED as "Superseded" | Two scans run in parallel for same target | High |

---

## Test Execution Quick Reference

### Prerequisites
```bash
# All containers must be healthy
docker ps --format "table {{.Names}}\t{{.Status}}"

# Verify API is up
curl http://localhost:8000/health
```

### Base curl command
```bash
APIKEY="X-API-Key: changeme_api_key_dev_2024"
BASE="http://localhost:8000"
```

### Submit a test scan
```bash
curl -X POST $BASE/scan \
  -H "$APIKEY" -H "Content-Type: application/json" \
  -d '{"target_url":"http://host.docker.internal:5000/","active_scan":false}'
```

### Poll scan status
```bash
curl $BASE/scan/{scan_id} -H "$APIKEY"
```

### Check DB directly
```bash
docker exec va_postgres psql -U va_user -d va_platform \
  -c "SELECT id, status, findings_count FROM scan_summary ORDER BY created_at DESC LIMIT 5;"
```

### Watch worker logs live
```bash
docker logs -f va_worker
```

---

## Severity Legend

| Severity | Meaning |
|----------|---------|
| **Critical** | Data loss, auth bypass, scan running against unintended targets, or security control failure |
| **High** | Feature broken, scan pipeline fails, data not persisted correctly |
| **Medium** | Edge case misbehaviour, minor data integrity issue, UX degraded |
| **Low** | Cosmetic, logging gap, non-blocking inconsistency |
| **Info** | Known gap / accepted risk to document for future hardening |
