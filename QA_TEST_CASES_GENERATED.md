# VA Automation Platform — Comprehensive QA Test Cases
**Generated:** 2026-05-19  
**Based on:** process.md Session 4 (Phase 7 COMPLETE + post-launch fixes)  
**Platform:** FastAPI · Celery · PostgreSQL · Redis · ZAP · Nuclei · testssl · nmap · Grafana · Docker Compose

---

## Category 1 — API Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| API-001 | POST /scan — valid HTTP target | Confirm scan job is accepted and queued | Platform running, valid API key | `POST /scan` body `{"target_url":"http://host.docker.internal:5000","active_scan":false}` with header `X-API-Key: changeme_api_key_dev_2024` | HTTP 202, body contains `scan_id`, `status: "PENDING"`, `target_url`, `created_at` | Non-202 status, missing `scan_id`, wrong status | Critical |
| API-002 | POST /scan — valid HTTPS target | Confirm HTTPS target accepted | Platform running | `POST /scan` body `{"target_url":"https://host.docker.internal:8443","active_scan":false}` | HTTP 202, `scan_id` returned, Celery task queued | 4xx/5xx response, no task in Redis | Critical |
| API-003 | POST /scan — active_scan true | Confirm active scan flag passed to worker | Platform running | `POST /scan` body `{"target_url":"http://host.docker.internal:5000","active_scan":true}` | HTTP 202, `active_scan: true` in response | `active_scan` missing or false in response | High |
| API-004 | POST /scan — duplicate target cancels old scan | Old PENDING scan for same target is revoked and marked FAILED | An existing PENDING/RUNNING scan for `http://host.docker.internal:5000` | Submit second `POST /scan` for same target | HTTP 202 for new scan; old scan status becomes `FAILED` with error "Superseded by new scan submission" | Old scan remains PENDING/RUNNING, two concurrent scans attack same target | Critical |
| API-005 | POST /scan — missing target_url | Validation rejects missing required field | Platform running | `POST /scan` body `{}` | HTTP 422 Unprocessable Entity, error describes missing `target_url` | 500 error, scan created with null target | High |
| API-006 | POST /scan — invalid scheme (ftp://) | SSRF prevention — non-HTTP/HTTPS schemes rejected | Platform running | `POST /scan` body `{"target_url":"ftp://example.com"}` | HTTP 422, error "URL must use http or https scheme" | Scan accepted and FTP target scanned | Critical |
| API-007 | POST /scan — URL with fragment (#) | Fragment URLs rejected to prevent parser confusion | Platform running | `POST /scan` body `{"target_url":"http://example.com/page#section"}` | HTTP 422, error "URL must not contain fragments" | Scan accepted with fragment in target | Medium |
| API-008 | POST /scan — URL too long (>2048 chars) | Oversized URL rejected | Platform running | `POST /scan` with `target_url` of 2049 characters | HTTP 422, error referencing max 2048 characters | Scan accepted with oversized URL | Medium |
| API-009 | GET /scan/{scan_id} — valid ID | Retrieve scan status and findings | Scan created via POST /scan | `GET /scan/{scan_id}` with correct API key | HTTP 200, contains `scan_id`, `status`, `findings_count`, `findings` array | 404, wrong scan_id returned | Critical |
| API-010 | GET /scan/{scan_id} — not found | 404 returned for unknown scan ID | Platform running | `GET /scan/00000000-0000-0000-0000-000000000000` | HTTP 404, detail message references the UUID | 500 error, 200 with empty body | High |
| API-011 | GET /scan/{scan_id} — invalid UUID format | Malformed path param rejected | Platform running | `GET /scan/not-a-uuid` | HTTP 422 Unprocessable Entity | 500 internal error | Medium |
| API-012 | GET /scans — default pagination | List scans newest-first | At least one scan in DB | `GET /scans` | HTTP 200, array of scan objects with `scan_id`, `target_url`, `status`, `findings_count`, `created_at`; max 50 items | 500 error, wrong order, missing fields | High |
| API-013 | GET /scans — custom limit/offset | Pagination parameters respected | At least 5 scans in DB | `GET /scans?limit=2&offset=2` | HTTP 200, exactly 2 items, different from offset=0 result | Wrong count, offset ignored | Medium |
| API-014 | GET /scans — limit=0 rejected | ge=1 constraint enforced | Platform running | `GET /scans?limit=0` | HTTP 422 Unprocessable Entity | 500 error, returns all scans | Medium |
| API-015 | GET /scans — limit=501 rejected | le=500 constraint enforced | Platform running | `GET /scans?limit=501` | HTTP 422 Unprocessable Entity | Returns 501 items or 500 error | Medium |
| API-016 | DELETE /scan/{scan_id} — completed scan | Delete scan and all findings | Completed scan in DB | `DELETE /scan/{scan_id}` | HTTP 204 No Content, subsequent GET returns 404, findings removed from DB | 500 error, scan still retrievable after delete | High |
| API-017 | DELETE /scan/{scan_id} — running scan revokes Celery task | Celery task terminated on delete | RUNNING scan with `celery_task_id` | `DELETE /scan/{scan_id}` for running scan | HTTP 204, worker log shows task revoked, scan deleted | Task continues running after delete, orphaned task attacks target | Critical |
| API-018 | DELETE /scan/{scan_id} — not found | 404 for unknown scan | Platform running | `DELETE /scan/00000000-0000-0000-0000-000000000000` | HTTP 404 | 204 with no effect, 500 error | High |
| API-019 | GET /scan/{scan_id}/report.pdf — completed scan | PDF download streams correctly | Completed scan with findings | `GET /scan/{scan_id}/report.pdf` | HTTP 200, `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="va_report_*.pdf"`, non-zero body bytes | 500 error, wrong content type, empty file | High |
| API-020 | GET /scan/{scan_id}/report.pdf — pending scan | PDF generated even for pending scans (0 findings) | Pending scan (just submitted) | `GET /scan/{scan_id}/report.pdf` | HTTP 200, valid PDF with 0 findings in summary | 404, 500, or corrupt PDF | Medium |
| API-021 | GET /scan/{scan_id}/report.pdf — not found | 404 for unknown scan | Platform running | `GET /scan/00000000-0000-0000-0000-000000000000/report.pdf` | HTTP 404 | 500 error, empty PDF returned | High |
| API-022 | GET /vulnerabilities — no filters | List all vulnerabilities | At least one completed scan with findings | `GET /vulnerabilities` | HTTP 200, array with `vuln_id`, `scan_id`, `tool`, `severity`, `title`, `hash`, `first_seen`, `last_seen` | 500 error, missing required fields | High |
| API-023 | GET /vulnerabilities — filter by scan_id | Only findings for specified scan returned | Two completed scans with findings | `GET /vulnerabilities?scan_id={scan_id}` | HTTP 200, all results have matching `scan_id` | Findings from other scans included | High |
| API-024 | GET /vulnerabilities — filter by severity | Severity filter applied correctly | Scan with mixed-severity findings | `GET /vulnerabilities?severity=CRITICAL` | HTTP 200, all results have `severity: "CRITICAL"` | Other severities included | High |
| API-025 | GET /vulnerabilities — filter by tool | Tool filter applied | Scan with ZAP and Nuclei findings | `GET /vulnerabilities?tool=ZAP` | HTTP 200, all results have `tool: "ZAP"` | Nuclei/testssl/nmap results included | Medium |
| API-026 | GET /vulnerabilities — invalid severity value | Pattern validation rejects bad value | Platform running | `GET /vulnerabilities?severity=CRITICAL_PLUS` | HTTP 422 | 200 with unfiltered results | Medium |
| API-027 | GET /vulnerabilities — invalid tool value | Pattern validation rejects unknown tool | Platform running | `GET /vulnerabilities?tool=BURPSUITE` | HTTP 422 | 200 with unfiltered results | Medium |
| API-028 | GET /vulnerabilities/{vuln_id} — valid | Single vulnerability returned | Completed scan with findings | `GET /vulnerabilities/{vuln_id}` | HTTP 200, full vulnerability object with all fields | 404, missing fields | High |
| API-029 | GET /vulnerabilities/{vuln_id} — not found | 404 returned | Platform running | `GET /vulnerabilities/00000000-0000-0000-0000-000000000000` | HTTP 404 | 500 error | High |
| API-030 | POST /assets — valid URL | Asset registered with domain extracted | Platform running | `POST /assets` body `{"url":"http://example.com"}` | HTTP 201, `asset_id`, `domain: "example.com"`, `url`, `created_at`, `updated_at` | 500 error, missing domain | High |
| API-031 | POST /assets — duplicate URL | 409 Conflict returned | Asset already registered | `POST /assets` with same URL | HTTP 409, detail "already exists" | Duplicate asset created, 500 error | Medium |
| API-032 | GET /assets — list all | Assets returned with pagination | At least one asset | `GET /assets` | HTTP 200, array of asset objects | 500 error, missing fields | Medium |
| API-033 | GET /assets/{asset_id} — valid | Single asset returned | Asset in DB | `GET /assets/{asset_id}` | HTTP 200, correct asset fields | 404, wrong asset | Medium |
| API-034 | GET /health — public endpoint | Health check returns OK without auth | Platform running | `GET /health` with no headers | HTTP 200, `{"status":"ok","version":"0.3.0","timestamp":"..."}` | 403, 500, wrong version | High |

---

## Category 2 — Authentication Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| AUTH-001 | Missing X-API-Key header | All protected endpoints reject missing key | Platform running | `POST /scan` with no `X-API-Key` header | HTTP 403, `{"detail":"Invalid or missing X-API-Key"}` | 200/202 accepted without key | Critical |
| AUTH-002 | Wrong X-API-Key value | Invalid key rejected | Platform running | `GET /scans` with `X-API-Key: wrong_key_here` | HTTP 403 | 200, scan data returned to unauthorized caller | Critical |
| AUTH-003 | Empty X-API-Key value | Empty string rejected | Platform running | `GET /scans` with `X-API-Key: ` (empty) | HTTP 403 | 200 returned | Critical |
| AUTH-004 | Public path /health bypasses auth | Health endpoint accessible without key | Platform running | `GET /health` with no API key | HTTP 200 | 403, platform health hidden | Medium |
| AUTH-005 | Public path /docs bypasses auth | Swagger UI accessible without key | Platform running | `GET /docs` with no API key | HTTP 200, Swagger UI HTML | 403 | Low |
| AUTH-006 | Public path /openapi.json bypasses auth | OpenAPI spec accessible without key | Platform running | `GET /openapi.json` with no API key | HTTP 200, JSON schema | 403 | Low |
| AUTH-007 | Correct key accepted | Valid key allows access | Platform running | `GET /scans` with correct `X-API-Key` | HTTP 200 | 403 with correct key | Critical |
| AUTH-008 | Key logged on rejection | Rejected requests logged with IP | Platform running | Send request with wrong key | Worker log: `Rejected request — invalid or missing X-API-Key | path=... ip=...` | No log entry on rejection | Medium |

---

## Category 3 — Input Validation Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| VAL-001 | Oversized request body rejected | 64 KB body size limit enforced | Platform running | Send `POST /scan` with body > 64 KB | HTTP 413, `{"detail":"Request body too large (max 64 KB)"}` | Request processed, 500 error | High |
| VAL-002 | file:// scheme rejected | Local file access prevented | Platform running | `POST /scan` with `target_url: "file:///etc/passwd"` | HTTP 422, scheme validation error | Scan created targeting local file | Critical |
| VAL-003 | javascript:// scheme rejected | Script injection via URL prevented | Platform running | `POST /scan` with `target_url: "javascript:alert(1)"` | HTTP 422 | Scan created with JS scheme | Critical |
| VAL-004 | URL without hostname rejected | Empty host blocked | Platform running | `POST /scan` with `target_url: "http://"` | HTTP 422, "URL must have a valid hostname" | Scan created with null target | High |
| VAL-005 | URL with fragment rejected | Fragment URLs not accepted | Platform running | `POST /scan` with `target_url: "http://example.com#frag"` | HTTP 422, "URL must not contain fragments" | Scan created with fragment | Medium |
| VAL-006 | target_url exceeding 2048 chars rejected | Long URL limit enforced | Platform running | `POST /scan` with URL of 2049 chars | HTTP 422, "URL too long (max 2048 characters)" | Scan accepted | Medium |
| VAL-007 | Invalid JSON body | Malformed JSON rejected | Platform running | `POST /scan` with body `{invalid json}` | HTTP 422 | 500 internal server error | High |
| VAL-008 | severity query param pattern enforced | Only valid severities accepted | Platform running | `GET /vulnerabilities?severity=EXTREME` | HTTP 422 | 200 with unfiltered results | Medium |
| VAL-009 | tool query param pattern enforced | Only valid tool names accepted | Platform running | `GET /vulnerabilities?tool=METASPLOIT` | HTTP 422 | 200 with unfiltered results | Medium |
| VAL-010 | scan_id UUID format enforced in path | Non-UUID scan IDs rejected | Platform running | `GET /scan/../../etc/passwd` | HTTP 422 or 404 | 500 error, path traversal executed | Critical |
| VAL-011 | negative offset rejected | ge=0 constraint enforced | Platform running | `GET /scans?offset=-1` | HTTP 422 | Results returned with negative offset | Low |
| VAL-012 | asset URL validation | Asset URL must be valid HTTP/HTTPS | Platform running | `POST /assets` with `{"url":"not-a-url"}` | HTTP 422 | Asset created with invalid URL | High |
| VAL-013 | XSS payload in URL field stored safely | User-supplied URL data escaped in responses | Platform running | `POST /assets` with URL `http://example.com/<script>alert(1)</script>` | HTTP 422 (invalid URL) or safe string in response | XSS payload executed in Swagger UI or Grafana | Critical |
| VAL-014 | SQL injection in scan target | No raw SQL execution from user input | Platform running | `POST /scan` with `target_url: "http://example.com'; DROP TABLE scans;--"` | HTTP 422 (invalid URL characters) or parameterized query used safely | SQLi causes DB error or table dropped | Critical |

---

## Category 4 — Rate Limiting Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| RATE-001 | POST /scan rate limit 10/min enforced | Burst of 11 scan submissions blocked at 11th | Platform running | Send 11 `POST /scan` requests in <1 minute from same IP | First 10 return 202; 11th returns HTTP 429 | 11th returns 202, no rate limiting | High |
| RATE-002 | GET /scans rate limit 60/min | 61st request in 1 min blocked | Platform running | Send 61 `GET /scans` requests in <1 minute | First 60 return 200; 61st returns HTTP 429 | No rate limiting applied | High |
| RATE-003 | GET /health is rate-limit exempt | Health check never rate-limited | Platform running | Send 200+ `GET /health` requests rapidly | All return HTTP 200 | 429 on health check | High |
| RATE-004 | Rate limit resets after window | After 1 minute, scan submissions allowed again | Rate limit hit on POST /scan | Wait 60 seconds, send 1 more `POST /scan` | HTTP 202 accepted | 429 persists after window | Medium |
| RATE-005 | PDF download rate limit 10/min | 11th PDF request blocked | Platform running | Send 11 `GET /scan/{id}/report.pdf` within 1 minute | First 10 return 200; 11th returns 429 | No rate limit on PDF endpoint | Medium |

---

## Category 5 — Scan Pipeline Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| PIPE-001 | Status transitions PENDING→RUNNING→COMPLETED | Full lifecycle tracked in DB | Target accessible | Submit scan, poll GET /scan/{id} every 10s | Status: PENDING → RUNNING (ZAP starts) → COMPLETED; `started_at` and `finished_at` populated | Status stuck at PENDING, jumps directly to COMPLETED, stuck RUNNING | Critical |
| PIPE-002 | celery_task_id stored after submission | Task ID linkage for revocation | Platform running | Submit scan, check DB `scans` table | `celery_task_id` column non-null within 2 seconds of submit | Null `celery_task_id` prevents task revocation | High |
| PIPE-003 | ZAP runs before Nuclei | Sequential execution order | Target accessible | Check worker logs after scan completes | Log entries: ZAP start → ZAP complete → Nuclei start → Nuclei complete → testssl → nmap → COMPLETED | Out-of-order execution, parallel execution | High |
| PIPE-004 | testssl skipped for HTTP targets | HTTP-only targets skip TLS scan | Platform running | Submit scan of `http://` target, check worker logs | Log: `testssl skipped — target is HTTP-only` | testssl attempts TCP connection to non-HTTPS target | High |
| PIPE-005 | testssl runs for HTTPS targets | TLS scanning triggered for HTTPS | HTTPS test server running | Submit scan of `https://host.docker.internal:8443` | Worker log shows testssl Docker container launched; JSON output file written to `/reports/testssl_{scan_id}.json` | testssl skipped, no file written | High |
| PIPE-006 | nmap runs for every target | Port scan executes regardless of scheme | Platform running | Submit scan, check worker logs | Log: `run_nmap_scan started`, `run_nmap_scan complete` | nmap skipped, no XML written | High |
| PIPE-007 | Duplicate scan cancels previous | Old task revoked, old scan marked FAILED | PENDING scan exists for target | Submit new scan for same target | Old scan `status=FAILED`, `error="Superseded by new scan submission"`; new scan `status=PENDING`; only one Celery task active | Two tasks scanning same target concurrently | Critical |
| PIPE-008 | Worker guard — missing scan record | Worker exits cleanly if scan not in DB | Worker running | Manually send Celery task with nonexistent scan_id | Worker logs `Scan ... not found or already terminal. Aborting.`, no scan attempted | Worker starts scanning nonexistent target | High |
| PIPE-009 | Worker guard — already COMPLETED scan | Worker ignores stale retries | Completed scan in DB | Re-queue old scan_id via Celery | Worker logs abort message, no second scan launched | Target scanned again unnecessarily | High |
| PIPE-010 | Scan FAILED status on ZAP error | Failure correctly propagated | ZAP container stopped | Submit scan while ZAP is down | Scan `status=FAILED`, `error` field populated with exception message | Scan stuck RUNNING, status=COMPLETED with 0 findings silently | High |
| PIPE-011 | findings_count accurate after scan | Count in GET /scan matches actual findings | Completed scan | `GET /scan/{scan_id}` vs `GET /vulnerabilities?scan_id={id}` | `findings_count` == actual count of vulnerability rows | Off-by-one, 0 when findings exist | High |
| PIPE-012 | active_scan=true triggers ZAP active scan | Active scan flag changes ZAP behaviour | Target accepting connections | Submit with `active_scan=true`, monitor ZAP logs | ZAP active scan job launched (log: `Active scan started`, `ascan.status` polled) | Active scan silently skipped | High |
| PIPE-013 | Scan duration calculated correctly | started_at/finished_at difference meaningful | Completed scan | `GET /scan/{scan_id}`, compute `finished_at - started_at` | Duration > 0 seconds, `started_at` < `finished_at` | Identical timestamps, negative duration | Medium |
| PIPE-014 | PDF generated for scan with 0 findings | Empty findings handled gracefully in PDF | Completed scan with 0 findings | `GET /scan/{scan_id}/report.pdf` | HTTP 200, valid PDF, summary shows 0 across all severities | 500 crash, corrupt PDF | Medium |

---

## Category 6 — Database Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| DB-001 | Scan record persisted after POST /scan | DB row created on submission | Platform running | Submit scan, query `SELECT * FROM scans WHERE id='{scan_id}'` | Row exists with correct `target`, `status='PENDING'`, `active_scan`, `created_at` | No row created, wrong status | Critical |
| DB-002 | Vulnerability records persisted after scan | Findings saved to `vulnerabilities` table | Completed scan | `SELECT COUNT(*) FROM vulnerabilities WHERE scan_id='{id}'` | Count > 0 (if target has findings); matches `findings_count` from API | 0 rows despite API showing findings, duplicate rows | Critical |
| DB-003 | Deduplication — same finding not doubled | Hash-based upsert prevents duplicate rows | Completed scan with findings | Run same scan target twice, compare vulnerability counts | Second scan does not double the count; `last_seen` updated on duplicate; `first_seen` unchanged | Duplicate rows with same `hash`, count doubles | High |
| DB-004 | Deduplication — hash updated last_seen | Re-seen findings update `last_seen` | Duplicate scan submitted | After second scan, query `SELECT first_seen, last_seen FROM vulnerabilities WHERE hash='{h}'` | `first_seen` unchanged from first scan; `last_seen` = second scan time | Both timestamps updated, or neither updated | Medium |
| DB-005 | Foreign key — deleting scan cascades to vulnerabilities | Orphaned vulnerability rows prevented | Completed scan with findings | `DELETE /scan/{scan_id}`, then `SELECT * FROM vulnerabilities WHERE scan_id='{id}'` | 0 rows in vulnerabilities; parent scan row gone | Orphaned vulnerability rows remain | High |
| DB-006 | Enum validation — invalid tool rejected | DB rejects unknown scanner_tool value | DB accessible | `INSERT INTO vulnerabilities (tool=...) VALUES ('UNKNOWN_TOOL')` directly | PostgreSQL raises invalid input value for enum error | Row inserted with invalid enum | Medium |
| DB-007 | Migration 0001-0004 idempotent | Migrations safe to re-run | Fresh DB | Run `alembic upgrade head` twice | No errors on second run | Error on re-run, schema corruption | High |
| DB-008 | ALTER TYPE ADD VALUE IF NOT EXISTS safe | Enum extension safe if value already exists | NMAP already in enum | Execute `ALTER TYPE scanner_tool ADD VALUE IF NOT EXISTS 'NMAP'` | No error, no duplicate | Error raised, migration fails | Medium |
| DB-009 | Asset auto-created on scan submit | get_or_create_asset creates asset row | No existing asset for target | Submit scan for new target, query `SELECT * FROM assets WHERE url='{target}'` | Asset row exists with correct `domain` and `url` | No asset row, FK violation | High |
| DB-010 | Asset reused on duplicate target | Same asset not recreated | Asset for target exists | Submit second scan for same target | Single asset row; scan row references same `asset_id` | Duplicate asset rows | Medium |
| DB-011 | DB persistence across container restart | Data survives postgres container restart | Completed scan in DB | `docker restart va_postgres`, then `GET /scan/{scan_id}` | Scan and findings still retrievable | Data lost on restart | Critical |
| DB-012 | celery_task_id updated by set_scan_task_id | Helper stores task ID correctly | Scan in PENDING state | Submit scan, check `SELECT celery_task_id FROM scans WHERE id='{id}'` | Non-null UUID matching Celery task | NULL `celery_task_id`, random value | High |

---

## Category 7 — Scanner-Specific Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| SCAN-001 | ZAP passive scan finds XSS | ZAP detects reflected XSS on `/vuln/xss` | web-test.py running on port 5000 | Submit scan of `http://host.docker.internal:5000`, check ZAP findings | At least 1 finding with `tool=ZAP`, `severity` HIGH or MEDIUM, title containing "XSS" or "Cross Site" | 0 ZAP findings despite vulnerable target | High |
| SCAN-002 | ZAP passive scan finds SQL injection | ZAP detects SQLi on `/vuln/sql` | web-test.py running | Submit scan, check ZAP findings | At least 1 finding related to SQL injection | 0 findings despite clear SQLi endpoint | High |
| SCAN-003 | ZAP AJAX spider crawls all routes | Spider discovers vulnerable lab routes | web-test.py running | Submit scan, check ZAP session after scan | Worker log shows AJAX spider completed; ZAP visited `/vuln/xss`, `/vuln/sql`, `/debug` | Only root `/` page crawled | High |
| SCAN-004 | ZAP active scan flag triggers ascan | Active scan launched when `active_scan=true` | web-test.py running | Submit `active_scan=true`, check ZAP worker logs | Log entry: `Active scan started for ...`, `ascan.status` polled until completion | Active scan silently skipped | High |
| SCAN-005 | Nuclei detects exposed endpoints | Nuclei templates fire on debug/git endpoints | web-test.py running | Submit scan, check `tool=NUCLEI` findings | At least 1 Nuclei finding (exposed debug, config, or default-creds template) | 0 Nuclei findings on vulnerable target | High |
| SCAN-006 | Nuclei output parsed from JSONL | JSONL file read and normalized correctly | Completed scan with Nuclei findings | Check `/reports/nuclei_{scan_id}.jsonl` exists; verify `GET /vulnerabilities?tool=NUCLEI` | File on disk, findings in DB with correct fields | Empty file, parse errors in worker log | High |
| SCAN-007 | testssl detects self-signed certificate | Self-signed cert flagged as CRITICAL | web-test.py running with `--tls` on port 8443 | Submit scan of `https://host.docker.internal:8443` | At least 1 finding `tool=TESTSSL` with `severity=CRITICAL` referencing self-signed cert | 0 testssl findings, CRITICAL cert issue missed | High |
| SCAN-008 | testssl JSON output written to reports volume | Output file accessible to worker | HTTPS scan completed | Check `REPORTS_DIR/testssl_{scan_id}.json` exists from worker container | File present, valid JSON array | File missing, `testssl output file not found` warning in logs | High |
| SCAN-009 | testssl OK findings filtered out | Passing TLS controls not saved as vulnerabilities | Completed HTTPS scan | Check `GET /vulnerabilities?tool=TESTSSL` | No findings with all-green "OK" status; only actionable findings stored | OK findings stored as vulnerabilities | Medium |
| SCAN-010 | nmap port scan finds open ports | Nmap discovers services on target host | web-test.py running on port 5000 | Submit scan, check `tool=NMAP` findings | At least 1 finding `tool=NMAP`, `parameter` contains port number, title "Open TCP port N/service" | 0 nmap findings, port 5000 not discovered | High |
| SCAN-011 | nmap XML output parsed correctly | XML parsing extracts port/service/severity | Completed scan with nmap findings | Check worker log for `run_nmap_scan complete` with finding count > 0 | Findings have `target` (IP), `parameter` (port), `title` matching format | XML parse error, 0 findings despite open ports | High |
| SCAN-012 | nmap uses Docker socket to run container | nmap executes via `docker run` | Docker socket mounted in worker | Check worker logs for `run_nmap_scan started` | Log shows docker command executed; XML file written to `/reports/nmap_{scan_id}.xml` | Permission denied on Docker socket, exit code 126 | Critical |
| SCAN-013 | nmap add-host flag enables host.docker.internal | Worker can resolve host machine from Docker | Worker running as root | Check nmap command built: contains `--add-host host.docker.internal:host-gateway` | Command contains the flag; nmap can reach host | `--add-host` missing, nmap cannot reach target | High |
| SCAN-014 | All 4 scanners save findings with correct tool enum | Tool field matches DB enum | Completed scan | `SELECT DISTINCT tool FROM vulnerabilities` | Contains values from `{ZAP, NUCLEI, TESTSSL, NMAP}` as appropriate | Unknown enum value, DB insert error | High |
| SCAN-015 | Scanner findings normalized to standard fields | All findings have required fields populated | Completed scan | `GET /vulnerabilities` | Every finding has non-null `vuln_id`, `scan_id`, `tool`, `severity`, `title`, `target`, `hash`, `first_seen`, `last_seen` | Null required fields, missing hash | High |

---

## Category 8 — Security Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| SEC-001 | SSRF — localhost target blocked or handled | Scanning localhost does not expose internal services | Platform running | `POST /scan` with `target_url: "http://localhost"` | Either HTTP 422 (if scheme/host validation catches it) OR scan created but scanners target loopback — note: current code does NOT block localhost by hostname; document as known limitation | 500 error, scan crashes | Critical |
| SEC-002 | SSRF — 127.0.0.1 target | Direct IP loopback | Platform running | `POST /scan` with `target_url: "http://127.0.0.1"` | Scan accepted (Pydantic accepts valid IP URLs); document that SSRF filtering at IP level is not implemented — flag as future hardening | Platform crashes scanning own DB/Redis | Critical |
| SEC-003 | SSRF — AWS metadata endpoint | Cloud metadata not scannable | Platform running | `POST /scan` with `target_url: "http://169.254.169.254"` | Scan accepted (no IP-range filtering); scanners time out attempting to reach unreachable address; 0 findings | Metadata returned to attacker via findings | Critical |
| SEC-004 | Command injection via target_url | Shell metacharacters in URL don't execute | Platform running | `POST /scan` with `target_url: "http://example.com; rm -rf /"` | HTTP 422 (Pydantic rejects invalid URL chars) | Shell command executes inside worker container | Critical |
| SEC-005 | Path traversal in scan_id path param | UUID validation prevents traversal | Platform running | `GET /scan/../../../../etc/passwd` | HTTP 422 or 404 — FastAPI UUID type rejects non-UUID path | File read or 500 error | Critical |
| SEC-006 | Request body size limit enforced | 64 KB limit blocks oversized payloads | Platform running | Send POST with `Content-Length: 65537` and body of that size | HTTP 413, body rejected before processing | Request processed despite size limit | High |
| SEC-007 | API key not in response bodies | Key not echoed back to caller | Platform running | Make any valid API request | Response body contains no occurrence of API key value | API key leaked in response JSON | Critical |
| SEC-008 | API key in logs — only rejection logged | Correct API key not logged | Log file or stdout | Make successful request, check logs | Log shows request accepted — key value NOT printed | API key value appears in log output | High |
| SEC-009 | CORS allows all origins (known limitation) | Document current CORS policy | Platform running | Send request with `Origin: https://evil.com` | `Access-Control-Allow-Origin: *` in response (expected — dev config); document as hardening needed for production | CORS blocks legitimate frontend during dev | Low |
| SEC-010 | Docker socket access scoped to worker | Backend container cannot access Docker socket | Platform running | `docker exec va_backend docker ps` | Permission denied — backend has no socket mount | Backend can spawn arbitrary containers | Critical |
| SEC-011 | Nuclei output file not path-traversable | Nuclei report path cannot escape /reports dir | Platform running | Review `nuclei_runner.py` output file path construction | File written to `/reports/nuclei_{uuid}.jsonl` — UUID in filename prevents traversal | Path contains `../` components | High |
| SEC-012 | testssl report path not traversable | testssl JSON confined to /reports | Platform running | Review `testssl_runner.py` output file path | File written to `/reports/testssl_{uuid}.json` | Arbitrary path write | High |
| SEC-013 | ZAP API key required for ZAP internal API | ZAP not accessible without key | ZAP container running | `curl http://localhost:8090/JSON/core/view/version/` (no key) | ZAP returns error/403 | ZAP returns data without API key | High |
| SEC-014 | Grafana behind no auth in dev | Document Grafana auth state | Grafana running | Access `http://localhost:3000` without login | Redirected to login page (admin/admin_dev_2024) | Dashboard accessible without credentials | Medium |

---

## Category 9 — Failure & Recovery Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| FAIL-001 | ZAP unavailable — scan marked FAILED | Worker handles ZAP connection error gracefully | All running except ZAP | `docker stop va_zap`, submit scan | Scan `status=FAILED`, `error` field shows connection error; no crash | Worker crashes, scan stuck RUNNING forever | Critical |
| FAIL-002 | ZAP unavailable — backend still healthy | ZAP down doesn't crash backend | ZAP stopped | `GET /health` | HTTP 200, platform reports healthy | Backend crashes when ZAP is down | High |
| FAIL-003 | Redis restart — pending tasks survive | Celery tasks re-queued after Redis restart | Scan in PENDING state | `docker restart va_redis` | Redis reconnects; Celery retries or worker picks up task | Task lost permanently, scan stuck PENDING | High |
| FAIL-004 | PostgreSQL restart — backend reconnects | DB connection pool re-established | Platform running | `docker restart va_postgres`, wait 15s, then `GET /scans` | HTTP 200 after ~15s (healthcheck recovery) | 500 error persists after DB is healthy | Critical |
| FAIL-005 | Worker crash — scan remains RUNNING (known limitation) | Document orphan scan behaviour | Running scan | `docker kill va_worker` mid-scan | Scan stays `RUNNING` permanently (no timeout mechanism currently); document as known gap | Scan auto-healed after worker restart | Medium |
| FAIL-006 | Worker restart — no double-scan | Worker guard prevents re-running completed scan | Completed scan in DB, worker restarted | `docker restart va_worker` | Worker starts cleanly; no old tasks re-executed (Celery acks messages before crash recovery) | Completed scan runs again | High |
| FAIL-007 | Docker socket unavailable — nmap fails gracefully | Socket missing doesn't crash entire scan | Worker running without socket | Remove socket mount, restart worker, submit scan | Worker logs nmap/testssl error; scan marked FAILED or completes with 0 nmap/testssl findings | Worker process crashes, no findings saved | High |
| FAIL-008 | Corrupted Nuclei JSONL — parse error handled | Bad output doesn't crash worker | Worker running | Manually write invalid JSONL to `/reports/nuclei_{id}.jsonl` before parse step | Worker logs parse error, returns `[]` for Nuclei findings; scan completes with ZAP/testssl/nmap results only | Worker crashes, scan FAILED entirely | High |
| FAIL-009 | Corrupted testssl JSON — parse error handled | Bad JSON output handled gracefully | Worker running | Write `not-valid-json` to testssl output file | Worker logs `failed to parse testssl JSON`, returns `[]`; scan continues | Worker crashes | High |
| FAIL-010 | nmap XML not found — graceful empty result | Missing nmap output handled | Worker running | No nmap XML file (docker run failed silently) | Worker logs `nmap output file not found`, returns `[]`; scan completes | Worker crashes, scan FAILED | High |
| FAIL-011 | Nuclei templates missing on first run | Template download failure handled | Fresh worker with empty templates volume | Start worker with empty nuclei-templates volume | Worker log shows `nuclei -update-templates` running before Celery starts; first scan waits for download | First scan fails with template not found error | Medium |
| FAIL-012 | testssl Docker image not pulled | Image missing causes graceful error | testssl image not cached | Submit HTTPS scan without pre-pulling `drwetter/testssl.sh:3.2` | Docker pulls image automatically on first run (or fails with pull error logged); scan marked FAILED if pull fails | Worker crashes indefinitely | Medium |
| FAIL-013 | PostgreSQL full disk simulation | DB write failure handled | DB accessible | Fill disk (simulation) or disconnect DB mid-scan | Worker logs DB error; scan status update may fail; no silent data loss | Worker crashes without logging error | High |
| FAIL-014 | Beat scheduler restart | Celery Beat reconnects after restart | Beat running | `docker restart va_beat` | Beat reconnects to Redis, resumes scheduled scans | Beat fails to restart, scheduled scans stop | Medium |
| FAIL-015 | Concurrent scans for different targets | Two simultaneous scans don't interfere | Platform running | Submit two scans for different targets simultaneously | Both scans proceed independently; findings correctly attributed to respective scan_ids | Findings cross-contaminated between scans | Critical |

---

## Category 10 — Grafana Dashboard Tests

| Test ID | Test Name | Objective | Preconditions | Steps | Expected Result | Failure Conditions | Severity |
|---------|-----------|-----------|---------------|-------|-----------------|-------------------|----------|
| GRAF-001 | "Findings by Severity" pie chart shows all slices | Wide SQL format returns all severity columns | Completed scan with mixed findings | Open Grafana dashboard, view Findings by Severity panel | Pie chart shows 5 coloured slices (CRITICAL, HIGH, MEDIUM, LOW, INFO) with correct counts | All slices same colour (yellow), single slice only | High |
| GRAF-002 | "Findings by Scanner" pie chart shows all tools | All 4 tool columns returned | Scan with ZAP, Nuclei, testssl, nmap findings | Open Grafana, view Findings by Scanner panel | 4 slices: ZAP, NUCLEI, TESTSSL, NMAP with correct counts | Single colour, missing tools | High |
| GRAF-003 | "Recent Scans" table updates on new scan | New scan appears without dashboard refresh | Grafana open, new scan submitted | Submit scan, wait 30s (Grafana default refresh) | New scan row appears in Recent Scans panel | New scan not visible after 1 minute | High |
| GRAF-004 | Vulnerability Details panel shows findings | Table panel filters by scan | Completed scan with findings | Open Grafana, filter by recent scan | Findings table shows title, tool, severity, target, evidence columns | Empty table despite findings in DB | High |
| GRAF-005 | Grafana datasource connected to PostgreSQL | Provisioned datasource is healthy | Grafana running | Grafana → Configuration → Data Sources → VA Platform PostgreSQL | Status: "Data source connected and labels found" | "unable to connect to server" error | Critical |
| GRAF-006 | Grafana dashboard auto-provisioned | Dashboard loaded without manual import | Fresh Grafana container | Open `http://localhost:3000/dashboards` | "VA Platform" dashboard listed and opens without errors | Dashboard missing, panels show "No data" | High |

---

## Summary Table — Test Count by Category

| Category | Test Count | Critical | High | Medium | Low |
|----------|-----------|----------|------|--------|-----|
| API Tests | 34 | 6 | 18 | 8 | 2 |
| Authentication | 8 | 4 | 2 | 1 | 1 |
| Input Validation | 14 | 5 | 6 | 3 | 0 |
| Rate Limiting | 5 | 0 | 3 | 2 | 0 |
| Pipeline | 14 | 3 | 10 | 1 | 0 |
| Database | 12 | 4 | 6 | 2 | 0 |
| Scanner | 15 | 2 | 11 | 2 | 0 |
| Security | 14 | 7 | 5 | 1 | 1 |
| Failure/Recovery | 15 | 3 | 9 | 3 | 0 |
| Grafana | 6 | 1 | 4 | 1 | 0 |
| **TOTAL** | **137** | **35** | **74** | **24** | **4** |

---

## Quick Test Commands Reference

```powershell
# Set your API key
$KEY = "changeme_api_key_dev_2024"
$BASE = "http://localhost:8000"

# API-001: Submit scan
Invoke-WebRequest -Uri "$BASE/scan" -Method POST -Headers @{"X-API-Key"=$KEY;"Content-Type"="application/json"} -Body '{"target_url":"http://host.docker.internal:5000","active_scan":false}'

# AUTH-001: Missing key
Invoke-WebRequest -Uri "$BASE/scans" -Method GET

# VAL-001: Oversized body
$bigbody = '{"target_url":"http://example.com","padding":"' + ('A' * 70000) + '"}'
Invoke-WebRequest -Uri "$BASE/scan" -Method POST -Headers @{"X-API-Key"=$KEY;"Content-Type"="application/json"} -Body $bigbody

# VAL-002: Invalid scheme
Invoke-WebRequest -Uri "$BASE/scan" -Method POST -Headers @{"X-API-Key"=$KEY;"Content-Type"="application/json"} -Body '{"target_url":"ftp://example.com"}'

# API-010: Not found
Invoke-WebRequest -Uri "$BASE/scan/00000000-0000-0000-0000-000000000000" -Headers @{"X-API-Key"=$KEY}

# DB-011: Check persistence after postgres restart
docker restart va_postgres
Start-Sleep -Seconds 20
Invoke-WebRequest -Uri "$BASE/scans" -Headers @{"X-API-Key"=$KEY}

# FAIL-001: ZAP down test
docker stop va_zap
Invoke-WebRequest -Uri "$BASE/scan" -Method POST -Headers @{"X-API-Key"=$KEY;"Content-Type"="application/json"} -Body '{"target_url":"http://host.docker.internal:5000","active_scan":false}'
# Wait ~2 min then check scan status for FAILED

# Verify DB state directly
docker exec va_postgres psql -U va_user -d va_platform -c "SELECT id, status, error, findings_count FROM scan_summary ORDER BY created_at DESC LIMIT 5;"

# Check worker logs for scanner output
docker logs va_worker --tail=100 | Select-String "testssl|nmap|nuclei|zap"
```

---

*Generated from process.md Session 4 state — 2026-05-19*  
*Update QA_TEST_RESULTS.md with Actual Result / Pass-Fail after each test run.*
