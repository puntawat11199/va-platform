# VA Automation Platform — Installation Guide

This guide covers installing the platform on a fresh machine — both **Windows** (with Docker Desktop) and **Linux** (with Docker Engine). All application services run inside Docker containers, so the host only needs Git and Docker installed.

---

## Table of Contents

1. [What This Platform Does](#1-what-this-platform-does)
2. [Architecture Overview](#2-architecture-overview)
3. [Tool Reference — What Each Service Does](#3-tool-reference)
4. [Prerequisites](#4-prerequisites)
   - [Windows](#windows)
   - [Linux](#linux)
5. [Installation Steps](#5-installation-steps)
6. [Environment Configuration](#6-environment-configuration)
7. [First Boot](#7-first-boot)
8. [Verifying the Installation](#8-verifying-the-installation)
9. [Accessing the Platform](#9-accessing-the-platform)
10. [Submitting Your First Scan](#10-submitting-your-first-scan)
11. [Stopping and Restarting](#11-stopping-and-restarting)
12. [Upgrading / Pulling New Code](#12-upgrading--pulling-new-code)
13. [Troubleshooting](#13-troubleshooting)
14. [Security Notes for Production](#14-security-notes-for-production)

---

## 1. What This Platform Does

The VA (Vulnerability Assessment) Automation Platform is a self-hosted security scanning system. You submit a target URL via a REST API, and the platform automatically runs four scanners against it:

| Scanner | What it finds |
|---------|---------------|
| **OWASP ZAP** | Web application vulnerabilities — XSS, SQLi, CSRF, missing headers, insecure cookies |
| **Nuclei** | Known CVEs, misconfigurations, exposed admin panels, default credentials |
| **testssl.sh** | SSL/TLS weaknesses — weak ciphers, expired certs, HSTS missing, BEAST/HEARTBLEED |
| **nmap** | Open ports — exposed databases, RDP, SSH, admin panels, unexpected services |

All findings are deduplicated, stored in PostgreSQL, and visualised in a Grafana dashboard.

---

## 2. Architecture Overview

```
                          ┌─────────────────────────────────────┐
                          │           Docker Network (va-net)    │
                          │                                      │
  User / CI Pipeline ───► │  FastAPI (port 8000)                 │
                          │       │                              │
                          │       ▼                              │
                          │  Redis (broker) ◄──── Celery Beat    │
                          │       │               (scheduler)    │
                          │       ▼                              │
                          │  Celery Worker                       │
                          │   ├── ZAP runner ──────► ZAP daemon  │
                          │   ├── Nuclei runner ───► Nuclei      │
                          │   ├── testssl runner ──► (docker run)│
                          │   └── nmap runner ─────► (docker run)│
                          │       │                              │
                          │       ▼                              │
                          │  PostgreSQL ◄───────── Grafana       │
                          │                        (port 3000)   │
                          └─────────────────────────────────────┘
```

**Data flow:**
1. You `POST /scan` with a target URL → FastAPI creates a scan record and pushes a job to Redis
2. Celery Worker picks up the job → runs ZAP, Nuclei, testssl.sh, nmap sequentially
3. Findings are normalised and saved to PostgreSQL (duplicates are merged by hash)
4. Grafana reads PostgreSQL directly and shows live dashboards
5. Celery Beat triggers automatic rescans of all registered assets every 24 hours

---

## 3. Tool Reference

### FastAPI (backend)
**Purpose:** The REST API that everything talks to.
- Accepts scan requests, creates scan records, dispatches jobs to Celery
- Provides endpoints for querying scans, vulnerabilities, and assets
- Enforces API key authentication and rate limiting
- Port: `8000`

### PostgreSQL
**Purpose:** Primary persistent storage.
- Stores scan records, vulnerability findings, and registered assets
- Findings are deduplicated by SHA-256 hash — rescanning the same target updates `last_seen` rather than creating duplicates
- Port: `5432`

### Redis
**Purpose:** Message broker and result backend for Celery.
- Holds the task queue — FastAPI writes scan jobs here, Celery reads them
- Stores task results (status, finding counts) for up to 24 hours
- Port: `6379`

### Celery Worker
**Purpose:** Async task runner that executes scans.
- Picks scan jobs from Redis and runs the four scanners in sequence
- Runs with concurrency of 2 — two scans can run simultaneously
- Includes a guard that aborts orphaned retries if a scan was already cancelled or completed

### Celery Beat
**Purpose:** Scheduled task dispatcher.
- Reads all registered assets from the database every 24 hours
- Enqueues a new scan job for each asset automatically (passive scan only — no active attack)

### OWASP ZAP
**Purpose:** Web application vulnerability scanner.
- Runs in daemon mode and exposes a REST API on port 8080 (host: 8090)
- Worker calls ZAP to: spider the target, run an AJAX spider (simulates a browser), run passive analysis, and optionally run an active attack scan
- Detects: XSS, SQL injection, CSRF, missing security headers, insecure cookies, path traversal, and ~100 other web vulnerability classes

### Nuclei
**Purpose:** Template-based vulnerability scanner for known CVEs and misconfigurations.
- Uses a community-maintained template library (50,000+ templates, updated on first start)
- Detects: outdated software versions, exposed config files, default credentials, exposed admin panels, cloud metadata endpoints, and known CVEs
- Much faster than ZAP; complements it by covering known-vulnerability patterns

### testssl.sh
**Purpose:** SSL/TLS configuration analyser.
- Runs as a short-lived Docker container against HTTPS targets
- Detects: weak cipher suites, insecure protocol versions (SSLv2/v3, TLS 1.0/1.1), missing HSTS, certificate expiry, BEAST, POODLE, HEARTBLEED, and other TLS vulnerabilities
- Skips HTTP-only targets automatically

### nmap
**Purpose:** Network port and service scanner.
- Runs as a short-lived Docker container using TCP connect scan (no raw sockets needed)
- Scans the top 100 most common ports and detects running services
- Flags exposed database ports (MySQL, PostgreSQL, Redis, MongoDB, etc.) as HIGH severity
- Flags SSH, RDP, VNC, Telnet, FTP as MEDIUM severity

### Grafana
**Purpose:** Visualisation and dashboard for scan results.
- Connects directly to PostgreSQL and displays live data
- Pre-provisioned dashboard shows: scan history, severity breakdown, vulnerability details table, asset risk summary
- Port: `3000`

---

## 4. Prerequisites

### Windows

#### Required software

| Software | Purpose | Download |
|----------|---------|---------|
| **Docker Desktop** | Runs all containers | https://www.docker.com/products/docker-desktop |
| **Git** | Clone the repository | https://git-scm.com/download/win |

**Docker Desktop setup:**
1. Download and install Docker Desktop for Windows
2. During setup, enable **WSL 2 backend** (recommended) — Docker Desktop will prompt you
3. Start Docker Desktop and wait for the whale icon in the system tray to turn green ("Docker Desktop is running")
4. Open **Settings → Resources → WSL Integration** and enable integration for your WSL distro if you use WSL

**Why WSL 2?** It provides a real Linux kernel, which makes Docker containers run faster and more reliably on Windows. The platform is tested on WSL 2.

#### Verify Docker is working

Open PowerShell or CMD:
```powershell
docker --version        # Docker version 27.x.x
docker compose version  # Docker Compose version v2.x.x
```

---

### Linux

#### Ubuntu / Debian

```bash
# Step 1: Remove any old Docker packages
sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Step 2: Install dependencies for the Docker repo
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# Step 3: Add Docker's official GPG key and repository
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Step 4: Install Docker Engine + Compose plugin
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Step 5: Add your user to the docker group (avoids needing sudo for every command)
# Log out and back in after this for the group change to take effect
sudo usermod -aG docker $USER

# Step 6: Enable Docker to start on boot
sudo systemctl enable docker
sudo systemctl start docker
```

> **Why avoid `apt install docker.io`?**
> The `docker.io` Debian/Ubuntu package installs the Docker daemon (`dockerd`) but does **not** include the `docker` CLI client. The official Docker repository installs both correctly.

#### RHEL / CentOS / Rocky Linux

```bash
sudo dnf install -y yum-utils
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
sudo systemctl enable --now docker
```

#### Verify Docker is working

```bash
docker --version        # Docker version 27.x.x
docker compose version  # Docker Compose version v2.x.x
```

---

## 5. Installation Steps

These steps are the same on both Windows (run in PowerShell) and Linux (run in bash).

### Step 1 — Clone the repository

```bash
# Replace the URL with your actual repo URL
git clone https://github.com/your-org/va-platform.git
cd va-platform
```

**Why:** Gets all application source code, Dockerfiles, configuration, and database schema onto the machine.

### Step 2 — Copy the environment file

**Windows (PowerShell):**
```powershell
Copy-Item .env.example .env
```

**Linux / macOS:**
```bash
cp .env.example .env
```

**Why:** `.env` holds all secrets and configuration. The `.env.example` file contains safe placeholder values for local development. You must create `.env` before Docker Compose can start — it reads from this file.

### Step 3 — Edit the environment file

Open `.env` in any text editor and review the values. For local development the defaults work, but you should change at minimum:

```ini
# Change these before any non-local use:
API_KEY=your_api_key_here        # API key for all requests
ZAP_API_KEY=changeme_zap_dev_2024        # ZAP internal API key
DB_PASSWORD=va_dev_password_2024         # PostgreSQL password
GRAFANA_PASSWORD=admin_dev_2024          # Grafana admin password
```

**Why:** These are the authentication credentials for every service. The defaults are public — anyone who knows them can access your platform. Change them before exposing the service on a network.

### Step 4 — Pull container images

```bash
docker compose pull
```

**Why:** Downloads all base images (PostgreSQL, Redis, ZAP, Nuclei, Grafana) before the first build. This step is optional but makes the next step faster and gives you a clear view of what's being downloaded.

### Step 5 — Build custom images

```bash
docker compose build
```

**Why:** Builds the two custom images — `backend` (FastAPI + Python dependencies) and `worker` (Celery + Nuclei binary + Docker CLI). This step compiles Python packages and downloads the static Docker CLI binary. It takes 3–10 minutes on a fresh machine.

### Step 6 — Start the platform

```bash
docker compose up -d
```

The `-d` flag runs all containers in the background (detached mode).

**Why each service starts in this order:**
1. **PostgreSQL** and **Redis** start first — all other services depend on them being healthy before they connect
2. **ZAP** starts and loads its scanning engine (~60 seconds)
3. **Nuclei** starts and downloads its template library (~2–5 minutes on first boot, subsequent starts are instant)
4. **Backend** and **Worker** start once PostgreSQL and Redis pass their health checks
5. **Grafana** starts and provisions the PostgreSQL datasource and dashboard automatically

---

## 6. Environment Configuration

All configuration lives in `.env`. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `API_KEY` | `your_api_key_here` | Required `X-API-Key` header for all API requests |
| `DB_PASSWORD` | `va_dev_password_2024` | PostgreSQL password |
| `ZAP_API_KEY` | `changeme_zap_dev_2024` | ZAP REST API authentication key |
| `GRAFANA_PASSWORD` | `admin_dev_2024` | Grafana admin password |
| `WORKER_CONCURRENCY` | `2` | Parallel scans per worker |
| `REPORTS_DIR` | `/reports` | Container path for scan output files |

**Generating secure keys (run this to get a random key):**
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

---

## 7. First Boot

On the very first `docker compose up`, several one-time initialisation steps happen automatically:

| What happens | Where | Why |
|---|---|---|
| PostgreSQL runs `db/init.sql` | `va_postgres` container | Creates all tables, enums, views, and indexes |
| Nuclei downloads ~50,000 templates | `va_nuclei` and `va_worker` containers | Required before Nuclei can scan anything |
| Grafana provisions the PostgreSQL datasource | `va_grafana` container | Connects Grafana to the database automatically |
| Grafana provisions the dashboard JSON | `va_grafana` container | Dashboard is available immediately without manual setup |
| FastAPI runs `Base.metadata.create_all` | `va_backend` container | Idempotent safety net — creates any tables init.sql missed |

**First boot takes 3–8 minutes** — mostly waiting for ZAP to fully load (60s) and Nuclei to download templates (2–5 min).

Check progress with:
```bash
docker compose logs -f
```

Press `Ctrl+C` to stop following logs (containers keep running).

---

## 8. Verifying the Installation

Run these checks after `docker compose up -d`. Wait ~3 minutes before expecting all services to be ready.

### Check all containers are running

```bash
docker compose ps
```

Expected output — all services should show `running` or `healthy`:

```
NAME          STATUS          PORTS
va_backend    healthy         0.0.0.0:8000->8000/tcp
va_beat       running
va_grafana    healthy         0.0.0.0:3000->3000/tcp
va_nuclei     running
va_postgres   healthy         127.0.0.1:5432->5432/tcp
va_redis      healthy         127.0.0.1:6379->6379/tcp
va_worker     running
va_zap        healthy         127.0.0.1:8090->8080/tcp
```

> **Note:** PostgreSQL, Redis, and ZAP are bound to `127.0.0.1` (this machine only). API and Grafana are on `0.0.0.0` (LAN-accessible).

### Check the API health endpoint

**Windows:**
```powershell
(Invoke-WebRequest -Uri "http://localhost:8000/health").Content
```

**Linux:**
```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected response:
```json
{
  "status": "ok",
  "version": "0.3.0",
  "timestamp": "2026-05-18T09:00:00.000000+00:00"
}
```

### Check worker is connected

```bash
docker logs va_worker --tail 5
```

Expected output:
```
[INFO] Connected to redis://redis:6379/0
[INFO] va-worker@<hostname> ready.
```

---

## 9. Accessing the Platform

| Service | URL | Credentials |
|---------|-----|-------------|
| **REST API** | http://localhost:8000 | `X-API-Key: <your API_KEY>` header |
| **API Docs (Swagger)** | http://localhost:8000/docs | No auth required to open |
| **ReDoc** | http://localhost:8000/redoc | No auth required |
| **Grafana Dashboard** | http://localhost:3000 | admin / `<your GRAFANA_PASSWORD>` |
| **ZAP API** (debug) | http://localhost:8090 | ZAP_API_KEY in URL |

### Using the Swagger UI (easiest way to test — works on Windows without curl)

1. Open [http://localhost:8000/docs](http://localhost:8000/docs)
2. Click the **Authorize** button (top-right, green padlock icon)
3. Enter your API key (value of `API_KEY` from your `.env`) → click **Authorize** → **Close**
4. Expand any endpoint, click **Try it out** → fill in parameters → **Execute**
5. After executing, the **Snippets** section below the response shows three copy-ready command formats:

| Tab | Use when |
|-----|---------|
| **cURL (Linux/Mac)** | Linux terminal or macOS |
| **cURL (Windows CMD)** | Windows Command Prompt with curl installed |
| **Invoke-WebRequest (PS)** | Windows PowerShell — no curl needed |

---

## 10. Submitting Your First Scan

Replace `<YOUR_API_KEY>` with the value of `API_KEY` in your `.env` file.

> **Tip:** Use the Swagger UI at http://localhost:8000/docs — click **Authorize**, enter your key once, then use **Try it out** on any endpoint. It generates `Invoke-WebRequest` commands automatically.

### Windows (PowerShell)

```powershell
$KEY = "your_api_key_here"   # value from your .env API_KEY
$BASE = "http://localhost:8000"
$headers = @{"X-API-Key" = $KEY; "Content-Type" = "application/json"}

# Submit a passive scan (safe — no attack payloads)
$response = Invoke-WebRequest -Method POST -Uri "$BASE/scan" -Headers $headers `
  -Body '{"target_url": "http://host.docker.internal:5000", "active_scan": false}'
$scan = $response.Content | ConvertFrom-Json
$scanId = $scan.scan_id
Write-Host "Scan ID: $scanId"

# Submit an active scan (sends attack payloads — only use against targets you own)
Invoke-WebRequest -Method POST -Uri "$BASE/scan" -Headers $headers `
  -Body '{"target_url": "http://host.docker.internal:5000", "active_scan": true}'

# Check scan status
Invoke-WebRequest -Uri "$BASE/scan/$scanId" -Headers @{"X-API-Key" = $KEY}

# List all scans
Invoke-WebRequest -Uri "$BASE/scans" -Headers @{"X-API-Key" = $KEY}
```

### Linux

```bash
KEY="your_api_key_here"   # value from your .env API_KEY
BASE="http://localhost:8000"

# Submit a passive scan
curl -s -X POST "$BASE/scan" \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://example.com", "active_scan": false}'

# Check scan status
curl -s "$BASE/scan/<scan_id>" -H "X-API-Key: $KEY"
```

### Polling for results

The scan runs asynchronously. Poll `GET /scan/{scan_id}` until `status` is `COMPLETED` or `FAILED`.

| Scan type | Expected duration |
|-----------|------------------|
| Passive only | 2–5 minutes |
| Active scan | 5–20 minutes depending on app complexity |

### View findings

```powershell
# Windows — all findings for a scan
Invoke-WebRequest -Uri "$BASE/vulnerabilities?scan_id=$scanId" -Headers @{"X-API-Key" = $KEY}

# Only CRITICAL findings
Invoke-WebRequest -Uri "$BASE/vulnerabilities?severity=CRITICAL" -Headers @{"X-API-Key" = $KEY}

# Findings from nmap only
Invoke-WebRequest -Uri "$BASE/vulnerabilities?tool=NMAP" -Headers @{"X-API-Key" = $KEY}
```

```bash
# Linux
curl -s "$BASE/vulnerabilities?scan_id=<scan_id>" -H "X-API-Key: $KEY"
curl -s "$BASE/vulnerabilities?severity=CRITICAL" -H "X-API-Key: $KEY"
```

### Download PDF report

```powershell
# Windows — saves to report.pdf in current directory
Invoke-WebRequest -Uri "$BASE/scan/$scanId/report.pdf" `
  -Headers @{"X-API-Key" = $KEY} `
  -OutFile "report.pdf"
Write-Host "Saved to report.pdf"
```

```bash
# Linux
curl -s "$BASE/scan/<scan_id>/report.pdf" -H "X-API-Key: $KEY" -o report.pdf
```

The PDF contains:
- **Cover page** — target, scan ID, status, duration
- **Executive summary** — finding counts by severity + bar chart + breakdown by scanner
- **Findings table** — all vulnerabilities sorted critical-first with colour coding

### Delete a scan

```powershell
# Windows — also cancels the Celery task if scan is still running
Invoke-WebRequest -Uri "$BASE/scan/$scanId" -Method DELETE -Headers @{"X-API-Key" = $KEY}
# Returns HTTP 204 on success
```

```bash
# Linux
curl -s -X DELETE "$BASE/scan/<scan_id>" -H "X-API-Key: $KEY" -w "%{http_code}"
```

---

## 11. Stopping and Restarting

```bash
# Stop all containers (data is preserved in volumes)
docker compose down

# Stop and delete all data (full reset — use with caution)
docker compose down -v

# Restart a single service
docker restart va_worker
docker restart va_backend

# View logs for a specific service
docker logs va_worker -f      # -f = follow (live tail)
docker logs va_backend -f
docker logs va_zap -f
```

---

## 12. Upgrading / Pulling New Code

```bash
# Pull latest code
git pull

# Rebuild only the images that changed
docker compose build backend worker

# Restart updated services (no downtime on other services)
docker compose up -d --no-deps backend worker

# If database schema changed (new migration), apply it
docker exec va_backend alembic upgrade head
```

**When do you need to rebuild vs. just restart?**

| Change type | Action needed |
|---|---|
| Python code in `backend/` or `worker/` | `docker restart va_backend va_worker` (hot-reload handles it) |
| `scanner/` scripts | `docker restart va_worker` |
| New Python package added to `requirements.txt` | `docker compose build backend` then restart |
| `worker/Dockerfile` changed | `docker compose build worker` then restart |
| Database migration added | `docker exec va_backend alembic upgrade head` |
| `docker-compose.yml` changed | `docker compose up -d` (re-applies changes) |

---

## 13. Troubleshooting

### "Port already in use" on startup

Another process is using one of the required ports. Find and stop it:

**Windows:**
```powershell
netstat -ano | findstr ":8000"   # find PID using port 8000
Stop-Process -Id <PID> -Force
```

**Linux:**
```bash
sudo lsof -i :8000
sudo kill -9 <PID>
```

Or change the host port in `docker-compose.yml` (e.g., `"8001:8000"` to use 8001 on the host).

---

### ZAP container unhealthy / taking too long

ZAP needs ~60 seconds to fully load on first start. Check its logs:
```bash
docker logs va_zap --tail 20
```
If it's still loading, wait another minute. If it shows an error, restart it:
```bash
docker restart va_zap
```

---

### Nuclei "output file not found" warning on first scan

This is expected on the very first scan — Nuclei is downloading ~50,000 templates. The download runs in the background when the container starts. Wait 2–5 minutes after first boot before submitting a scan.

Check if templates are downloaded:
```bash
docker exec va_nuclei ls /root/nuclei-templates | head -5
```

---

### Worker can't connect to Docker socket (testssl/nmap fail with exit code 126)

The worker runs testssl.sh and nmap as short-lived Docker containers via the Docker socket.

**Windows / Docker Desktop:** The socket (`/var/run/docker.sock`) is owned by `root:root` (GID 0). The worker is configured to run as root (`user: "0"` in `docker-compose.yml`) to have access. If you see "permission denied" errors:

```powershell
# Verify worker is running as root
docker exec va_worker id
# Expected: uid=0(root) gid=0(root)

# Restart the worker
docker restart va_worker
```

**Linux (Docker Engine):** The socket is typically owned by the `docker` group (GID 999). If your system uses a different GID:

```bash
# Check the GID of your Docker socket
stat -c '%g' /var/run/docker.sock

# If not 999, either:
# Option A — run worker as root (same as Windows, simplest):
#   Set user: "0" in docker-compose.yml under the worker service

# Option B — keep non-root: update the Dockerfile groupadd line to match your GID:
# && groupadd -g <YOUR_GID> docker-host 2>/dev/null || true \
# then rebuild: docker compose build worker
```

---

### `docker compose` not found (Linux)

You have the old standalone `docker-compose` (v1) instead of the Compose plugin (v2). Either install the plugin (recommended — see Step 4 in [Linux prerequisites](#linux)) or replace `docker compose` with `docker-compose` in all commands.

---

### API returns 403 on every request

You're missing or using the wrong `X-API-Key` header. Check your `.env`:
```bash
cat .env | grep API_KEY
```
The value must match the `X-API-Key` header in your request. The `/health`, `/docs`, and `/redoc` endpoints do not require the key.

---

### Grafana shows "No data" on all panels

1. Check the PostgreSQL datasource: go to **Connections → Data Sources → PostgreSQL** → click **Save & Test**
2. If it fails, verify the credentials in `grafana/provisioning/datasources/postgres.yml` match your `.env`
3. Check that at least one completed scan exists — the panels are empty if no scans have run

---

### Database already exists / schema conflict after `compose down -v`

The `db/init.sql` script is idempotent — all statements use `IF NOT EXISTS` and `OR REPLACE`. It's safe to restart with a fresh volume at any time.

If you're upgrading an existing database without wiping it, run pending migrations instead:
```bash
docker exec va_backend alembic upgrade head
```

---

## 14. Security Notes for Production

The default configuration is designed for local development. Before exposing this platform on any network:

1. **Change all default credentials** in `.env`:
   - `API_KEY` — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`
   - `DB_PASSWORD`
   - `ZAP_API_KEY`
   - `GRAFANA_PASSWORD`

2. **Restrict CORS** — change `CORS_ORIGINS=*` to your specific frontend origin

3. **Dangerous ports are already localhost-only** — PostgreSQL (5432), Redis (6379), and ZAP (8090) are bound to `127.0.0.1` by default and cannot be reached from the network. If you ever need to tighten the API or Grafana as well:
   ```yaml
   ports:
     - "127.0.0.1:8000:8000"   # API reachable from this machine only
     - "127.0.0.1:3000:3000"   # Grafana reachable from this machine only
   ```

4. **Put a reverse proxy in front** (nginx/Caddy) with TLS termination for any non-localhost access

5. **Only scan targets you own** — the active scan option (`active_scan: true`) sends real attack payloads. Scanning systems without written permission is illegal in most jurisdictions.

6. **Remove `--reload` from the backend command** in `docker-compose.yml` for production — hot-reload is a development convenience that adds overhead and attack surface.
