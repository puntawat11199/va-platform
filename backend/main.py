"""
main.py — FastAPI application entry point for the VA Automation Platform.
"""

import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Any

from celery import Celery
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse, JSONResponse, Response
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy.ext.asyncio import AsyncSession

import crud
from db.database import engine, get_db
from db.models import Base

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("va_platform.main")

_celery = Celery(broker=os.getenv("REDIS_URL", "redis://redis:6379/0"))

# API key — set API_KEY in .env; default is dev-only and must be changed in production
API_KEY: str = os.getenv("API_KEY", "changeme_api_key_dev_2024")

# Routes that bypass API key auth (public endpoints)
_PUBLIC_PATHS: frozenset[str] = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

MAX_REQUEST_BODY_BYTES: int = 64 * 1024   # 64 KB — more than enough for any scan/asset JSON payload
MAX_URL_LENGTH: int = 2048

# Rate limiter — keyed by client IP
limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

def _normalise_target(v: str) -> str:
    """
    Accept a bare IP/hostname or a full URL; always return a full http(s):// string.

    Examples:
      "192.168.1.1"        → "http://192.168.1.1"
      "192.168.1.1:8080"   → "http://192.168.1.1:8080"
      "10.0.0.1/admin"     → "http://10.0.0.1/admin"
      "https://example.com/"  → "https://example.com/"  (unchanged)
    """
    v = v.strip()
    if not v:
        raise ValueError("Target must not be empty")
    if len(v) > MAX_URL_LENGTH:
        raise ValueError(f"Target too long (max {MAX_URL_LENGTH} characters)")
    if "#" in v:
        raise ValueError("Target must not contain fragments")
    if "://" not in v:
        v = "http://" + v
    parsed = urlparse(v)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Target must use http or https scheme")
    if not parsed.hostname:
        raise ValueError("Target must have a valid hostname or IP address")
    return v


_VALID_TOOLS = {"ZAP", "NUCLEI", "TESTSSL", "NMAP"}


class ScanRequest(BaseModel):
    target_url: str
    active_scan: bool = False
    tools: list[str] | None = None  # None = run all tools; subset e.g. ["NMAP","NUCLEI"]

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str) -> str:
        return _normalise_target(v)

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        if len(v) == 0:
            raise ValueError("tools list must not be empty — omit the field to run all tools")
        invalid = set(t.upper() for t in v) - _VALID_TOOLS
        if invalid:
            raise ValueError(f"Unknown tools: {sorted(invalid)}. Valid options: {sorted(_VALID_TOOLS)}")
        return [t.upper() for t in v]


class ScanResponse(BaseModel):
    scan_id: str
    target_url: str
    active_scan: bool
    tools: list[str]
    status: str
    created_at: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    target_url: str
    active_scan: bool
    status: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    findings_count: int = 0
    findings: list[dict[str, Any]] = []


class ScanListItem(BaseModel):
    scan_id: str
    target_url: str
    status: str
    findings_count: int
    created_at: str


class VulnerabilityResponse(BaseModel):
    vuln_id: str
    scan_id: str
    tool: str
    severity: str
    title: str
    description: str | None = None
    target: str
    path: str | None = None
    parameter: str | None = None
    evidence: str | None = None
    hash: str
    first_seen: str
    last_seen: str


class AssetRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _normalise_target(v)


class AssetResponse(BaseModel):
    asset_id: str
    domain: str
    url: str
    created_at: str
    updated_at: str


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _vuln_to_response(v) -> VulnerabilityResponse:
    return VulnerabilityResponse(
        vuln_id=str(v.id), scan_id=str(v.scan_id), tool=v.tool.value,
        severity=v.severity.value, title=v.title, description=v.description,
        target=v.target, path=v.path, parameter=v.parameter, evidence=v.evidence,
        hash=v.hash, first_seen=_iso(v.first_seen), last_seen=_iso(v.last_seen),
    )


def _asset_to_response(a) -> AssetResponse:
    return AssetResponse(
        asset_id=str(a.id), domain=a.domain, url=a.url,
        created_at=_iso(a.created_at), updated_at=_iso(a.updated_at),
    )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("VA Platform backend starting up")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    logger.info("VA Platform backend shutting down")
    await engine.dispose()


app = FastAPI(
    title="VA Automation Platform",
    description="Web Vulnerability Assessment Automation Platform — REST API",
    version="0.3.0",
    lifespan=lifespan,
    docs_url=None,   # disabled — replaced by custom /docs below
)


def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi
    schema = get_openapi(title=app.title, version=app.version, description=app.description, routes=app.routes)
    schema.setdefault("components", {})["securitySchemes"] = {
        "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
    }
    schema["security"] = [{"ApiKeyAuth": []}]
    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = _custom_openapi


@app.get("/docs", include_in_schema=False)
async def custom_docs() -> HTMLResponse:
    base = get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="VA Automation Platform — API Docs",
        swagger_ui_parameters={
            "requestSnippetsEnabled": True,
            "requestSnippets": {
                "generators": {
                    "curl_bash":         {"title": "cURL (Linux/Mac)",       "syntax": "bash"},
                    "curl_powershell":   {"title": "cURL (Windows CMD)",     "syntax": "powershell"},
                    "invoke_webrequest": {"title": "Invoke-WebRequest (PS)", "syntax": "powershell"},
                },
                "defaultExpanded": True,
                "languages": None,
            },
        },
    )
    html = base.body.decode("utf-8")

    # Plugin receives `system` so it can read authorized API key from auth state.
    # X-API-Key lives in system.authSelectors.authorized(), not in req.get("headers").
    plugin_fn = """
  function InvokeWebRequestPlugin(system) {
    return {
      fn: {
        requestSnippetGenerator_invoke_webrequest: function(req) {
          var url    = req.get("url");
          var method = (req.get("method") || "GET").toUpperCase();
          var hdrs   = req.get("headers");
          var body   = req.get("body");

          // Collect headers from request object
          var hMap = {};
          if (hdrs && hdrs.size > 0) {
            hdrs.entrySeq().forEach(function(e) { hMap[e[0]] = e[1]; });
          }

          // Pull API key from Swagger UI auth state (set via Authorize button)
          try {
            var authorized = system.authSelectors.authorized();
            if (authorized && authorized.size > 0) {
              authorized.forEach(function(auth) {
                var schema = auth.get("schema");
                if (schema && schema.get("type") === "apiKey" && schema.get("in") === "header") {
                  hMap[schema.get("name")] = auth.get("value");
                }
              });
            }
          } catch(e) {}

          var parts = [];
          parts.push('Invoke-WebRequest -Uri "' + url + '"');
          parts.push("-Method " + method);

          var keys = Object.keys(hMap);
          if (keys.length > 0) {
            var hp = keys.map(function(k) { return '"' + k + '"="' + hMap[k] + '"'; });
            parts.push("-Headers @{" + hp.join("; ") + "}");
          }

          if (body) {
            var b = (typeof body === "string") ? body : JSON.stringify(body, null, 2);
            parts.push("-Body '" + b.replace(/'/g, "''") + "'");
          }
          return parts.join(" `\\n  ");
        }
      }
    };
  }
"""
    # Insert the function definition just before "const ui = SwaggerUIBundle("
    # Inject plugin function definition before the SwaggerUIBundle call
    html = html.replace(
        "const ui = SwaggerUIBundle(",
        plugin_fn + "    const ui = SwaggerUIBundle(",
        1,
    )

    # Inject plugins array into the SwaggerUIBundle config (before presets:)
    html = html.replace(
        "\n    presets: [",
        "\n    plugins: [InvokeWebRequestPlugin],\n    presets: [",
        1,
    )

    return HTMLResponse(html)


app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def limit_request_body(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_BODY_BYTES:
        return JSONResponse(
            status_code=413,
            content={"detail": f"Request body too large (max {MAX_REQUEST_BODY_BYTES // 1024} KB)"},
        )
    return await call_next(request)


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    if request.url.path in _PUBLIC_PATHS:
        return await call_next(request)
    key = request.headers.get("X-API-Key")
    if not key or key != API_KEY:
        logger.warning("Rejected request — invalid or missing X-API-Key | path=%s ip=%s", request.url.path, request.client.host)
        return JSONResponse(status_code=403, content={"detail": "Invalid or missing X-API-Key"})
    return await call_next(request)


# ---------------------------------------------------------------------------
# Routes — Platform
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["Platform"])
@limiter.exempt
async def health_check(request: Request) -> HealthResponse:
    return HealthResponse(status="ok", version=app.version, timestamp=datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Routes — Scans
# ---------------------------------------------------------------------------

@app.post("/scan", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED, tags=["Scans"],
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "All tools — full scan (default)": {
                            "summary": "All tools — full scan (default)",
                            "description": "Runs all 4 scanners in order: nmap → Nuclei → testssl → ZAP. Omit the tools field to run everything.",
                            "value": {
                                "target_url": "https://example.com/",
                                "active_scan": False,
                            },
                        },
                        "Scan a bare IP address": {
                            "summary": "Scan a bare IP address",
                            "description": "Pass a plain IPv4 address (with optional port). http:// is added automatically.",
                            "value": {
                                "target_url": "192.168.1.1",
                                "active_scan": False,
                            },
                        },
                        "Scan IP with non-standard port": {
                            "summary": "Scan IP with non-standard port",
                            "description": "Include :port directly in the target — no scheme needed.",
                            "value": {
                                "target_url": "192.168.1.1:8080",
                                "active_scan": False,
                                "tools": ["NMAP", "NUCLEI"],
                            },
                        },
                        "Single tool — nmap only": {
                            "summary": "Single tool — nmap only (~30s)",
                            "description": "Quick port scan only. Use when you just want to see what ports are open.",
                            "value": {
                                "target_url": "https://example.com/",
                                "active_scan": False,
                                "tools": ["NMAP"],
                            },
                        },
                        "Single tool — Nuclei only": {
                            "summary": "Single tool — Nuclei only (~2 min)",
                            "description": "Check for known CVEs and misconfigurations only.",
                            "value": {
                                "target_url": "https://example.com/",
                                "active_scan": False,
                                "tools": ["NUCLEI"],
                            },
                        },
                        "Single tool — testssl only": {
                            "summary": "Single tool — testssl only (~2 min)",
                            "description": "TLS/SSL audit only. HTTPS targets only — HTTP targets are skipped automatically.",
                            "value": {
                                "target_url": "https://example.com/",
                                "active_scan": False,
                                "tools": ["TESTSSL"],
                            },
                        },
                        "Single tool — ZAP only": {
                            "summary": "Single tool — ZAP only (2–20 min)",
                            "description": "Web application vulnerability scan only (spider + passive analysis).",
                            "value": {
                                "target_url": "https://example.com/",
                                "active_scan": False,
                                "tools": ["ZAP"],
                            },
                        },
                        "ZAP active scan": {
                            "summary": "ZAP active scan — sends attack payloads",
                            "description": "WARNING: Sends real attack payloads. Only use against targets you own or have written permission to test.",
                            "value": {
                                "target_url": "https://example.com/",
                                "active_scan": True,
                                "tools": ["ZAP"],
                            },
                        },
                        "Custom combination — nmap + Nuclei": {
                            "summary": "Custom combination — nmap + Nuclei (~3 min)",
                            "description": "Ports and CVE check only. Faster than a full scan — skips TLS and web crawling.",
                            "value": {
                                "target_url": "https://example.com/",
                                "active_scan": False,
                                "tools": ["NMAP", "NUCLEI"],
                            },
                        },
                    }
                }
            }
        }
    },
)
@limiter.limit("10/minute")
async def submit_scan(request: Request, payload: ScanRequest, db: AsyncSession = Depends(get_db)) -> ScanResponse:
    """
    Submit a new scan job. Returns `scan_id` immediately — poll **GET /scan/{scan_id}** for results.

    `target_url` accepts a full URL **or a bare IP/hostname** — `http://` is added automatically when no scheme is given:
    - `https://example.com/` — full URL (unchanged)
    - `192.168.1.1` → `http://192.168.1.1`
    - `192.168.1.1:8080` → `http://192.168.1.1:8080`

    ---

    **All tools (default)** — omit the `tools` field:
    ```json
    {"target_url": "https://example.com/", "active_scan": false}
    ```
    Runs all 4 scanners in order: **nmap → Nuclei → testssl → ZAP**

    ---

    **Single tool** — pass one item in `tools`:
    ```json
    {"target_url": "https://example.com/", "tools": ["NMAP"]}
    ```

    | Tool | What it scans | Time |
    |------|--------------|------|
    | `NMAP` | Open ports and services | ~30s |
    | `NUCLEI` | Known CVEs and misconfigurations | ~2 min |
    | `TESTSSL` | TLS/SSL weaknesses (HTTPS only) | ~2 min |
    | `ZAP` | Web application vulnerabilities | 2–20 min |

    ---

    **Custom combination** — pass multiple tools:
    ```json
    {"target_url": "https://example.com/", "tools": ["NMAP", "NUCLEI"]}
    ```
    """
    target_str = str(payload.target_url)

    # Cancel any PENDING/RUNNING scan for the same target so the old task
    # stops attacking the target and the worker guard discards stale retries.
    existing = await crud.get_active_scan_for_target(db, target_str)
    if existing:
        if existing.celery_task_id:
            _celery.control.revoke(existing.celery_task_id, terminate=True, signal="SIGTERM")
            logger.info("Cancelled previous task %s for scan_id=%s", existing.celery_task_id, existing.id)
        from db.models import ScanStatus
        await crud.update_scan_status(db, str(existing.id), ScanStatus.FAILED, error="Superseded by new scan submission")
        logger.info("Marked scan_id=%s FAILED (superseded)", existing.id)

    scan_id    = str(uuid.uuid4())
    asset      = await crud.get_or_create_asset(db, target_str)
    scan       = await crud.create_scan(db, scan_id=scan_id, target_url=target_str, active_scan=payload.active_scan, asset_id=str(asset.id))
    tools      = payload.tools or sorted(_VALID_TOOLS)   # None = all tools
    celery_task_id = str(uuid.uuid4())
    _celery.send_task("worker.celery_app.run_scan", args=[scan_id, target_str, payload.active_scan, tools], queue="scans", task_id=celery_task_id)
    await crud.set_scan_task_id(db, scan_id, celery_task_id)
    logger.info("Scan submitted: scan_id=%s task_id=%s target=%s active=%s tools=%s", scan_id, celery_task_id, target_str, payload.active_scan, tools)
    return ScanResponse(scan_id=str(scan.id), target_url=scan.target, active_scan=scan.active_scan, tools=tools, status=scan.status.value, created_at=_iso(scan.created_at))


@app.get("/scan/{scan_id}", response_model=ScanStatusResponse, tags=["Scans"])
@limiter.limit("60/minute")
async def get_scan(request: Request, scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> ScanStatusResponse:
    """Retrieve status and results of a scan by its ID."""
    scan = await crud.get_scan(db, str(scan_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan {scan_id!r} not found")
    return ScanStatusResponse(
        scan_id=str(scan.id), target_url=scan.target, active_scan=scan.active_scan,
        status=scan.status.value, created_at=_iso(scan.created_at),
        started_at=_iso(scan.started_at), finished_at=_iso(scan.finished_at),
        error=scan.error, findings_count=len(scan.vulnerabilities),
        findings=[v.raw for v in scan.vulnerabilities if v.raw is not None],
    )


@app.get("/scan/{scan_id}/report.pdf", tags=["Scans"])
@limiter.limit("10/minute")
async def download_scan_report(request: Request, scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> Response:
    """Download a PDF report for a completed scan."""
    scan = await crud.get_scan(db, str(scan_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan {scan_id!r} not found")

    from pdf_report import generate_scan_pdf
    pdf_bytes = generate_scan_pdf(scan, scan.vulnerabilities)

    filename = f"va_report_{str(scan_id)[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/scan/{scan_id}/cancel", response_model=ScanStatusResponse, tags=["Scans"])
@limiter.limit("30/minute")
async def cancel_scan(request: Request, scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> ScanStatusResponse:
    """
    Cancel a running or pending scan. Keeps the scan record and all findings found so far.
    Use DELETE /scan/{id} if you want to remove the scan entirely.
    """
    scan = await crud.get_scan_status(db, str(scan_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan {scan_id!r} not found")

    from db.models import ScanStatus
    if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is already in terminal state: {scan.status.value}",
        )

    # Revoke Celery task before updating DB
    if scan.celery_task_id:
        _celery.control.revoke(scan.celery_task_id, terminate=True, signal="SIGTERM")
        logger.info("Revoked Celery task %s for cancelled scan_id=%s", scan.celery_task_id, scan_id)

    cancelled = await crud.cancel_scan(db, str(scan_id))

    # Re-fetch with findings for the response
    full = await crud.get_scan(db, str(scan_id))
    logger.info("Cancelled scan_id=%s — findings preserved: %d", scan_id, len(full.vulnerabilities))

    return ScanStatusResponse(
        scan_id=str(full.id), target_url=full.target, active_scan=full.active_scan,
        status=full.status.value, created_at=_iso(full.created_at),
        started_at=_iso(full.started_at), finished_at=_iso(full.finished_at),
        error=full.error, findings_count=len(full.vulnerabilities),
        findings=[v.raw for v in full.vulnerabilities if v.raw is not None],
    )


@app.delete("/scan/{scan_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Scans"])
@limiter.limit("30/minute")
async def delete_scan(request: Request, scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> None:
    """Delete a scan and all its findings. Revokes the Celery task if still running."""
    scan = await crud.get_scan_status(db, str(scan_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan {scan_id!r} not found")

    from db.models import ScanStatus
    if scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING) and scan.celery_task_id:
        _celery.control.revoke(scan.celery_task_id, terminate=True, signal="SIGTERM")
        logger.info("Revoked Celery task %s for deleted scan_id=%s", scan.celery_task_id, scan_id)

    await crud.delete_scan(db, str(scan_id))
    logger.info("Deleted scan_id=%s", scan_id)


@app.get("/scans", response_model=list[ScanListItem], tags=["Scans"])
@limiter.limit("60/minute")
async def list_scans(
    request: Request,
    limit:  Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)]         = 0,
    db: AsyncSession = Depends(get_db),
) -> list[ScanListItem]:
    """List scans newest-first. Use limit/offset for pagination."""
    scans = await crud.list_scans(db, limit=limit, offset=offset)
    return [ScanListItem(scan_id=str(s.id), target_url=s.target, status=s.status.value, findings_count=len(s.vulnerabilities), created_at=_iso(s.created_at)) for s in scans]


# ---------------------------------------------------------------------------
# Routes — Vulnerabilities
# ---------------------------------------------------------------------------

@app.get("/vulnerabilities", response_model=list[VulnerabilityResponse], tags=["Vulnerabilities"])
@limiter.limit("60/minute")
async def list_vulnerabilities(
    request:  Request,
    scan_id:  Annotated[uuid.UUID | None, Query()] = None,
    severity: Annotated[str | None, Query(pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")] = None,
    tool:     Annotated[str | None, Query(pattern="^(ZAP|NUCLEI|TESTSSL|NMAP)$")] = None,
    limit:    Annotated[int, Query(ge=1, le=1000)] = 100,
    offset:   Annotated[int, Query(ge=0)]          = 0,
    db: AsyncSession = Depends(get_db),
) -> list[VulnerabilityResponse]:
    """List vulnerabilities. Filters: scan_id, severity (CRITICAL|HIGH|MEDIUM|LOW|INFO), tool (ZAP|NUCLEI)."""
    vulns = await crud.list_vulnerabilities(
        db,
        scan_id=str(scan_id) if scan_id else None,
        severity=severity, tool=tool, limit=limit, offset=offset,
    )
    return [_vuln_to_response(v) for v in vulns]


@app.get("/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse, tags=["Vulnerabilities"])
@limiter.limit("60/minute")
async def get_vulnerability(request: Request, vuln_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> VulnerabilityResponse:
    """Fetch a single vulnerability by its UUID."""
    vuln = await crud.get_vulnerability(db, str(vuln_id))
    if vuln is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Vulnerability {vuln_id!r} not found")
    return _vuln_to_response(vuln)


# ---------------------------------------------------------------------------
# Routes — Assets
# ---------------------------------------------------------------------------

@app.post("/assets", response_model=AssetResponse, status_code=status.HTTP_201_CREATED, tags=["Assets"])
@limiter.limit("30/minute")
async def create_asset(request: Request, payload: AssetRequest, db: AsyncSession = Depends(get_db)) -> AssetResponse:
    """Register a new asset. Returns 409 if URL already exists."""
    url = str(payload.url)
    if await crud.get_asset_by_url(db, url):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Asset {url!r} already exists")
    asset = await crud.create_asset(db, url)
    logger.info("Asset registered: asset_id=%s url=%s", asset.id, url)
    return _asset_to_response(asset)


@app.get("/assets", response_model=list[AssetResponse], tags=["Assets"])
@limiter.limit("60/minute")
async def list_assets(
    request: Request,
    limit:   Annotated[int, Query(ge=1, le=500)] = 100,
    offset:  Annotated[int, Query(ge=0)]         = 0,
    db: AsyncSession = Depends(get_db),
) -> list[AssetResponse]:
    """List all registered assets, newest first."""
    return [_asset_to_response(a) for a in await crud.list_assets(db, limit=limit, offset=offset)]


@app.get("/assets/{asset_id}", response_model=AssetResponse, tags=["Assets"])
@limiter.limit("60/minute")
async def get_asset(request: Request, asset_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> AssetResponse:
    """Fetch a single asset by its UUID."""
    asset = await crud.get_asset(db, str(asset_id))
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Asset {asset_id!r} not found")
    return _asset_to_response(asset)
