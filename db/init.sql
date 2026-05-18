-- init.sql — VA Automation Platform initial database schema
-- Runs automatically on first postgres container startup via
-- /docker-entrypoint-initdb.d/init.sql
-- Re-running is safe: all statements use IF NOT EXISTS / OR REPLACE.

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";   -- uuid_generate_v4()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";     -- trigram index for text search


-- ---------------------------------------------------------------------------
-- Enum types
-- ---------------------------------------------------------------------------

DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM (
        'PENDING',
        'RUNNING',
        'COMPLETED',
        'FAILED'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE severity_level AS ENUM (
        'CRITICAL',
        'HIGH',
        'MEDIUM',
        'LOW',
        'INFO'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE scanner_tool AS ENUM (
        'ZAP',
        'NUCLEI',
        'TESTSSL',
        'NMAP'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;


-- ---------------------------------------------------------------------------
-- Table: assets
-- Represents a target domain/URL that has been or will be scanned.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS assets (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain      TEXT        NOT NULL,
    url         TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  assets             IS 'Target domains and URLs registered for scanning.';
COMMENT ON COLUMN assets.domain      IS 'Bare domain extracted from the URL (e.g. example.com).';
COMMENT ON COLUMN assets.url         IS 'Canonical root URL of the asset.';

CREATE INDEX IF NOT EXISTS idx_assets_domain     ON assets (domain);
CREATE INDEX IF NOT EXISTS idx_assets_created_at ON assets (created_at DESC);


-- ---------------------------------------------------------------------------
-- Table: scans
-- One row per scan job submitted against an asset.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS scans (
    id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id     UUID        REFERENCES assets (id) ON DELETE SET NULL,
    target       TEXT        NOT NULL,
    status       scan_status NOT NULL DEFAULT 'PENDING',
    active_scan  BOOLEAN     NOT NULL DEFAULT FALSE,
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    error        TEXT,                          -- populated on FAILED status
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE  scans             IS 'Scan jobs submitted to the platform.';
COMMENT ON COLUMN scans.target      IS 'Full URL that was scanned.';
COMMENT ON COLUMN scans.active_scan IS 'True when ZAP active scan was included.';
COMMENT ON COLUMN scans.error       IS 'Error message when status = FAILED.';

CREATE INDEX IF NOT EXISTS idx_scans_asset_id   ON scans (asset_id);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans (status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);


-- ---------------------------------------------------------------------------
-- Table: vulnerabilities
-- Normalised findings from ZAP and Nuclei, deduplicated by SHA-256 hash.
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id     UUID          NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    tool        scanner_tool  NOT NULL,
    severity    severity_level NOT NULL,
    title       TEXT          NOT NULL,
    description TEXT,
    target      TEXT          NOT NULL,
    path        TEXT,
    parameter   TEXT,
    evidence    TEXT,
    -- SHA-256 of (target + title + parameter + evidence) for deduplication
    hash        CHAR(64)      NOT NULL,
    first_seen  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    last_seen   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    -- Raw finding payload from the scanner (preserved for audit)
    raw         JSONB
);

COMMENT ON TABLE  vulnerabilities          IS 'Normalised, deduplicated vulnerability findings.';
COMMENT ON COLUMN vulnerabilities.hash     IS 'SHA-256(target||title||parameter||evidence) — dedup key.';
COMMENT ON COLUMN vulnerabilities.raw      IS 'Original scanner output preserved for audit/re-parsing.';
COMMENT ON COLUMN vulnerabilities.evidence IS 'HTTP response snippet or payload that triggered the finding.';

CREATE INDEX IF NOT EXISTS idx_vuln_scan_id    ON vulnerabilities (scan_id);
CREATE INDEX IF NOT EXISTS idx_vuln_severity   ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vuln_tool       ON vulnerabilities (tool);
CREATE INDEX IF NOT EXISTS idx_vuln_hash       ON vulnerabilities (hash);
CREATE INDEX IF NOT EXISTS idx_vuln_first_seen ON vulnerabilities (first_seen DESC);
-- GIN index enables fast JSONB queries on raw scanner output
CREATE INDEX IF NOT EXISTS idx_vuln_raw        ON vulnerabilities USING GIN (raw);


-- ---------------------------------------------------------------------------
-- View: scan_summary
-- Convenience view used by Grafana dashboard panels.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW scan_summary AS
SELECT
    s.id                                        AS scan_id,
    s.target,
    s.status,
    s.active_scan,
    s.created_at,
    s.started_at,
    s.finished_at,
    EXTRACT(EPOCH FROM (s.finished_at - s.started_at))::INT
                                                AS duration_seconds,
    COUNT(v.id)                                 AS total_findings,
    COUNT(v.id) FILTER (WHERE v.severity = 'CRITICAL') AS critical_count,
    COUNT(v.id) FILTER (WHERE v.severity = 'HIGH')     AS high_count,
    COUNT(v.id) FILTER (WHERE v.severity = 'MEDIUM')   AS medium_count,
    COUNT(v.id) FILTER (WHERE v.severity = 'LOW')      AS low_count,
    COUNT(v.id) FILTER (WHERE v.severity = 'INFO')     AS info_count
FROM scans s
LEFT JOIN vulnerabilities v ON v.scan_id = s.id
GROUP BY s.id;

COMMENT ON VIEW scan_summary IS 'Per-scan finding counts by severity — used by Grafana.';


-- ---------------------------------------------------------------------------
-- View: asset_risk_summary
-- Rolls up vulnerability counts per asset across all scans.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW asset_risk_summary AS
SELECT
    a.id                                            AS asset_id,
    a.domain,
    a.url,
    COUNT(DISTINCT s.id)                            AS total_scans,
    COUNT(v.id)                                     AS total_findings,
    COUNT(v.id) FILTER (WHERE v.severity = 'CRITICAL') AS critical_count,
    COUNT(v.id) FILTER (WHERE v.severity = 'HIGH')     AS high_count,
    MAX(s.created_at)                               AS last_scanned_at
FROM assets a
LEFT JOIN scans s         ON s.asset_id = a.id
LEFT JOIN vulnerabilities v ON v.scan_id = s.id
GROUP BY a.id;

COMMENT ON VIEW asset_risk_summary IS 'Per-asset risk rollup across all scans — used by Grafana.';


-- ---------------------------------------------------------------------------
-- Trigger: auto-update updated_at on assets
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_assets_updated_at ON assets;
CREATE TRIGGER trg_assets_updated_at
    BEFORE UPDATE ON assets
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
