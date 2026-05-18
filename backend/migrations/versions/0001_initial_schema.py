"""initial schema — assets, scans, vulnerabilities

Revision ID: 0001
Revises:
Create Date: 2026-05-15
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Extensions (idempotent) ---
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm"')

    # --- Enum types ---
    scan_status = postgresql.ENUM(
        "PENDING", "RUNNING", "COMPLETED", "FAILED",
        name="scan_status", create_type=False,
    )
    severity_level = postgresql.ENUM(
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
        name="severity_level", create_type=False,
    )
    scanner_tool = postgresql.ENUM(
        "ZAP", "NUCLEI",
        name="scanner_tool", create_type=False,
    )

    op.execute(
        "DO $$ BEGIN CREATE TYPE scan_status AS ENUM "
        "('PENDING','RUNNING','COMPLETED','FAILED'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    op.execute(
        "DO $$ BEGIN CREATE TYPE severity_level AS ENUM "
        "('CRITICAL','HIGH','MEDIUM','LOW','INFO'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    op.execute(
        "DO $$ BEGIN CREATE TYPE scanner_tool AS ENUM "
        "('ZAP','NUCLEI'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )

    # --- assets ---
    op.create_table(
        "assets",
        sa.Column("id",         postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("domain",     sa.Text,  nullable=False),
        sa.Column("url",        sa.Text,  nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_assets_domain",     "assets", ["domain"])
    op.create_index("idx_assets_created_at", "assets", ["created_at"])

    # updated_at trigger
    op.execute(
        "CREATE OR REPLACE FUNCTION set_updated_at() "
        "RETURNS TRIGGER LANGUAGE plpgsql AS $$ "
        "BEGIN NEW.updated_at = NOW(); RETURN NEW; END; $$"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_assets_updated_at ON assets; "
        "CREATE TRIGGER trg_assets_updated_at "
        "BEFORE UPDATE ON assets "
        "FOR EACH ROW EXECUTE FUNCTION set_updated_at()"
    )

    # --- scans ---
    op.create_table(
        "scans",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("asset_id",    postgresql.UUID(as_uuid=True), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("target",      sa.Text, nullable=False),
        sa.Column("status",      sa.Enum("PENDING", "RUNNING", "COMPLETED", "FAILED", name="scan_status", create_type=False), nullable=False, server_default="PENDING"),
        sa.Column("active_scan", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("started_at",  sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error",       sa.Text, nullable=True),
        sa.Column("created_at",  sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("idx_scans_asset_id",   "scans", ["asset_id"])
    op.create_index("idx_scans_status",     "scans", ["status"])
    op.create_index("idx_scans_created_at", "scans", ["created_at"])

    # --- vulnerabilities ---
    op.create_table(
        "vulnerabilities",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuid_generate_v4()")),
        sa.Column("scan_id",     postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool",        sa.Enum("ZAP", "NUCLEI", name="scanner_tool", create_type=False), nullable=False),
        sa.Column("severity",    sa.Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", name="severity_level", create_type=False), nullable=False),
        sa.Column("title",       sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("target",      sa.Text, nullable=False),
        sa.Column("path",        sa.Text, nullable=True),
        sa.Column("parameter",   sa.Text, nullable=True),
        sa.Column("evidence",    sa.Text, nullable=True),
        sa.Column("hash",        sa.String(64), nullable=False),
        sa.Column("first_seen",  sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("last_seen",   sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("raw",         postgresql.JSONB, nullable=True),
    )
    op.create_index("idx_vuln_scan_id",    "vulnerabilities", ["scan_id"])
    op.create_index("idx_vuln_severity",   "vulnerabilities", ["severity"])
    op.create_index("idx_vuln_tool",       "vulnerabilities", ["tool"])
    op.create_index("idx_vuln_hash",       "vulnerabilities", ["hash"])
    op.create_index("idx_vuln_first_seen", "vulnerabilities", ["first_seen"])
    # GIN index for JSONB — cannot use op.create_index for this dialect option
    op.execute("CREATE INDEX IF NOT EXISTS idx_vuln_raw ON vulnerabilities USING GIN (raw)")


def downgrade() -> None:
    op.drop_table("vulnerabilities")
    op.drop_table("scans")
    op.drop_table("assets")
    op.execute("DROP TYPE IF EXISTS scanner_tool")
    op.execute("DROP TYPE IF EXISTS severity_level")
    op.execute("DROP TYPE IF EXISTS scan_status")
