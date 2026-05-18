"""add unique constraint (scan_id, hash) for vulnerability deduplication

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-15
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_vuln_scan_hash",
        "vulnerabilities",
        ["scan_id", "hash"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_vuln_scan_hash", "vulnerabilities", type_="unique")
