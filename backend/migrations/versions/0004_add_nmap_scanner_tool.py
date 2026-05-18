"""add NMAP value to scanner_tool enum

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-18
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PostgreSQL requires ALTER TYPE ... ADD VALUE outside a transaction block
    op.execute("ALTER TYPE scanner_tool ADD VALUE IF NOT EXISTS 'NMAP'")


def downgrade() -> None:
    op.execute("ALTER TYPE scanner_tool RENAME VALUE 'NMAP' TO '_NMAP_REMOVED'")
