"""add CANCELLED value to scan_status enum

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-25
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PostgreSQL requires ALTER TYPE ... ADD VALUE outside a transaction block
    op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'CANCELLED'")


def downgrade() -> None:
    op.execute("ALTER TYPE scan_status RENAME VALUE 'CANCELLED' TO '_CANCELLED_REMOVED'")
