"""add TESTSSL value to scanner_tool enum

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-18
"""
from typing import Sequence, Union

from alembic import op


revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # PostgreSQL requires ALTER TYPE ... ADD VALUE outside a transaction block
    op.execute("ALTER TYPE scanner_tool ADD VALUE IF NOT EXISTS 'TESTSSL'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values; renaming is the safest
    # approach — rename the value to make it inert rather than dropping it.
    op.execute("ALTER TYPE scanner_tool RENAME VALUE 'TESTSSL' TO '_TESTSSL_REMOVED'")
