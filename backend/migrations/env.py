"""
Alembic env.py — runs migrations using the sync psycopg2 driver.
DATABASE_URL env var is read at runtime so the same image works in any env.
"""

import os
import re
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from db.models import Base

# ---------------------------------------------------------------------------
# Alembic config object
# ---------------------------------------------------------------------------
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# Resolve sync DATABASE_URL (strip +asyncpg if present)
# ---------------------------------------------------------------------------
def _sync_url() -> str:
    url = os.getenv(
        "DATABASE_URL",
        "postgresql://va_user:va_dev_password_2024@postgres:5432/va_platform",
    )
    # Strip async driver prefix so psycopg2 is used for migrations
    url = re.sub(r"^postgresql\+asyncpg://", "postgresql://", url)
    url = re.sub(r"^postgres://",            "postgresql://", url)
    return url


# ---------------------------------------------------------------------------
# Offline mode — generate SQL script without a live DB connection
# ---------------------------------------------------------------------------
def run_migrations_offline() -> None:
    context.configure(
        url=_sync_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online mode — run against a live DB connection
# ---------------------------------------------------------------------------
def run_migrations_online() -> None:
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _sync_url()

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
