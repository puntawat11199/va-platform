"""
Async SQLAlchemy engine and session factory.

Engine uses asyncpg driver (postgresql+asyncpg://).
Alembic uses the sync psycopg2 URL — handled separately in alembic/env.py.
"""

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from db.models import Base

# ---------------------------------------------------------------------------
# Database URL
# ---------------------------------------------------------------------------

# docker-compose injects DATABASE_URL as postgresql://...
# SQLAlchemy async engine requires the +asyncpg dialect prefix.
_RAW_URL: str = os.getenv(
    "DATABASE_URL",
    "postgresql://va_user:va_dev_password_2024@postgres:5432/va_platform",
)

# Swap scheme in-place so callers don't need to set two env vars.
DATABASE_URL: str = _RAW_URL.replace(
    "postgresql://", "postgresql+asyncpg://", 1
).replace(
    "postgres://", "postgresql+asyncpg://", 1   # handle shorthand postgres:// too
)

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

engine = create_async_engine(
    DATABASE_URL,
    echo=False,          # set True locally to log all SQL
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,  # discard stale connections silently
)

# ---------------------------------------------------------------------------
# Session factory
# ---------------------------------------------------------------------------

async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,  # keep attributes accessible after commit
)

# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Yield a database session for a single request, then close it.
    Usage: db: AsyncSession = Depends(get_db)
    """
    async with async_session_factory() as session:
        yield session
