"""Test fixtures and configuration."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import String, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from keyspider.db.session import Base

# Use an in-memory SQLite database for tests
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# Make PostgreSQL-specific types work with SQLite for testing
from sqlalchemy import JSON
from sqlalchemy.dialects.postgresql import INET, JSONB


@event.listens_for(Base.metadata, "before_create")
def _patch_pg_types_for_sqlite(target, connection, **kw):
    """Replace PostgreSQL-specific column types with SQLite-compatible ones."""
    if connection.dialect.name == "sqlite":
        for table in target.tables.values():
            for column in table.columns:
                if isinstance(column.type, INET):
                    column.type = String(45)
                elif isinstance(column.type, JSONB):
                    column.type = JSON()


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def db_session():
    """Create a test database session."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    # Import all models to register them
    import keyspider.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
def sample_auth_log_debian():
    return (FIXTURES_DIR / "sample_auth_log_debian.txt").read_text()


@pytest.fixture
def sample_auth_log_rhel():
    return (FIXTURES_DIR / "sample_auth_log_rhel.txt").read_text()


@pytest.fixture
def sample_syslog_aix():
    return (FIXTURES_DIR / "sample_syslog_aix.txt").read_text()
