"""Integration tests for the API endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from keyspider.main import app
from keyspider.dependencies import get_db
from keyspider.db.session import Base


async def _override_get_db():
    """Provide a SQLite test database session for API tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    # Apply INET -> String fix for SQLite
    from sqlalchemy import String
    from sqlalchemy.dialects.postgresql import INET
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, INET):
                column.type = String(45)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_health_check():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_login_required():
    """Verify that API endpoints require authentication."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/servers")
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_invalid_credentials():
    app.dependency_overrides[get_db] = _override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/auth/login", json={
                "username": "nonexistent",
                "password": "wrong",
            })
            assert response.status_code == 401
    finally:
        app.dependency_overrides.clear()
