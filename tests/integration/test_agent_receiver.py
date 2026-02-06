"""Integration tests for the agent receiver API endpoints."""

import hashlib
import secrets

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import JSON, String
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from keyspider.main import app
from keyspider.dependencies import get_db
from keyspider.db.session import Base
from keyspider.models.agent_status import AgentStatus
from keyspider.models.server import Server


@pytest.mark.asyncio
async def test_heartbeat_valid_token():
    """Test heartbeat endpoint with valid agent token."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    import keyspider.models  # noqa: F401

    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, INET):
                column.type = String(45)
            elif isinstance(column.type, JSONB):
                column.type = JSON()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    async with session_factory() as session:
        server = Server(hostname="recv-test", ip_address="10.0.0.1", ssh_port=22, os_type="linux")
        session.add(server)
        await session.flush()

        agent = AgentStatus(
            server_id=server.id,
            deployment_status="active",
            agent_token_hash=token_hash,
            agent_version="1.0.0",
        )
        session.add(agent)
        await session.commit()
        server_id = server.id

    async def _override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/agent/heartbeat",
                json={"server_id": server_id, "agent_version": "1.0.0"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            assert response.json()["status"] == "ok"
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()


@pytest.mark.asyncio
async def test_heartbeat_invalid_token():
    """Test heartbeat endpoint with invalid token returns 401."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    import keyspider.models  # noqa: F401

    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, INET):
                column.type = String(45)
            elif isinstance(column.type, JSONB):
                column.type = JSON()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/agent/heartbeat",
                json={"server_id": 1, "agent_version": "1.0.0"},
                headers={"Authorization": "Bearer invalid-token"},
            )
            assert response.status_code == 401
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()


@pytest.mark.asyncio
async def test_heartbeat_missing_token():
    """Test heartbeat endpoint with missing token returns 401."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/agent/heartbeat",
            json={"server_id": 1, "agent_version": "1.0.0"},
        )
        assert response.status_code == 401
