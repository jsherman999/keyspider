"""FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from keyspider.api.router import api_router
from keyspider.config import settings
from keyspider.db.session import Base, engine, _is_sqlite

logger = logging.getLogger(__name__)


async def _init_sqlite_db():
    """Create tables and seed admin user for local SQLite development."""
    from sqlalchemy import JSON, String, event
    from sqlalchemy.dialects.postgresql import INET, JSONB

    @event.listens_for(Base.metadata, "before_create")
    def _patch_pg_types(target, connection, **kw):
        if connection.dialect.name == "sqlite":
            for table in target.tables.values():
                for column in table.columns:
                    if isinstance(column.type, INET):
                        column.type = String(45)
                    elif isinstance(column.type, JSONB):
                        column.type = JSON()

    import keyspider.models  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Seed admin user if none exists
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from passlib.hash import bcrypt
    from keyspider.models.user import User

    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin = User(
                username="admin",
                password_hash=bcrypt.hash("admin"),
                display_name="Administrator",
                role="admin",
            )
            session.add(admin)
            await session.commit()
            logger.info("Created default admin user (username: admin, password: admin)")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if _is_sqlite:
        await _init_sqlite_db()
    yield
    await engine.dispose()


app = FastAPI(
    title="Keyspider",
    description="SSH key usage monitoring and tracking",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")


@app.get("/health")
async def health_check():
    return {"status": "ok"}
