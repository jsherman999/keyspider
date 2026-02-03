"""Common query helpers."""

from __future__ import annotations

from typing import Any, Sequence, TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from keyspider.db.session import Base

T = TypeVar("T", bound=Base)


async def paginate(
    session: AsyncSession,
    stmt: Select,
    offset: int = 0,
    limit: int = 50,
) -> tuple[Sequence[Any], int]:
    """Execute a paginated query, returning (items, total_count)."""
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await session.execute(count_stmt)).scalar() or 0
    result = await session.execute(stmt.offset(offset).limit(limit))
    items = result.scalars().all()
    return items, total


async def get_or_create(
    session: AsyncSession,
    model: type[T],
    defaults: dict[str, Any] | None = None,
    **kwargs: Any,
) -> tuple[T, bool]:
    """Get an existing record or create a new one."""
    stmt = select(model).filter_by(**kwargs)
    result = await session.execute(stmt)
    instance = result.scalar_one_or_none()
    if instance:
        return instance, False
    params = {**kwargs, **(defaults or {})}
    instance = model(**params)
    session.add(instance)
    await session.flush()
    return instance, True
