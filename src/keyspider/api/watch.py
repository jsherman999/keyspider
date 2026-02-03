"""Watch session API endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from keyspider.db.queries import paginate
from keyspider.dependencies import CurrentUser, DbSession, OperatorUser
from keyspider.models.access_event import AccessEvent
from keyspider.models.server import Server
from keyspider.models.watch_session import WatchSession
from keyspider.schemas.access_event import AccessEventListResponse
from keyspider.schemas.watch import WatchCreate, WatchListResponse, WatchResponse
from keyspider.workers.watch_tasks import start_watcher, stop_watcher

router = APIRouter()


@router.post("", response_model=WatchResponse, status_code=201)
async def create_watch(request: WatchCreate, db: DbSession, user: OperatorUser):
    # Verify server exists
    result = await db.execute(select(Server).where(Server.id == request.server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    # Check for existing active watch on this server
    result = await db.execute(
        select(WatchSession).where(
            WatchSession.server_id == request.server_id,
            WatchSession.status == "active",
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Server is already being watched")

    watch = WatchSession(
        server_id=request.server_id,
        auto_spider=request.auto_spider,
        spider_depth=request.spider_depth,
    )
    db.add(watch)
    await db.commit()
    await db.refresh(watch)

    # Start the watcher task
    start_watcher.delay(watch.id)

    return watch


@router.get("", response_model=WatchListResponse)
async def list_watches(db: DbSession, user: CurrentUser):
    result = await db.execute(
        select(WatchSession).order_by(WatchSession.started_at.desc())
    )
    items = result.scalars().all()
    return WatchListResponse(items=items, total=len(items))


@router.get("/{session_id}", response_model=WatchResponse)
async def get_watch(session_id: int, db: DbSession, user: CurrentUser):
    result = await db.execute(
        select(WatchSession).where(WatchSession.id == session_id)
    )
    watch = result.scalar_one_or_none()
    if not watch:
        raise HTTPException(status_code=404, detail="Watch session not found")
    return watch


@router.post("/{session_id}/stop")
async def stop_watch(session_id: int, db: DbSession, user: OperatorUser):
    result = await db.execute(
        select(WatchSession).where(WatchSession.id == session_id)
    )
    watch = result.scalar_one_or_none()
    if not watch:
        raise HTTPException(status_code=404, detail="Watch session not found")

    stop_watcher.delay(session_id)
    watch.status = "stopped"
    watch.stopped_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "Watch stopped"}


@router.post("/{session_id}/pause")
async def pause_watch(session_id: int, db: DbSession, user: OperatorUser):
    result = await db.execute(
        select(WatchSession).where(WatchSession.id == session_id)
    )
    watch = result.scalar_one_or_none()
    if not watch:
        raise HTTPException(status_code=404, detail="Watch session not found")

    stop_watcher.delay(session_id)
    watch.status = "paused"
    await db.commit()
    return {"message": "Watch paused"}


@router.post("/{session_id}/resume")
async def resume_watch(session_id: int, db: DbSession, user: OperatorUser):
    result = await db.execute(
        select(WatchSession).where(WatchSession.id == session_id)
    )
    watch = result.scalar_one_or_none()
    if not watch:
        raise HTTPException(status_code=404, detail="Watch session not found")

    if watch.status not in ("paused", "stopped", "error"):
        raise HTTPException(status_code=400, detail="Session is not in a resumable state")

    watch.status = "active"
    await db.commit()
    start_watcher.delay(session_id)
    return {"message": "Watch resumed"}


@router.get("/{session_id}/events", response_model=AccessEventListResponse)
async def get_watch_events(
    session_id: int,
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: str | None = None,
):
    result = await db.execute(
        select(WatchSession).where(WatchSession.id == session_id)
    )
    watch = result.scalar_one_or_none()
    if not watch:
        raise HTTPException(status_code=404, detail="Watch session not found")

    stmt = (
        select(AccessEvent)
        .where(
            AccessEvent.target_server_id == watch.server_id,
            AccessEvent.event_time >= watch.started_at,
        )
        .order_by(AccessEvent.event_time.desc())
    )
    if search:
        stmt = stmt.where(
            AccessEvent.username.ilike(f"%{search}%")
            | AccessEvent.source_ip.cast(str).ilike(f"%{search}%")
        )

    items, total = await paginate(db, stmt, offset, limit)
    return AccessEventListResponse(items=items, total=total, offset=offset, limit=limit)
