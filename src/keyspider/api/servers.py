"""Server API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from keyspider.db.queries import paginate
from keyspider.dependencies import CurrentUser, DbSession, OperatorUser
from keyspider.models.access_event import AccessEvent
from keyspider.models.access_path import AccessPath
from keyspider.models.key_location import KeyLocation
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey
from keyspider.schemas.access_event import AccessEventListResponse, AccessEventResponse, AccessPathResponse
from keyspider.schemas.server import (
    ServerCreate,
    ServerImport,
    ServerListResponse,
    ServerResponse,
    ServerUpdate,
)
from keyspider.schemas.ssh_key import KeyLocationResponse

router = APIRouter()


@router.get("", response_model=ServerListResponse)
async def list_servers(
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: str | None = None,
    os_type: str | None = None,
    is_reachable: bool | None = None,
):
    stmt = select(Server)
    if search:
        stmt = stmt.where(
            Server.hostname.ilike(f"%{search}%") | Server.ip_address.cast(str).ilike(f"%{search}%")
        )
    if os_type:
        stmt = stmt.where(Server.os_type == os_type)
    if is_reachable is not None:
        stmt = stmt.where(Server.is_reachable == is_reachable)

    stmt = stmt.order_by(Server.hostname)
    items, total = await paginate(db, stmt, offset, limit)
    return ServerListResponse(items=items, total=total, offset=offset, limit=limit)


@router.post("", response_model=ServerResponse, status_code=201)
async def create_server(request: ServerCreate, db: DbSession, user: OperatorUser):
    server = Server(**request.model_dump())
    db.add(server)
    await db.commit()
    await db.refresh(server)
    return server


@router.get("/{server_id}", response_model=ServerResponse)
async def get_server(server_id: int, db: DbSession, user: CurrentUser):
    result = await db.execute(select(Server).where(Server.id == server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")
    return server


@router.put("/{server_id}", response_model=ServerResponse)
async def update_server(server_id: int, request: ServerUpdate, db: DbSession, user: OperatorUser):
    result = await db.execute(select(Server).where(Server.id == server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    for field, value in request.model_dump(exclude_unset=True).items():
        setattr(server, field, value)

    await db.commit()
    await db.refresh(server)
    return server


@router.delete("/{server_id}")
async def delete_server(server_id: int, db: DbSession, user: OperatorUser):
    result = await db.execute(select(Server).where(Server.id == server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    await db.delete(server)
    await db.commit()
    return {"message": "Server deleted"}


@router.get("/{server_id}/keys", response_model=list[KeyLocationResponse])
async def get_server_keys(server_id: int, db: DbSession, user: CurrentUser):
    result = await db.execute(
        select(KeyLocation, SSHKey, Server)
        .join(SSHKey, KeyLocation.ssh_key_id == SSHKey.id)
        .join(Server, KeyLocation.server_id == Server.id)
        .where(KeyLocation.server_id == server_id)
    )
    rows = result.all()
    return [
        KeyLocationResponse(
            id=kl.id,
            ssh_key_id=kl.ssh_key_id,
            server_id=kl.server_id,
            file_path=kl.file_path,
            file_type=kl.file_type,
            unix_owner=kl.unix_owner,
            unix_permissions=kl.unix_permissions,
            last_verified_at=kl.last_verified_at,
            server_hostname=srv.hostname,
        )
        for kl, _key, srv in rows
    ]


@router.get("/{server_id}/access-events", response_model=AccessEventListResponse)
async def get_server_events(
    server_id: int,
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    stmt = (
        select(AccessEvent)
        .where(AccessEvent.target_server_id == server_id)
        .order_by(AccessEvent.event_time.desc())
    )
    items, total = await paginate(db, stmt, offset, limit)
    return AccessEventListResponse(items=items, total=total, offset=offset, limit=limit)


@router.get("/{server_id}/access-paths", response_model=list[AccessPathResponse])
async def get_server_paths(server_id: int, db: DbSession, user: CurrentUser):
    result = await db.execute(
        select(AccessPath).where(
            (AccessPath.source_server_id == server_id) | (AccessPath.target_server_id == server_id)
        )
    )
    return result.scalars().all()


@router.post("/import", response_model=list[ServerResponse], status_code=201)
async def import_servers(request: ServerImport, db: DbSession, user: OperatorUser):
    created = []
    for srv in request.servers:
        server = Server(**srv.model_dump())
        db.add(server)
        created.append(server)

    await db.commit()
    for s in created:
        await db.refresh(s)
    return created
