"""SSH Keys API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from keyspider.db.queries import paginate
from keyspider.dependencies import CurrentUser, DbSession
from keyspider.models.access_event import AccessEvent
from keyspider.models.key_location import KeyLocation
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey
from keyspider.schemas.access_event import AccessEventListResponse
from keyspider.schemas.ssh_key import (
    KeyLocationResponse,
    SSHKeyDetail,
    SSHKeyListResponse,
    SSHKeyResponse,
)

router = APIRouter()


@router.get("", response_model=SSHKeyListResponse)
async def list_keys(
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    key_type: str | None = None,
    is_host_key: bool | None = None,
    search: str | None = None,
):
    stmt = select(SSHKey)
    if key_type:
        stmt = stmt.where(SSHKey.key_type == key_type)
    if is_host_key is not None:
        stmt = stmt.where(SSHKey.is_host_key == is_host_key)
    if search:
        stmt = stmt.where(
            SSHKey.fingerprint_sha256.ilike(f"%{search}%")
            | SSHKey.comment.ilike(f"%{search}%")
        )
    stmt = stmt.order_by(SSHKey.created_at.desc())
    items, total = await paginate(db, stmt, offset, limit)
    return SSHKeyListResponse(items=items, total=total, offset=offset, limit=limit)


@router.get("/{key_id}", response_model=SSHKeyDetail)
async def get_key(key_id: int, db: DbSession, user: CurrentUser):
    result = await db.execute(select(SSHKey).where(SSHKey.id == key_id))
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    # Get counts
    loc_count = (await db.execute(
        select(func.count()).where(KeyLocation.ssh_key_id == key_id)
    )).scalar() or 0

    event_count = (await db.execute(
        select(func.count()).where(AccessEvent.ssh_key_id == key_id)
    )).scalar() or 0

    return SSHKeyDetail(
        id=key.id,
        fingerprint_sha256=key.fingerprint_sha256,
        fingerprint_md5=key.fingerprint_md5,
        key_type=key.key_type,
        key_bits=key.key_bits,
        comment=key.comment,
        is_host_key=key.is_host_key,
        first_seen_at=key.first_seen_at,
        created_at=key.created_at,
        public_key_data=key.public_key_data,
        location_count=loc_count,
        event_count=event_count,
    )


@router.get("/{key_id}/locations", response_model=list[KeyLocationResponse])
async def get_key_locations(key_id: int, db: DbSession, user: CurrentUser):
    result = await db.execute(
        select(KeyLocation, Server)
        .join(Server, KeyLocation.server_id == Server.id)
        .where(KeyLocation.ssh_key_id == key_id)
    )
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
        for kl, srv in result.all()
    ]


@router.get("/{key_id}/access-events", response_model=AccessEventListResponse)
async def get_key_events(
    key_id: int,
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    stmt = (
        select(AccessEvent)
        .where(AccessEvent.ssh_key_id == key_id)
        .order_by(AccessEvent.event_time.desc())
    )
    items, total = await paginate(db, stmt, offset, limit)
    return AccessEventListResponse(items=items, total=total, offset=offset, limit=limit)


@router.get("/by-fingerprint/{fingerprint:path}", response_model=SSHKeyResponse)
async def get_key_by_fingerprint(fingerprint: str, db: DbSession, user: CurrentUser):
    result = await db.execute(
        select(SSHKey).where(SSHKey.fingerprint_sha256 == fingerprint)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return key
