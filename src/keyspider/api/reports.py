"""Reports and alerts API endpoints."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import func, select

from keyspider.db.queries import paginate
from keyspider.dependencies import CurrentUser, DbSession, OperatorUser
from keyspider.models.access_event import AccessEvent
from keyspider.models.access_path import AccessPath
from keyspider.models.key_location import KeyLocation
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey
from keyspider.models.unreachable_source import UnreachableSource
from keyspider.models.watch_session import WatchSession
from keyspider.schemas.report import (
    AlertAcknowledge,
    AlertNotes,
    DormantKeyItem,
    KeyExposureItem,
    MysteryKeyItem,
    StaleKeyItem,
    SummaryReport,
    UnreachableListResponse,
    UnreachableSourceResponse,
)

router = APIRouter()


@router.get("/unreachable", response_model=UnreachableListResponse)
async def get_unreachable_sources(
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: str | None = None,
    acknowledged: bool | None = None,
):
    stmt = select(UnreachableSource).order_by(
        UnreachableSource.severity, UnreachableSource.last_seen_at.desc()
    )
    if severity:
        stmt = stmt.where(UnreachableSource.severity == severity)
    if acknowledged is not None:
        stmt = stmt.where(UnreachableSource.acknowledged == acknowledged)

    items, total = await paginate(db, stmt, offset, limit)
    return UnreachableListResponse(items=items, total=total, offset=offset, limit=limit)


@router.get("/key-exposure", response_model=list[KeyExposureItem])
async def get_key_exposure(db: DbSession, user: CurrentUser):
    """Keys found on multiple servers."""
    stmt = (
        select(
            SSHKey.id,
            SSHKey.fingerprint_sha256,
            SSHKey.key_type,
            SSHKey.comment,
            func.count(func.distinct(KeyLocation.server_id)).label("server_count"),
        )
        .join(KeyLocation, SSHKey.id == KeyLocation.ssh_key_id)
        .group_by(SSHKey.id)
        .having(func.count(func.distinct(KeyLocation.server_id)) > 1)
        .order_by(func.count(func.distinct(KeyLocation.server_id)).desc())
    )
    result = await db.execute(stmt)
    rows = result.all()

    items = []
    for row in rows:
        # Get server hostnames
        srv_result = await db.execute(
            select(Server.hostname)
            .join(KeyLocation, Server.id == KeyLocation.server_id)
            .where(KeyLocation.ssh_key_id == row.id)
            .distinct()
        )
        servers = [s for (s,) in srv_result.all()]

        items.append(KeyExposureItem(
            ssh_key_id=row.id,
            fingerprint_sha256=row.fingerprint_sha256,
            key_type=row.key_type,
            comment=row.comment,
            server_count=row.server_count,
            servers=servers,
        ))

    return items


@router.get("/dormant-keys", response_model=list[DormantKeyItem])
async def get_dormant_keys(db: DbSession, user: CurrentUser):
    """Keys in authorized_keys that have never been seen in logs."""
    # Get all authorized key locations
    stmt = (
        select(KeyLocation, SSHKey, Server)
        .join(SSHKey, KeyLocation.ssh_key_id == SSHKey.id)
        .join(Server, KeyLocation.server_id == Server.id)
        .where(KeyLocation.file_type == "authorized_keys")
    )
    result = await db.execute(stmt)
    rows = result.all()

    now = datetime.now(timezone.utc)
    items = []
    for kl, key, server in rows:
        # Check if this key has any accepted events on this server
        event_result = await db.execute(
            select(func.count(AccessEvent.id)).where(
                AccessEvent.target_server_id == server.id,
                AccessEvent.ssh_key_id == key.id,
                AccessEvent.event_type == "accepted",
            )
        )
        event_count = event_result.scalar() or 0
        if event_count == 0:
            items.append(DormantKeyItem(
                ssh_key_id=key.id,
                fingerprint_sha256=key.fingerprint_sha256,
                key_type=key.key_type,
                comment=key.comment,
                server_id=server.id,
                server_hostname=server.hostname,
                file_path=kl.file_path,
                first_seen_at=key.first_seen_at,
                days_since_first_seen=(now - key.first_seen_at).days,
            ))

    items.sort(key=lambda x: x.days_since_first_seen, reverse=True)
    return items


@router.get("/mystery-keys", response_model=list[MysteryKeyItem])
async def get_mystery_keys(db: DbSession, user: CurrentUser):
    """Keys seen in auth logs but not found in any authorized_keys file."""
    # Get fingerprints seen in accepted events
    used_fps = await db.execute(
        select(
            AccessEvent.fingerprint,
            AccessEvent.source_ip,
            AccessEvent.username,
            AccessEvent.target_server_id,
            func.count(AccessEvent.id).label("event_count"),
            func.max(AccessEvent.event_time).label("last_seen"),
        )
        .where(
            AccessEvent.event_type == "accepted",
            AccessEvent.fingerprint.isnot(None),
        )
        .group_by(
            AccessEvent.fingerprint,
            AccessEvent.source_ip,
            AccessEvent.username,
            AccessEvent.target_server_id,
        )
    )
    rows = used_fps.all()

    # Get all fingerprints in authorized_keys
    auth_fps_result = await db.execute(
        select(SSHKey.fingerprint_sha256)
        .join(KeyLocation, SSHKey.id == KeyLocation.ssh_key_id)
        .where(KeyLocation.file_type == "authorized_keys")
        .distinct()
    )
    authorized_fps = {row[0] for row in auth_fps_result.all()}

    items = []
    for row in rows:
        if row.fingerprint not in authorized_fps:
            # Get server hostname
            srv_result = await db.execute(
                select(Server.hostname).where(Server.id == row.target_server_id)
            )
            hostname = srv_result.scalar() or "unknown"

            items.append(MysteryKeyItem(
                fingerprint=row.fingerprint,
                last_source_ip=row.source_ip,
                last_username=row.username,
                server_id=row.target_server_id,
                server_hostname=hostname,
                event_count=row.event_count,
                last_seen_at=row.last_seen,
            ))

    items.sort(key=lambda x: x.event_count, reverse=True)
    return items


@router.get("/stale-keys", response_model=list[StaleKeyItem])
async def get_stale_keys(
    db: DbSession,
    user: CurrentUser,
    days: int = Query(90, ge=1, description="Days since last use to consider stale"),
    age_days: int | None = Query(None, ge=1, description="Filter by key age (file_mtime) older than N days"),
):
    """Keys in authorized_keys with no recent use."""
    # Get authorized_keys locations
    stmt = (
        select(KeyLocation, SSHKey, Server)
        .join(SSHKey, KeyLocation.ssh_key_id == SSHKey.id)
        .join(Server, KeyLocation.server_id == Server.id)
        .where(KeyLocation.file_type == "authorized_keys")
    )
    result = await db.execute(stmt)
    rows = result.all()

    now = datetime.now(timezone.utc)
    items = []

    for kl, key, server in rows:
        # Get last event for this key
        event_result = await db.execute(
            select(AccessEvent.event_time)
            .where(AccessEvent.ssh_key_id == key.id)
            .order_by(AccessEvent.event_time.desc())
            .limit(1)
        )
        last_event_row = event_result.first()
        last_event = last_event_row[0] if last_event_row else None

        days_since = None
        if last_event:
            days_since = (now - last_event).days
        else:
            days_since = (now - key.first_seen_at).days

        if days_since and days_since >= days:
            # Optional age filter based on file_mtime
            if age_days is not None and key.file_mtime:
                key_age = (now - key.file_mtime).days
                if key_age < age_days:
                    continue

            items.append(StaleKeyItem(
                ssh_key_id=key.id,
                fingerprint_sha256=key.fingerprint_sha256,
                key_type=key.key_type,
                server_id=server.id,
                server_hostname=server.hostname,
                file_path=kl.file_path,
                last_event=last_event,
                days_since_use=days_since,
            ))

    items.sort(key=lambda x: x.days_since_use or 0, reverse=True)
    return items


@router.get("/summary", response_model=SummaryReport)
async def get_summary(db: DbSession, user: CurrentUser):
    total_servers = (await db.execute(select(func.count(Server.id)))).scalar() or 0
    reachable = (await db.execute(
        select(func.count(Server.id)).where(Server.is_reachable.is_(True))
    )).scalar() or 0
    total_keys = (await db.execute(select(func.count(SSHKey.id)))).scalar() or 0
    total_locations = (await db.execute(select(func.count(KeyLocation.id)))).scalar() or 0
    total_events = (await db.execute(select(func.count(AccessEvent.id)))).scalar() or 0
    total_paths = (await db.execute(select(func.count(AccessPath.id)))).scalar() or 0
    active_watchers = (await db.execute(
        select(func.count(WatchSession.id)).where(WatchSession.status == "active")
    )).scalar() or 0
    unreachable_count = (await db.execute(
        select(func.count(UnreachableSource.id)).where(UnreachableSource.acknowledged.is_(False))
    )).scalar() or 0
    critical_count = (await db.execute(
        select(func.count(UnreachableSource.id)).where(
            UnreachableSource.severity == "critical", UnreachableSource.acknowledged.is_(False)
        )
    )).scalar() or 0
    high_count = (await db.execute(
        select(func.count(UnreachableSource.id)).where(
            UnreachableSource.severity == "high", UnreachableSource.acknowledged.is_(False)
        )
    )).scalar() or 0

    return SummaryReport(
        total_servers=total_servers,
        reachable_servers=reachable,
        unreachable_servers=total_servers - reachable,
        total_keys=total_keys,
        total_key_locations=total_locations,
        total_access_events=total_events,
        total_access_paths=total_paths,
        active_watchers=active_watchers,
        unreachable_sources=unreachable_count,
        critical_alerts=critical_count,
        high_alerts=high_count,
    )


# Alert management
@router.get("/alerts", response_model=UnreachableListResponse)
async def list_alerts(
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: str | None = None,
):
    stmt = (
        select(UnreachableSource)
        .where(UnreachableSource.acknowledged.is_(False))
        .order_by(UnreachableSource.severity, UnreachableSource.last_seen_at.desc())
    )
    if severity:
        stmt = stmt.where(UnreachableSource.severity == severity)

    items, total = await paginate(db, stmt, offset, limit)
    return UnreachableListResponse(items=items, total=total, offset=offset, limit=limit)


@router.put("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    request: AlertAcknowledge,
    db: DbSession,
    user: OperatorUser,
):
    result = await db.execute(
        select(UnreachableSource).where(UnreachableSource.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.acknowledged = request.acknowledged
    alert.acknowledged_by = user.id
    await db.commit()
    return {"message": "Alert updated"}


@router.put("/alerts/{alert_id}/notes")
async def update_alert_notes(
    alert_id: int,
    request: AlertNotes,
    db: DbSession,
    user: OperatorUser,
):
    result = await db.execute(
        select(UnreachableSource).where(UnreachableSource.id == alert_id)
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.notes = request.notes
    await db.commit()
    return {"message": "Notes updated"}
