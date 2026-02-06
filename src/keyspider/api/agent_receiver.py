"""Agent receiver API - endpoints for agents to report data."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from keyspider.dependencies import get_db
from keyspider.models.access_event import AccessEvent
from keyspider.models.agent_status import AgentStatus
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey
from keyspider.models.sudo_event import SudoEvent
from keyspider.models.key_location import KeyLocation
from keyspider.core.fingerprint import (
    calculate_sha256_fingerprint,
    calculate_md5_fingerprint,
    detect_key_type,
    extract_comment,
)
from keyspider.db.queries import get_or_create
from keyspider.schemas.agent import (
    AgentEventsPayload,
    AgentHeartbeat,
    AgentKeyInventory,
    AgentSudoEventsPayload,
)

logger = logging.getLogger(__name__)
router = APIRouter()


async def verify_agent_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AgentStatus:
    """Verify the agent's bearer token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")

    token = auth[7:]
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    result = await db.execute(
        select(AgentStatus).where(AgentStatus.agent_token_hash == token_hash)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

    return agent


@router.post("/heartbeat")
async def agent_heartbeat(
    payload: AgentHeartbeat,
    agent: AgentStatus = Depends(verify_agent_token),
    db: AsyncSession = Depends(get_db),
):
    """Receive heartbeat from an agent."""
    agent.last_heartbeat_at = datetime.now(timezone.utc)
    agent.deployment_status = "active"
    if payload.agent_version:
        agent.agent_version = payload.agent_version
    await db.commit()
    return {"status": "ok"}


@router.post("/events")
async def agent_events(
    payload: AgentEventsPayload,
    agent: AgentStatus = Depends(verify_agent_token),
    db: AsyncSession = Depends(get_db),
):
    """Receive SSH auth events from an agent."""
    server_id = agent.server_id

    # Pre-fetch fingerprint -> key_id map
    fingerprints = {e.fingerprint for e in payload.events if e.fingerprint}
    key_map: dict[str, int] = {}
    if fingerprints:
        result = await db.execute(
            select(SSHKey.fingerprint_sha256, SSHKey.id).where(
                SSHKey.fingerprint_sha256.in_(fingerprints)
            )
        )
        for fp, kid in result.all():
            key_map[fp] = kid

    # Pre-fetch source_ip -> server_id map
    source_ips = {e.source_ip for e in payload.events if e.source_ip}
    ip_map: dict[str, int] = {}
    if source_ips:
        result = await db.execute(
            select(Server.ip_address, Server.id).where(
                Server.ip_address.in_(source_ips)
            )
        )
        for ip, sid in result.all():
            ip_map[ip] = sid

    access_events = []
    for event in payload.events:
        try:
            event_time = datetime.fromisoformat(event.timestamp)
        except ValueError:
            event_time = datetime.now(timezone.utc)

        ssh_key_id = key_map.get(event.fingerprint) if event.fingerprint else None
        source_server_id = ip_map.get(event.source_ip)

        access_events.append(AccessEvent(
            target_server_id=server_id,
            source_ip=event.source_ip,
            source_server_id=source_server_id,
            ssh_key_id=ssh_key_id,
            fingerprint=event.fingerprint,
            username=event.username,
            auth_method=event.auth_method,
            event_type=event.event_type,
            event_time=event_time,
            raw_log_line=event.raw_line,
            log_source="agent",
        ))

    db.add_all(access_events)
    agent.last_event_at = datetime.now(timezone.utc)
    await db.commit()

    return {"status": "ok", "events_received": len(access_events)}


@router.post("/sudo-events")
async def agent_sudo_events(
    payload: AgentSudoEventsPayload,
    agent: AgentStatus = Depends(verify_agent_token),
    db: AsyncSession = Depends(get_db),
):
    """Receive sudo events from an agent."""
    server_id = agent.server_id

    sudo_events = []
    for event in payload.events:
        try:
            event_time = datetime.fromisoformat(event.timestamp)
        except ValueError:
            event_time = datetime.now(timezone.utc)

        sudo_events.append(SudoEvent(
            server_id=server_id,
            username=event.username,
            command=event.command,
            target_user=event.target_user,
            working_dir=event.working_dir,
            tty=event.tty,
            event_time=event_time,
            success=event.success,
            raw_log_line=event.raw_line,
        ))

    db.add_all(sudo_events)
    agent.last_event_at = datetime.now(timezone.utc)
    await db.commit()

    return {"status": "ok", "events_received": len(sudo_events)}


@router.post("/keys")
async def agent_keys(
    payload: AgentKeyInventory,
    agent: AgentStatus = Depends(verify_agent_token),
    db: AsyncSession = Depends(get_db),
):
    """Receive key inventory from an agent."""
    server_id = agent.server_id
    keys_stored = 0

    for key_item in payload.keys:
        key_data = key_item.public_key_data.strip()
        if not key_data:
            continue

        fp_sha = calculate_sha256_fingerprint(key_data)
        fp_md5 = calculate_md5_fingerprint(key_data)
        if not fp_sha:
            continue

        ssh_key, _ = await get_or_create(
            db, SSHKey,
            defaults={
                "fingerprint_md5": fp_md5,
                "key_type": detect_key_type(key_data) or "unknown",
                "public_key_data": key_data,
                "comment": extract_comment(key_data),
                "is_host_key": key_item.is_host_key,
            },
            fingerprint_sha256=fp_sha,
        )

        # Parse mtime
        file_mtime = None
        if key_item.file_mtime:
            try:
                file_mtime = datetime.fromisoformat(key_item.file_mtime)
            except ValueError:
                pass

        if file_mtime:
            if ssh_key.file_mtime is None or file_mtime < ssh_key.file_mtime:
                ssh_key.file_mtime = file_mtime
            if ssh_key.file_mtime:
                ssh_key.estimated_age_days = (
                    datetime.now(timezone.utc) - ssh_key.file_mtime
                ).days

        await get_or_create(
            db, KeyLocation,
            defaults={
                "file_type": key_item.file_type,
                "unix_owner": key_item.unix_owner,
                "unix_permissions": key_item.unix_permissions,
                "file_mtime": file_mtime,
                "file_size": key_item.file_size,
                "last_verified_at": datetime.now(timezone.utc),
            },
            ssh_key_id=ssh_key.id,
            server_id=server_id,
            file_path=key_item.file_path,
        )
        keys_stored += 1

    await db.commit()
    return {"status": "ok", "keys_stored": keys_stored}
