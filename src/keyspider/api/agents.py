"""Agent management API - endpoints for UI/operators."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from keyspider.core.agent_manager import AgentManager
from keyspider.core.ssh_connector import SSHConnectionPool
from keyspider.db.queries import paginate
from keyspider.dependencies import CurrentUser, DbSession, OperatorUser
from keyspider.models.agent_status import AgentStatus
from keyspider.models.server import Server
from keyspider.models.sudo_event import SudoEvent
from keyspider.schemas.agent import (
    AgentDeployBatchRequest,
    AgentDeployRequest,
    AgentStatusResponse,
    SudoEventListResponse,
    SudoEventResponse,
)

router = APIRouter()


@router.get("", response_model=list[AgentStatusResponse])
async def list_agents(db: DbSession, user: CurrentUser):
    """List all agent statuses."""
    result = await db.execute(
        select(AgentStatus).order_by(AgentStatus.server_id)
    )
    return result.scalars().all()


@router.get("/{server_id}", response_model=AgentStatusResponse)
async def get_agent_status(server_id: int, db: DbSession, user: CurrentUser):
    """Get agent status for a specific server."""
    result = await db.execute(
        select(AgentStatus).where(AgentStatus.server_id == server_id)
    )
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found for this server")
    return agent


@router.post("/deploy/{server_id}", response_model=AgentStatusResponse)
async def deploy_agent(
    server_id: int,
    request: AgentDeployRequest,
    db: DbSession,
    user: OperatorUser,
):
    """Deploy agent to a server."""
    result = await db.execute(select(Server).where(Server.id == server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    pool = SSHConnectionPool()
    try:
        manager = AgentManager(pool)
        status = await manager.deploy_agent(db, server, request.api_url)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deploy failed: {e}")
    finally:
        await pool.close_all()


@router.post("/deploy-batch", response_model=list[AgentStatusResponse])
async def deploy_batch(
    request: AgentDeployBatchRequest,
    db: DbSession,
    user: OperatorUser,
):
    """Deploy agent to multiple servers."""
    pool = SSHConnectionPool()
    try:
        manager = AgentManager(pool)
        results = await manager.deploy_to_many(db, request.server_ids, request.api_url)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch deploy failed: {e}")
    finally:
        await pool.close_all()


@router.post("/{server_id}/uninstall")
async def uninstall_agent(
    server_id: int,
    db: DbSession,
    user: OperatorUser,
):
    """Uninstall agent from a server."""
    result = await db.execute(select(Server).where(Server.id == server_id))
    server = result.scalar_one_or_none()
    if not server:
        raise HTTPException(status_code=404, detail="Server not found")

    pool = SSHConnectionPool()
    try:
        manager = AgentManager(pool)
        await manager.uninstall_agent(db, server)
        return {"message": "Agent uninstalled"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Uninstall failed: {e}")
    finally:
        await pool.close_all()


@router.get("/{server_id}/sudo-events", response_model=SudoEventListResponse)
async def get_sudo_events(
    server_id: int,
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    """Get sudo events for a server (paginated)."""
    stmt = (
        select(SudoEvent)
        .where(SudoEvent.server_id == server_id)
        .order_by(SudoEvent.event_time.desc())
    )
    items, total = await paginate(db, stmt, offset, limit)
    return SudoEventListResponse(items=items, total=total, offset=offset, limit=limit)
