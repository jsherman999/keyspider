"""Scan API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from keyspider.db.queries import paginate
from keyspider.dependencies import CurrentUser, DbSession, OperatorUser
from keyspider.models.scan_job import ScanJob
from keyspider.schemas.scan import ScanCreate, ScanListResponse, ScanResponse
from keyspider.workers.scan_tasks import scan_single_server
from keyspider.workers.spider_tasks import spider_crawl

router = APIRouter()


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(request: ScanCreate, db: DbSession, user: OperatorUser):
    job = ScanJob(
        job_type=request.job_type,
        status="pending",
        initiated_by="api",
        seed_server_id=request.seed_server_id,
        max_depth=request.max_depth,
        config=request.config,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Dispatch the appropriate task (skip if broker is unavailable)
    try:
        if request.job_type == "server_scan" and request.seed_server_id:
            scan_single_server.delay(job.id, request.seed_server_id)
        elif request.job_type == "spider_crawl" and request.seed_server_id:
            spider_crawl.delay(job.id, request.seed_server_id, request.max_depth)
        elif request.job_type == "full_scan":
            from keyspider.models.server import Server
            result = await db.execute(select(Server).where(Server.is_reachable.is_(True)))
            servers = result.scalars().all()
            for server in servers:
                scan_single_server.delay(job.id, server.id)
    except Exception:
        # Celery broker not available -- job is recorded but won't execute
        import logging
        logging.getLogger(__name__).warning("Celery broker unavailable; scan job %d recorded but not dispatched", job.id)

    return job


@router.get("", response_model=ScanListResponse)
async def list_scans(
    db: DbSession,
    user: CurrentUser,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status: str | None = None,
):
    stmt = select(ScanJob).order_by(ScanJob.created_at.desc())
    if status:
        stmt = stmt.where(ScanJob.status == status)
    items, total = await paginate(db, stmt, offset, limit)
    return ScanListResponse(items=items, total=total, offset=offset, limit=limit)


@router.get("/{job_id}", response_model=ScanResponse)
async def get_scan(job_id: int, db: DbSession, user: CurrentUser):
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@router.post("/{job_id}/cancel")
async def cancel_scan(job_id: int, db: DbSession, user: OperatorUser):
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if job.status not in ("pending", "running"):
        raise HTTPException(status_code=400, detail="Job cannot be cancelled")

    job.status = "cancelled"
    await db.commit()
    return {"message": "Scan cancelled"}
