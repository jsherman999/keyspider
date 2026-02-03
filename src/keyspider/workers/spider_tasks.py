"""Spider crawl Celery tasks."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from keyspider.workers.celery_app import app
from keyspider.core.spider_engine import SpiderEngine
from keyspider.core.ssh_connector import SSHConnectionPool
from keyspider.db.session import async_session_factory
from keyspider.models.scan_job import ScanJob
from keyspider.models.server import Server

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@app.task(bind=True, name="keyspider.workers.spider_tasks.spider_crawl")
def spider_crawl(self, job_id: int, seed_server_id: int, max_depth: int = 10):
    """Execute a spider crawl from a seed server."""
    return _run_async(_spider_crawl(self, job_id, seed_server_id, max_depth))


async def _spider_crawl(task, job_id: int, seed_server_id: int, max_depth: int):
    pool = SSHConnectionPool()
    async with async_session_factory() as session:
        # Update job status
        result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            return {"error": "Job not found"}

        result = await session.execute(select(Server).where(Server.id == seed_server_id))
        server = result.scalar_one_or_none()
        if not server:
            job.status = "failed"
            job.error_message = "Seed server not found"
            await session.commit()
            return {"error": "Seed server not found"}

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        await session.commit()

        try:
            async def progress_callback(progress):
                # Update Celery task state
                task.update_state(
                    state="PROGRESS",
                    meta={
                        "servers_scanned": progress.servers_scanned,
                        "keys_found": progress.keys_found,
                        "events_parsed": progress.events_parsed,
                        "unreachable_found": progress.unreachable_found,
                        "current_depth": progress.current_depth,
                        "current_server": progress.current_server,
                    },
                )

            engine = SpiderEngine(
                pool=pool,
                session=session,
                max_depth=max_depth,
                progress_callback=progress_callback,
            )

            progress = await engine.crawl(server.ip_address, server.ssh_port)

            # Update job with results
            job.status = "completed"
            job.completed_at = datetime.now(timezone.utc)
            job.servers_scanned = progress.servers_scanned
            job.keys_found = progress.keys_found
            job.events_parsed = progress.events_parsed
            job.unreachable_found = progress.unreachable_found
            await session.commit()

            return {
                "status": "completed",
                "servers_scanned": progress.servers_scanned,
                "keys_found": progress.keys_found,
                "events_parsed": progress.events_parsed,
                "unreachable_found": progress.unreachable_found,
            }

        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)
            await session.commit()
            logger.error("Spider crawl failed for job %d: %s", job_id, e)
            return {"error": str(e)}
        finally:
            await pool.close_all()
