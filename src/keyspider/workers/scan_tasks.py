"""Server scan Celery tasks."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from keyspider.workers.celery_app import app
from keyspider.config import settings
from keyspider.core.key_scanner import scan_server_keys
from keyspider.core.log_parser import detect_log_paths, parse_log
from keyspider.core.sftp_reader import SFTPReader
from keyspider.core.ssh_connector import SSHConnectionPool, get_ssh_pool
from keyspider.db.queries import get_or_create
from keyspider.db.session import async_session_factory
from keyspider.models.key_location import KeyLocation
from keyspider.models.scan_job import ScanJob
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine from a sync Celery task."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@app.task(bind=True, name="keyspider.workers.scan_tasks.scan_single_server")
def scan_single_server(self, job_id: int, server_id: int):
    """Scan a single server for SSH keys and auth logs."""
    return _run_async(_scan_single_server(self, job_id, server_id))


async def _scan_single_server(task, job_id: int, server_id: int):
    pool = SSHConnectionPool()
    async with async_session_factory() as session:
        # Update job status
        result = await session.execute(select(ScanJob).where(ScanJob.id == job_id))
        job = result.scalar_one_or_none()
        if not job:
            return {"error": "Job not found"}

        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        await session.commit()

        # Get server
        result = await session.execute(select(Server).where(Server.id == server_id))
        server = result.scalar_one_or_none()
        if not server:
            job.status = "failed"
            job.error_message = "Server not found"
            await session.commit()
            return {"error": "Server not found"}

        # Check if agent is active for this server
        if server.prefer_agent:
            from keyspider.models.agent_status import AgentStatus
            result = await session.execute(
                select(AgentStatus).where(
                    AgentStatus.server_id == server.id,
                    AgentStatus.deployment_status == "active",
                )
            )
            agent = result.scalar_one_or_none()
            if agent and agent.last_heartbeat_at:
                age = (datetime.now(timezone.utc) - agent.last_heartbeat_at).total_seconds()
                if age < 300:
                    # Agent is active, skip SSH scan
                    server.last_scanned_at = datetime.now(timezone.utc)
                    job.status = "completed"
                    job.completed_at = datetime.now(timezone.utc)
                    job.servers_scanned = 1
                    await session.commit()
                    return {"status": "completed", "source": "agent"}

        try:
            # Get SSH connection
            wrapper = await pool.get_connection(server.ip_address, server.ssh_port)
            try:
                conn = wrapper.conn

                # Scan keys via SFTP
                keys = await scan_server_keys(conn, server.ip_address, server.ssh_port, server.os_type)
                keys_stored = 0
                for dk in keys:
                    if not dk.fingerprint_sha256:
                        continue
                    ssh_key, created = await get_or_create(
                        session, SSHKey,
                        defaults={
                            "fingerprint_md5": dk.fingerprint_md5,
                            "key_type": dk.key_type or "unknown",
                            "public_key_data": dk.public_key_data,
                            "comment": dk.comment,
                            "is_host_key": dk.is_host_key,
                        },
                        fingerprint_sha256=dk.fingerprint_sha256,
                    )

                    # Update file_mtime
                    if dk.file_mtime:
                        if ssh_key.file_mtime is None or dk.file_mtime < ssh_key.file_mtime:
                            ssh_key.file_mtime = dk.file_mtime
                        if ssh_key.file_mtime:
                            ssh_key.estimated_age_days = (
                                datetime.now(timezone.utc) - ssh_key.file_mtime
                            ).days

                    await get_or_create(
                        session, KeyLocation,
                        defaults={
                            "file_type": dk.file_type,
                            "unix_owner": dk.unix_owner,
                            "unix_permissions": dk.unix_permissions,
                            "file_mtime": dk.file_mtime,
                            "file_size": dk.file_size,
                            "last_verified_at": datetime.now(timezone.utc),
                        },
                        ssh_key_id=ssh_key.id,
                        server_id=server.id,
                        file_path=dk.file_path,
                    )
                    keys_stored += 1

                # Parse auth logs via SFTP
                events_parsed = 0
                log_paths = detect_log_paths(server.os_type)
                for log_path in log_paths:
                    try:
                        content = await SFTPReader.read_file_tail(
                            conn, log_path,
                            max_lines=settings.log_max_lines_initial,
                        )
                        if content:
                            file_info = await SFTPReader.stat_file(conn, log_path)
                            ref_time = file_info.mtime if file_info else None
                            events = parse_log(content, server.os_type, ref_time)
                            events_parsed = len(events)
                            break
                    except Exception:
                        continue

                # Update job and server
                server.last_scanned_at = datetime.now(timezone.utc)
                server.is_reachable = True
                job.status = "completed"
                job.completed_at = datetime.now(timezone.utc)
                job.servers_scanned = 1
                job.keys_found = keys_stored
                job.events_parsed = events_parsed
                await session.commit()

                return {
                    "status": "completed",
                    "keys_found": keys_stored,
                    "events_parsed": events_parsed,
                }
            finally:
                await pool.release_connection(wrapper.wrapper_id)

        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            job.completed_at = datetime.now(timezone.utc)
            await session.commit()
            logger.error("Scan failed for server %d: %s", server_id, e)
            return {"error": str(e)}
        finally:
            await pool.close_all()


@app.task(name="keyspider.workers.scan_tasks.scheduled_full_scan")
def scheduled_full_scan():
    """Scheduled task to scan all servers."""
    return _run_async(_scheduled_full_scan())


async def _scheduled_full_scan():
    async with async_session_factory() as session:
        # Create a scan job
        job = ScanJob(
            job_type="full_scan",
            status="pending",
            initiated_by="scheduler",
        )
        session.add(job)
        await session.commit()

        # Get all reachable servers
        result = await session.execute(
            select(Server).where(Server.is_reachable.is_(True))
        )
        servers = result.scalars().all()

        # Launch individual scan tasks
        for server in servers:
            scan_single_server.delay(job.id, server.id)

        return {"job_id": job.id, "servers_queued": len(servers)}


@app.task(name="keyspider.workers.scan_tasks.check_agent_health")
def check_agent_health():
    """Check agent heartbeats and mark stale agents as inactive."""
    return _run_async(_check_agent_health())


async def _check_agent_health():
    from keyspider.models.agent_status import AgentStatus

    async with async_session_factory() as session:
        result = await session.execute(
            select(AgentStatus).where(AgentStatus.deployment_status == "active")
        )
        agents = result.scalars().all()
        now = datetime.now(timezone.utc)
        stale_count = 0

        for agent in agents:
            if agent.last_heartbeat_at:
                age = (now - agent.last_heartbeat_at).total_seconds()
                if age > 300:  # 5 minutes
                    agent.deployment_status = "inactive"
                    stale_count += 1

        await session.commit()
        return {"checked": len(agents), "stale": stale_count}
