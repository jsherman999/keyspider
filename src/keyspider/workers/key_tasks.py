"""Key discovery Celery tasks."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from keyspider.workers.celery_app import app
from keyspider.core.key_scanner import scan_server_keys
from keyspider.core.ssh_connector import SSHConnectionPool
from keyspider.db.queries import get_or_create
from keyspider.db.session import async_session_factory
from keyspider.models.key_location import KeyLocation
from keyspider.models.scan_job import ScanJob
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey

logger = logging.getLogger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@app.task(bind=True, name="keyspider.workers.key_tasks.scan_keys_for_server")
def scan_keys_for_server(self, server_id: int):
    """Scan a single server for SSH keys only."""
    return _run_async(_scan_keys_for_server(server_id))


async def _scan_keys_for_server(server_id: int):
    pool = SSHConnectionPool()
    async with async_session_factory() as session:
        result = await session.execute(select(Server).where(Server.id == server_id))
        server = result.scalar_one_or_none()
        if not server:
            return {"error": "Server not found"}

        try:
            keys = await scan_server_keys(pool, server.ip_address, server.ssh_port, server.os_type)

            keys_stored = 0
            for dk in keys:
                if not dk.fingerprint_sha256:
                    continue
                ssh_key, _ = await get_or_create(
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
                await get_or_create(
                    session, KeyLocation,
                    defaults={
                        "file_type": dk.file_type,
                        "unix_owner": dk.unix_owner,
                        "unix_permissions": dk.unix_permissions,
                        "last_verified_at": datetime.now(timezone.utc),
                    },
                    ssh_key_id=ssh_key.id,
                    server_id=server.id,
                    file_path=dk.file_path,
                )
                keys_stored += 1

            server.last_scanned_at = datetime.now(timezone.utc)
            await session.commit()

            return {"keys_found": keys_stored}
        except Exception as e:
            logger.error("Key scan failed for server %d: %s", server_id, e)
            return {"error": str(e)}
        finally:
            await pool.close_all()


@app.task(name="keyspider.workers.key_tasks.scan_keys_all_servers")
def scan_keys_all_servers():
    """Scan all reachable servers for SSH keys."""
    return _run_async(_scan_keys_all())


async def _scan_keys_all():
    async with async_session_factory() as session:
        result = await session.execute(
            select(Server).where(Server.is_reachable.is_(True))
        )
        servers = result.scalars().all()
        for server in servers:
            scan_keys_for_server.delay(server.id)
        return {"servers_queued": len(servers)}
