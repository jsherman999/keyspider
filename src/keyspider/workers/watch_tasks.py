"""Watcher management Celery tasks."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select

from keyspider.workers.celery_app import app
from keyspider.core.log_parser import AuthEvent
from keyspider.core.watcher import LogWatcher
from keyspider.db.queries import get_or_create
from keyspider.db.session import async_session_factory
from keyspider.models.access_event import AccessEvent
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey
from keyspider.models.watch_session import WatchSession

logger = logging.getLogger(__name__)

# Track active watchers by session ID
_active_watchers: dict[int, LogWatcher] = {}


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@app.task(bind=True, name="keyspider.workers.watch_tasks.start_watcher")
def start_watcher(self, session_id: int):
    """Start a log watcher for a server."""
    return _run_async(_start_watcher(self, session_id))


async def _start_watcher(task, session_id: int):
    async with async_session_factory() as db_session:
        result = await db_session.execute(
            select(WatchSession).where(WatchSession.id == session_id)
        )
        watch = result.scalar_one_or_none()
        if not watch:
            return {"error": "Watch session not found"}

        result = await db_session.execute(
            select(Server).where(Server.id == watch.server_id)
        )
        server = result.scalar_one_or_none()
        if not server:
            watch.status = "error"
            watch.error_message = "Server not found"
            await db_session.commit()
            return {"error": "Server not found"}

        watcher = LogWatcher(
            hostname=server.ip_address,
            port=server.ssh_port,
            os_type=server.os_type,
        )

        async def on_event(event: AuthEvent):
            """Handle a new auth event from the watcher."""
            async with async_session_factory() as event_session:
                # Match fingerprint to key
                ssh_key_id = None
                if event.fingerprint:
                    key_result = await event_session.execute(
                        select(SSHKey).where(
                            SSHKey.fingerprint_sha256 == event.fingerprint
                        )
                    )
                    key = key_result.scalar_one_or_none()
                    if key:
                        ssh_key_id = key.id

                # Match source IP to server
                source_server_id = None
                src_result = await event_session.execute(
                    select(Server).where(Server.ip_address == event.source_ip)
                )
                src_server = src_result.scalar_one_or_none()
                if src_server:
                    source_server_id = src_server.id

                access_event = AccessEvent(
                    target_server_id=server.id,
                    source_ip=event.source_ip,
                    source_server_id=source_server_id,
                    ssh_key_id=ssh_key_id,
                    fingerprint=event.fingerprint,
                    username=event.username,
                    auth_method=event.auth_method,
                    event_type=event.event_type,
                    event_time=event.timestamp,
                    raw_log_line=event.raw_line,
                )
                event_session.add(access_event)
                await event_session.commit()

        watcher.on_event(lambda e: asyncio.create_task(on_event(e)))
        _active_watchers[session_id] = watcher

        watch.status = "active"
        await db_session.commit()

        try:
            await watcher.start()
        except Exception as e:
            watch.status = "error"
            watch.error_message = str(e)
            await db_session.commit()
            raise
        finally:
            _active_watchers.pop(session_id, None)


@app.task(name="keyspider.workers.watch_tasks.stop_watcher")
def stop_watcher(session_id: int):
    """Stop a running watcher."""
    return _run_async(_stop_watcher(session_id))


async def _stop_watcher(session_id: int):
    watcher = _active_watchers.get(session_id)
    if watcher:
        await watcher.stop()
        _active_watchers.pop(session_id, None)

    async with async_session_factory() as session:
        result = await session.execute(
            select(WatchSession).where(WatchSession.id == session_id)
        )
        watch = result.scalar_one_or_none()
        if watch:
            watch.status = "stopped"
            watch.stopped_at = datetime.now(timezone.utc)
            await session.commit()

    return {"status": "stopped"}


@app.task(name="keyspider.workers.watch_tasks.health_check_watchers")
def health_check_watchers():
    """Periodic health check for all active watchers."""
    return _run_async(_health_check())


async def _health_check():
    async with async_session_factory() as session:
        result = await session.execute(
            select(WatchSession).where(WatchSession.status == "active")
        )
        active_sessions = result.scalars().all()

        for watch in active_sessions:
            watcher = _active_watchers.get(watch.id)
            if not watcher or not watcher.is_running:
                # Restart the watcher
                logger.warning("Restarting watcher for session %d", watch.id)
                start_watcher.delay(watch.id)

    return {"checked": len(active_sessions) if 'active_sessions' in dir() else 0}
