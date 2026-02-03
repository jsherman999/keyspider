"""WebSocket endpoints for real-time streaming."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from keyspider.db.session import async_session_factory
from keyspider.models.scan_job import ScanJob
from keyspider.models.watch_session import WatchSession

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections for broadcasting events."""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = {}

    async def connect(self, channel: str, ws: WebSocket):
        await ws.accept()
        if channel not in self._connections:
            self._connections[channel] = []
        self._connections[channel].append(ws)

    def disconnect(self, channel: str, ws: WebSocket):
        if channel in self._connections:
            self._connections[channel].remove(ws)
            if not self._connections[channel]:
                del self._connections[channel]

    async def broadcast(self, channel: str, data: dict):
        if channel in self._connections:
            dead = []
            for ws in self._connections[channel]:
                try:
                    await ws.send_json(data)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.disconnect(channel, ws)


manager = ConnectionManager()


@router.websocket("/watch/{session_id}")
async def watch_stream(ws: WebSocket, session_id: int):
    """Stream real-time auth events for a watch session."""
    channel = f"watch-{session_id}"
    await manager.connect(channel, ws)

    try:
        # Verify session exists
        async with async_session_factory() as db:
            result = await db.execute(
                select(WatchSession).where(WatchSession.id == session_id)
            )
            watch = result.scalar_one_or_none()
            if not watch:
                await ws.send_json({"error": "Session not found"})
                return

        # Keep connection alive and poll for events
        while True:
            try:
                # Wait for client messages (ping/pong or commands)
                data = await asyncio.wait_for(ws.receive_text(), timeout=30)
                if data == "ping":
                    await ws.send_json({"type": "pong"})
            except asyncio.TimeoutError:
                # Send keepalive
                await ws.send_json({"type": "keepalive"})

    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(channel, ws)


@router.websocket("/scan/{job_id}")
async def scan_progress(ws: WebSocket, job_id: int):
    """Stream scan progress updates for a scan job."""
    channel = f"scan-{job_id}"
    await manager.connect(channel, ws)

    try:
        while True:
            async with async_session_factory() as db:
                result = await db.execute(
                    select(ScanJob).where(ScanJob.id == job_id)
                )
                job = result.scalar_one_or_none()
                if not job:
                    await ws.send_json({"error": "Job not found"})
                    break

                await ws.send_json({
                    "type": "progress",
                    "status": job.status,
                    "servers_scanned": job.servers_scanned,
                    "keys_found": job.keys_found,
                    "events_parsed": job.events_parsed,
                    "unreachable_found": job.unreachable_found,
                })

                if job.status in ("completed", "failed", "cancelled"):
                    break

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(channel, ws)
