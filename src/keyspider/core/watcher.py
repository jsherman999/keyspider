"""Real-time SSH auth log tailing service."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import AsyncIterator, Callable

import asyncssh

from keyspider.core.log_parser import AuthEvent, detect_log_paths, parse_line
from keyspider.config import settings

logger = logging.getLogger(__name__)


class LogWatcher:
    """Watches SSH auth logs on a remote server in real time."""

    def __init__(
        self,
        hostname: str,
        port: int = 22,
        os_type: str = "linux",
        username: str = "root",
        key_path: str = settings.ssh_key_path,
        known_hosts: str | None = settings.ssh_known_hosts,
    ):
        self.hostname = hostname
        self.port = port
        self.os_type = os_type
        self.username = username
        self.key_path = key_path
        self.known_hosts = known_hosts
        self._conn: asyncssh.SSHClientConnection | None = None
        self._process: asyncssh.SSHClientProcess | None = None
        self._running = False
        self._callbacks: list[Callable[[AuthEvent], None]] = []
        self._event_queues: list[asyncio.Queue[AuthEvent | None]] = []

    def on_event(self, callback: Callable[[AuthEvent], None]) -> None:
        """Register a callback for new auth events."""
        self._callbacks.append(callback)

    async def start(self) -> None:
        """Start watching the auth log."""
        self._running = True
        reconnect_delay = settings.watcher_reconnect_delay
        max_delay = settings.watcher_max_reconnect_delay

        while self._running:
            try:
                await self._connect_and_tail()
            except (asyncssh.Error, OSError, asyncio.TimeoutError) as e:
                if not self._running:
                    break
                logger.warning(
                    "Watcher connection lost for %s:%d: %s. Reconnecting in %ds...",
                    self.hostname, self.port, e, reconnect_delay,
                )
                await asyncio.sleep(reconnect_delay)
                reconnect_delay = min(reconnect_delay * 2, max_delay)
            except Exception as e:
                logger.error("Unexpected watcher error for %s:%d: %s", self.hostname, self.port, e)
                if not self._running:
                    break
                await asyncio.sleep(reconnect_delay)

    async def _connect_and_tail(self) -> None:
        """Establish SSH connection and tail the auth log."""
        self._conn = await asyncssh.connect(
            self.hostname,
            port=self.port,
            username=self.username,
            client_keys=[self.key_path],
            known_hosts=self.known_hosts,
        )

        log_paths = detect_log_paths(self.os_type)
        log_path = log_paths[0]  # Primary log path

        # Use tail -F to follow log rotations
        self._process = await self._conn.create_process(
            f"tail -F {log_path} 2>/dev/null"
        )

        logger.info("Watcher started for %s:%d on %s", self.hostname, self.port, log_path)

        async for line in self._process.stdout:
            if not self._running:
                break

            line = line.strip()
            if not line:
                continue

            event = parse_line(line, self.os_type)
            if event:
                for callback in self._callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        logger.error("Watcher callback error: %s", e)

    async def stop(self) -> None:
        """Stop the watcher and unblock all event generators."""
        self._running = False

        # Send sentinel to all registered queues to unblock waiters
        for q in self._event_queues:
            try:
                q.put_nowait(None)
            except asyncio.QueueFull:
                pass

        if self._process:
            self._process.close()
            self._process = None
        if self._conn:
            self._conn.close()
            self._conn = None
        logger.info("Watcher stopped for %s:%d", self.hostname, self.port)

    @property
    def is_running(self) -> bool:
        return self._running

    async def events(self) -> AsyncIterator[AuthEvent]:
        """Async iterator that yields auth events."""
        queue: asyncio.Queue[AuthEvent | None] = asyncio.Queue()
        self._event_queues.append(queue)

        def enqueue(event: AuthEvent):
            queue.put_nowait(event)

        self.on_event(enqueue)

        try:
            while self._running:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    if event is None:
                        # Sentinel received - watcher is stopping
                        break
                    yield event
                except asyncio.TimeoutError:
                    continue
        finally:
            # Clean up callback and queue reference
            if enqueue in self._callbacks:
                self._callbacks.remove(enqueue)
            if queue in self._event_queues:
                self._event_queues.remove(queue)
