"""SSH connection management with asyncssh pooling."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import asyncssh

from keyspider.config import settings

logger = logging.getLogger(__name__)


@dataclass
class SSHConnection:
    """Wrapper around an asyncssh connection with metadata."""

    conn: asyncssh.SSHClientConnection
    hostname: str
    port: int
    in_use: bool = False


class SSHConnectionPool:
    """Manages a pool of SSH connections with per-server limits."""

    def __init__(
        self,
        max_connections: int = settings.ssh_max_connections,
        per_server_limit: int = settings.ssh_per_server_limit,
        connect_timeout: int = settings.ssh_connect_timeout,
        command_timeout: int = settings.ssh_command_timeout,
        key_path: str = settings.ssh_key_path,
        known_hosts: str | None = settings.ssh_known_hosts,
    ):
        self._max_connections = max_connections
        self._per_server_limit = per_server_limit
        self._connect_timeout = connect_timeout
        self._command_timeout = command_timeout
        self._key_path = key_path
        self._known_hosts = known_hosts
        self._pools: dict[str, list[SSHConnection]] = {}
        self._semaphore = asyncio.Semaphore(max_connections)
        self._lock = asyncio.Lock()

    def _server_key(self, hostname: str, port: int) -> str:
        return f"{hostname}:{port}"

    async def _create_connection(
        self, hostname: str, port: int, username: str = "root"
    ) -> asyncssh.SSHClientConnection:
        """Create a new SSH connection with retry."""
        max_retries = 3
        delay = 1.0
        last_error: Exception | None = None

        for attempt in range(max_retries):
            try:
                conn = await asyncio.wait_for(
                    asyncssh.connect(
                        hostname,
                        port=port,
                        username=username,
                        client_keys=[self._key_path],
                        known_hosts=self._known_hosts,
                    ),
                    timeout=self._connect_timeout,
                )
                return conn
            except (asyncssh.Error, OSError, asyncio.TimeoutError) as e:
                last_error = e
                if attempt < max_retries - 1:
                    logger.warning(
                        "SSH connect attempt %d failed for %s:%d: %s",
                        attempt + 1, hostname, port, e,
                    )
                    await asyncio.sleep(delay)
                    delay *= 2

        raise ConnectionError(
            f"Failed to connect to {hostname}:{port} after {max_retries} attempts: {last_error}"
        )

    async def get_connection(
        self, hostname: str, port: int = 22, username: str = "root"
    ) -> asyncssh.SSHClientConnection:
        """Get a connection from the pool or create a new one."""
        key = self._server_key(hostname, port)

        await self._semaphore.acquire()
        async with self._lock:
            # Check for idle connection in pool
            if key in self._pools:
                for wrapper in self._pools[key]:
                    if not wrapper.in_use:
                        try:
                            # Test if connection is still alive
                            await asyncio.wait_for(
                                wrapper.conn.run("echo ok", check=True),
                                timeout=5,
                            )
                            wrapper.in_use = True
                            return wrapper.conn
                        except Exception:
                            # Connection is dead, remove it
                            self._pools[key].remove(wrapper)
                            continue

            # Check per-server limit
            current = len(self._pools.get(key, []))
            if current >= self._per_server_limit:
                self._semaphore.release()
                raise ConnectionError(
                    f"Per-server connection limit ({self._per_server_limit}) reached for {key}"
                )

        # Create new connection outside the lock
        conn = await self._create_connection(hostname, port, username)
        wrapper = SSHConnection(conn=conn, hostname=hostname, port=port, in_use=True)

        async with self._lock:
            if key not in self._pools:
                self._pools[key] = []
            self._pools[key].append(wrapper)

        return conn

    async def release_connection(self, hostname: str, port: int = 22) -> None:
        """Release a connection back to the pool."""
        key = self._server_key(hostname, port)
        async with self._lock:
            if key in self._pools:
                for wrapper in self._pools[key]:
                    if wrapper.in_use:
                        wrapper.in_use = False
                        break
        self._semaphore.release()

    async def close_connection(self, hostname: str, port: int = 22) -> None:
        """Close and remove a connection from the pool."""
        key = self._server_key(hostname, port)
        async with self._lock:
            if key in self._pools:
                for wrapper in self._pools[key]:
                    if wrapper.in_use:
                        wrapper.conn.close()
                        self._pools[key].remove(wrapper)
                        break
        self._semaphore.release()

    async def run_command(
        self,
        hostname: str,
        command: str,
        port: int = 22,
        username: str = "root",
        timeout: int | None = None,
    ) -> asyncssh.SSHCompletedProcess:
        """Run a command on a remote server."""
        timeout = timeout or self._command_timeout
        conn = await self.get_connection(hostname, port, username)
        try:
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=timeout,
            )
            return result
        finally:
            await self.release_connection(hostname, port)

    async def check_reachable(self, hostname: str, port: int = 22) -> bool:
        """Check if a server is reachable via SSH."""
        try:
            conn = await self._create_connection(hostname, port)
            conn.close()
            return True
        except Exception:
            return False

    async def close_all(self) -> None:
        """Close all connections in the pool."""
        async with self._lock:
            for key, wrappers in self._pools.items():
                for wrapper in wrappers:
                    try:
                        wrapper.conn.close()
                    except Exception:
                        pass
            self._pools.clear()


# Global pool instance
ssh_pool = SSHConnectionPool()
