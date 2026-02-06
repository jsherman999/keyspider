"""SSH connection management with asyncssh pooling."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

import asyncssh

from keyspider.config import settings

logger = logging.getLogger(__name__)


@dataclass
class SSHConnectionWrapper:
    """Wrapper around an asyncssh connection with tracking metadata."""

    conn: asyncssh.SSHClientConnection
    hostname: str
    port: int
    wrapper_id: str = field(default_factory=lambda: str(uuid.uuid4()))
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
        self._pools: dict[str, list[SSHConnectionWrapper]] = {}
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
    ) -> SSHConnectionWrapper:
        """Get a connection from the pool or create a new one.

        Returns an SSHConnectionWrapper with a unique wrapper_id for tracking.
        """
        key = self._server_key(hostname, port)

        await self._semaphore.acquire()

        # Find idle candidate under lock (quick)
        candidate: SSHConnectionWrapper | None = None
        async with self._lock:
            if key in self._pools:
                for wrapper in self._pools[key]:
                    if not wrapper.in_use:
                        candidate = wrapper
                        wrapper.in_use = True  # Tentatively mark as in-use
                        break

            # Check per-server limit if no candidate
            if candidate is None:
                current = len(self._pools.get(key, []))
                if current >= self._per_server_limit:
                    self._semaphore.release()
                    raise ConnectionError(
                        f"Per-server connection limit ({self._per_server_limit}) reached for {key}"
                    )

        # Health check outside the lock
        if candidate is not None:
            try:
                await asyncio.wait_for(
                    candidate.conn.run("echo ok", check=True),
                    timeout=5,
                )
                return candidate
            except Exception:
                # Connection is dead, remove it
                async with self._lock:
                    if key in self._pools and candidate in self._pools[key]:
                        self._pools[key].remove(candidate)
                # Fall through to create a new connection

        # Create new connection outside the lock
        conn = await self._create_connection(hostname, port, username)
        wrapper = SSHConnectionWrapper(conn=conn, hostname=hostname, port=port, in_use=True)

        async with self._lock:
            if key not in self._pools:
                self._pools[key] = []
            self._pools[key].append(wrapper)

        return wrapper

    async def release_connection(self, wrapper_id: str) -> None:
        """Release a connection back to the pool by wrapper ID."""
        async with self._lock:
            for key, wrappers in self._pools.items():
                for wrapper in wrappers:
                    if wrapper.wrapper_id == wrapper_id:
                        wrapper.in_use = False
                        self._semaphore.release()
                        return
        # If wrapper not found, still release semaphore
        self._semaphore.release()

    async def close_connection(self, wrapper_id: str) -> None:
        """Close and remove a connection from the pool by wrapper ID."""
        async with self._lock:
            for key, wrappers in self._pools.items():
                for wrapper in wrappers:
                    if wrapper.wrapper_id == wrapper_id:
                        wrapper.conn.close()
                        wrappers.remove(wrapper)
                        self._semaphore.release()
                        return
        self._semaphore.release()

    async def get_sftp_client(
        self, hostname: str, port: int = 22, username: str = "root"
    ) -> tuple[asyncssh.SFTPClient, str]:
        """Get an SFTP client and wrapper_id for a server.

        Returns (sftp_client, wrapper_id). Caller must release via wrapper_id.
        """
        wrapper = await self.get_connection(hostname, port, username)
        sftp = await wrapper.conn.start_sftp_client()
        return sftp, wrapper.wrapper_id

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
        wrapper = await self.get_connection(hostname, port, username)
        try:
            result = await asyncio.wait_for(
                wrapper.conn.run(command, check=False),
                timeout=timeout,
            )
            return result
        finally:
            await self.release_connection(wrapper.wrapper_id)

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


# Lazy pool singleton
_pool: SSHConnectionPool | None = None


def get_ssh_pool() -> SSHConnectionPool:
    """Get or create the global SSH connection pool."""
    global _pool
    if _pool is None:
        _pool = SSHConnectionPool()
    return _pool


def set_ssh_pool(pool: SSHConnectionPool) -> None:
    """Set the global SSH pool (for testing)."""
    global _pool
    _pool = pool
