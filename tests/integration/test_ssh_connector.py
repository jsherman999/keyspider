"""Integration tests for SSH connector (requires SSH access)."""

import pytest

from keyspider.core.ssh_connector import (
    SSHConnectionPool,
    SSHConnectionWrapper,
    get_ssh_pool,
    set_ssh_pool,
)


class TestSSHConnectionPool:
    def test_pool_initialization(self):
        pool = SSHConnectionPool(max_connections=10, per_server_limit=2)
        assert pool._max_connections == 10
        assert pool._per_server_limit == 2

    def test_server_key(self):
        pool = SSHConnectionPool()
        assert pool._server_key("10.0.0.1", 22) == "10.0.0.1:22"
        assert pool._server_key("10.0.0.1", 2222) == "10.0.0.1:2222"

    @pytest.mark.asyncio
    async def test_close_all_empty(self):
        pool = SSHConnectionPool()
        await pool.close_all()  # Should not raise

    @pytest.mark.asyncio
    async def test_release_nonexistent_wrapper(self):
        pool = SSHConnectionPool()
        await pool.release_connection("does-not-exist")

    @pytest.mark.asyncio
    async def test_close_nonexistent_wrapper(self):
        pool = SSHConnectionPool()
        await pool.close_connection("does-not-exist")


class TestSSHConnectionWrapperTracking:
    def test_wrapper_has_unique_ids(self):
        from unittest.mock import MagicMock
        conn = MagicMock()
        wrappers = [
            SSHConnectionWrapper(conn=conn, hostname="host", port=22)
            for _ in range(10)
        ]
        ids = {w.wrapper_id for w in wrappers}
        assert len(ids) == 10  # All unique

    def test_wrapper_in_use_default(self):
        from unittest.mock import MagicMock
        conn = MagicMock()
        w = SSHConnectionWrapper(conn=conn, hostname="host", port=22)
        assert w.in_use is False


class TestLazySingleton:
    def test_set_and_get(self):
        original = SSHConnectionPool(max_connections=3)
        set_ssh_pool(original)
        assert get_ssh_pool() is original
        set_ssh_pool(None)

    def test_auto_creates_on_first_get(self):
        set_ssh_pool(None)
        pool = get_ssh_pool()
        assert isinstance(pool, SSHConnectionPool)
        set_ssh_pool(None)
