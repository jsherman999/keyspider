"""Tests for the SSH connection pool wrapper_id tracking and lazy init."""

import pytest

from keyspider.core.ssh_connector import (
    SSHConnectionPool,
    SSHConnectionWrapper,
    get_ssh_pool,
    set_ssh_pool,
    _pool,
)


class TestSSHConnectionWrapper:
    def test_wrapper_has_unique_id(self):
        from unittest.mock import MagicMock
        conn = MagicMock()
        w1 = SSHConnectionWrapper(conn=conn, hostname="10.0.0.1", port=22)
        w2 = SSHConnectionWrapper(conn=conn, hostname="10.0.0.1", port=22)
        assert w1.wrapper_id != w2.wrapper_id

    def test_wrapper_defaults(self):
        from unittest.mock import MagicMock
        conn = MagicMock()
        w = SSHConnectionWrapper(conn=conn, hostname="10.0.0.1", port=22)
        assert w.in_use is False
        assert w.hostname == "10.0.0.1"
        assert w.port == 22
        assert len(w.wrapper_id) > 0


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
    async def test_release_unknown_wrapper_id(self):
        pool = SSHConnectionPool()
        # Releasing an unknown wrapper should not raise, but should still release semaphore
        await pool.release_connection("nonexistent-id")

    @pytest.mark.asyncio
    async def test_close_unknown_wrapper_id(self):
        pool = SSHConnectionPool()
        # Closing an unknown wrapper should not raise
        await pool.close_connection("nonexistent-id")


class TestLazyInit:
    def test_get_ssh_pool_returns_pool(self):
        # Reset first
        set_ssh_pool(None)
        pool = get_ssh_pool()
        assert isinstance(pool, SSHConnectionPool)

    def test_get_ssh_pool_returns_same_instance(self):
        set_ssh_pool(None)
        pool1 = get_ssh_pool()
        pool2 = get_ssh_pool()
        assert pool1 is pool2

    def test_set_ssh_pool_overrides(self):
        custom_pool = SSHConnectionPool(max_connections=5)
        set_ssh_pool(custom_pool)
        assert get_ssh_pool() is custom_pool
        # Clean up
        set_ssh_pool(None)
