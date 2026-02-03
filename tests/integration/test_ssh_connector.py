"""Integration tests for SSH connector (requires SSH access)."""

import pytest

from keyspider.core.ssh_connector import SSHConnectionPool


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
