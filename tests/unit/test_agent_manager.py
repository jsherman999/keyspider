"""Tests for the agent manager."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone, timedelta

from keyspider.core.agent_manager import AgentManager, _SYSTEMD_UNIT


class TestAgentManagerRender:
    def test_render_systemd_unit(self):
        pool = MagicMock()
        manager = AgentManager(pool)
        unit = manager._render_systemd_unit()
        assert "[Unit]" in unit
        assert "keyspider-agent" in unit
        assert "ExecStart" in unit

    def test_render_agent_injects_config(self):
        pool = MagicMock()
        manager = AgentManager(pool)

        # Mock the agent template file
        template = '''#!/usr/bin/env python3
"""Keyspider Agent."""

CONFIG = {
    "api_url": "PLACEHOLDER",
    "agent_token": "PLACEHOLDER",
    "server_id": 0,
    "heartbeat_interval": 60,
    "collect_interval": 30,
    "log_paths": ["/var/log/auth.log"],
    "agent_version": "1.0.0",
}

class Agent:
    pass
'''
        with patch("keyspider.core.agent_manager._AGENT_SCRIPT_PATH") as mock_path:
            mock_path.read_text.return_value = template
            rendered = manager._render_agent("https://keyspider.example.com", 42, "test-token-xyz")

        assert '"api_url": "https://keyspider.example.com"' in rendered
        assert '"server_id": 42' in rendered
        assert '"agent_token": "test-token-xyz"' in rendered
        assert "class Agent:" in rendered  # Non-config code preserved


class TestAgentManagerHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy_agent(self, db_session):
        from keyspider.models.server import Server
        from keyspider.models.agent_status import AgentStatus

        server = Server(
            hostname="agent-test", ip_address="10.0.0.1", ssh_port=22, os_type="linux"
        )
        db_session.add(server)
        await db_session.flush()

        agent = AgentStatus(
            server_id=server.id,
            deployment_status="active",
            agent_token_hash="abc123",
            last_heartbeat_at=datetime.now(timezone.utc),
        )
        db_session.add(agent)
        await db_session.commit()

        pool = MagicMock()
        manager = AgentManager(pool)
        healthy = await manager.check_health(db_session, server.id)
        assert healthy is True

    @pytest.mark.asyncio
    async def test_stale_agent(self, db_session):
        from keyspider.models.server import Server
        from keyspider.models.agent_status import AgentStatus

        server = Server(
            hostname="stale-test", ip_address="10.0.0.2", ssh_port=22, os_type="linux"
        )
        db_session.add(server)
        await db_session.flush()

        agent = AgentStatus(
            server_id=server.id,
            deployment_status="active",
            agent_token_hash="abc456",
            last_heartbeat_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        )
        db_session.add(agent)
        await db_session.commit()

        pool = MagicMock()
        manager = AgentManager(pool)
        healthy = await manager.check_health(db_session, server.id)
        assert healthy is False

    @pytest.mark.asyncio
    async def test_no_agent(self, db_session):
        pool = MagicMock()
        manager = AgentManager(pool)
        healthy = await manager.check_health(db_session, 99999)
        assert healthy is False
