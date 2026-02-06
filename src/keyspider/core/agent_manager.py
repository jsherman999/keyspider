"""Agent deployment and management via SSH."""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from keyspider.core.ssh_connector import SSHConnectionPool
from keyspider.db.queries import get_or_create
from keyspider.models.agent_status import AgentStatus
from keyspider.models.server import Server

logger = logging.getLogger(__name__)

_AGENT_SCRIPT_PATH = Path(__file__).parent.parent / "agent" / "keyspider_agent.py"

_SYSTEMD_UNIT = """\
[Unit]
Description=Keyspider Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/keyspider/keyspider_agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=keyspider-agent

[Install]
WantedBy=multi-user.target
"""


class AgentManager:
    """Manages agent deployment and lifecycle via SSH."""

    def __init__(self, pool: SSHConnectionPool):
        self.pool = pool

    async def deploy_agent(
        self, session: AsyncSession, server: Server, api_url: str
    ) -> AgentStatus:
        """Deploy the agent to a server via SSH/SFTP."""
        # Generate unique agent token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Render agent script with config
        agent_script = self._render_agent(api_url, server.id, token)

        # Get SSH connection
        wrapper = await self.pool.get_connection(server.ip_address, server.ssh_port)
        try:
            conn = wrapper.conn
            sftp = await conn.start_sftp_client()

            # Create directory
            try:
                await sftp.mkdir("/opt/keyspider")
            except Exception:
                pass  # Directory may already exist

            # Upload agent script
            async with sftp.open("/opt/keyspider/keyspider_agent.py", "w") as f:
                await f.write(agent_script)

            # Make executable
            await conn.run("chmod +x /opt/keyspider/keyspider_agent.py", check=False)

            # Upload systemd unit
            async with sftp.open("/etc/systemd/system/keyspider-agent.service", "w") as f:
                await f.write(_SYSTEMD_UNIT)

            # Enable and start the service
            await conn.run(
                "systemctl daemon-reload && systemctl enable --now keyspider-agent",
                check=False,
            )

            sftp.exit()
        finally:
            await self.pool.release_connection(wrapper.wrapper_id)

        # Create/update AgentStatus record
        agent_status, created = await get_or_create(
            session,
            AgentStatus,
            defaults={
                "agent_version": "1.0.0",
                "deployment_status": "deploying",
                "agent_token_hash": token_hash,
                "config": {
                    "api_url": api_url,
                    "server_id": server.id,
                },
                "installed_at": datetime.now(timezone.utc),
            },
            server_id=server.id,
        )
        if not created:
            agent_status.deployment_status = "deploying"
            agent_status.agent_token_hash = token_hash
            agent_status.installed_at = datetime.now(timezone.utc)
            agent_status.error_message = None

        server.prefer_agent = True
        await session.commit()

        return agent_status

    async def uninstall_agent(
        self, session: AsyncSession, server: Server
    ) -> None:
        """Uninstall the agent from a server."""
        wrapper = await self.pool.get_connection(server.ip_address, server.ssh_port)
        try:
            conn = wrapper.conn
            await conn.run(
                "systemctl disable --now keyspider-agent 2>/dev/null; "
                "rm -rf /opt/keyspider /etc/systemd/system/keyspider-agent.service; "
                "systemctl daemon-reload",
                check=False,
            )
        finally:
            await self.pool.release_connection(wrapper.wrapper_id)

        # Update AgentStatus
        result = await session.execute(
            select(AgentStatus).where(AgentStatus.server_id == server.id)
        )
        agent_status = result.scalar_one_or_none()
        if agent_status:
            agent_status.deployment_status = "not_deployed"

        server.prefer_agent = False
        await session.commit()

    async def check_health(self, session: AsyncSession, server_id: int) -> bool:
        """Check if agent is healthy (heartbeat within 5 minutes)."""
        result = await session.execute(
            select(AgentStatus).where(AgentStatus.server_id == server_id)
        )
        agent = result.scalar_one_or_none()
        if not agent or not agent.last_heartbeat_at:
            return False
        age = (datetime.now(timezone.utc) - agent.last_heartbeat_at).total_seconds()
        return age < 300

    async def deploy_to_many(
        self,
        session: AsyncSession,
        server_ids: list[int],
        api_url: str,
    ) -> list[AgentStatus]:
        """Deploy agent to multiple servers."""
        results = []
        for server_id in server_ids:
            result = await session.execute(
                select(Server).where(Server.id == server_id)
            )
            server = result.scalar_one_or_none()
            if not server:
                continue
            try:
                status = await self.deploy_agent(session, server, api_url)
                results.append(status)
            except Exception as e:
                logger.error("Failed to deploy agent to server %d: %s", server_id, e)
                # Record error
                agent_status, _ = await get_or_create(
                    session,
                    AgentStatus,
                    defaults={
                        "deployment_status": "error",
                        "error_message": str(e),
                    },
                    server_id=server_id,
                )
                agent_status.deployment_status = "error"
                agent_status.error_message = str(e)
                await session.commit()
                results.append(agent_status)
        return results

    def _render_agent(self, api_url: str, server_id: int, token: str) -> str:
        """Render the agent script with injected config."""
        template = _AGENT_SCRIPT_PATH.read_text()

        # Replace the CONFIG dict
        config_str = (
            f'CONFIG = {{\n'
            f'    "api_url": "{api_url}",\n'
            f'    "agent_token": "{token}",\n'
            f'    "server_id": {server_id},\n'
            f'    "heartbeat_interval": 60,\n'
            f'    "collect_interval": 30,\n'
            f'    "log_paths": ["/var/log/auth.log", "/var/log/secure"],\n'
            f'    "agent_version": "1.0.0",\n'
            f'}}'
        )

        # Replace from CONFIG = { to the closing }
        import re
        rendered = re.sub(
            r'CONFIG = \{[^}]+\}',
            config_str,
            template,
            count=1,
        )
        return rendered

    def _render_systemd_unit(self) -> str:
        """Return systemd service file content."""
        return _SYSTEMD_UNIT
