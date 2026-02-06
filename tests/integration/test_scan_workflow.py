"""Integration tests for the scan workflow."""

import pytest
from datetime import datetime, timezone

from keyspider.models.server import Server
from keyspider.models.scan_job import ScanJob
from keyspider.models.ssh_key import SSHKey
from keyspider.models.key_location import KeyLocation
from keyspider.models.access_path import AccessPath
from keyspider.models.agent_status import AgentStatus
from keyspider.models.sudo_event import SudoEvent


class TestScanWorkflow:
    @pytest.mark.asyncio
    async def test_create_server(self, db_session):
        server = Server(
            hostname="test-server",
            ip_address="10.0.0.1",
            ssh_port=22,
            os_type="linux",
            discovered_via="manual",
        )
        db_session.add(server)
        await db_session.commit()
        assert server.id is not None
        assert server.is_reachable is True

    @pytest.mark.asyncio
    async def test_create_scan_job(self, db_session):
        job = ScanJob(
            job_type="server_scan",
            status="pending",
            initiated_by="test",
        )
        db_session.add(job)
        await db_session.commit()
        assert job.id is not None
        assert job.status == "pending"
        assert job.servers_scanned == 0

    @pytest.mark.asyncio
    async def test_create_ssh_key_and_location(self, db_session):
        server = Server(
            hostname="key-test-server",
            ip_address="10.0.0.2",
            ssh_port=22,
            os_type="linux",
        )
        db_session.add(server)
        await db_session.flush()

        key = SSHKey(
            fingerprint_sha256="SHA256:testfp1234567890",
            key_type="rsa",
            key_bits=4096,
        )
        db_session.add(key)
        await db_session.flush()

        location = KeyLocation(
            ssh_key_id=key.id,
            server_id=server.id,
            file_path="/root/.ssh/authorized_keys",
            file_type="authorized_keys",
            unix_owner="root",
            unix_permissions="0600",
        )
        db_session.add(location)
        await db_session.commit()

        assert location.id is not None
        assert location.ssh_key_id == key.id
        assert location.server_id == server.id


class TestNewModelFields:
    @pytest.mark.asyncio
    async def test_server_scan_watermark(self, db_session):
        server = Server(
            hostname="watermark-test",
            ip_address="10.0.10.1",
            ssh_port=22,
            os_type="linux",
        )
        db_session.add(server)
        await db_session.commit()

        assert server.scan_watermark is None
        server.scan_watermark = "2024-01-15T10:00:00Z"
        await db_session.commit()
        assert server.scan_watermark == "2024-01-15T10:00:00Z"

    @pytest.mark.asyncio
    async def test_server_prefer_agent(self, db_session):
        server = Server(
            hostname="agent-pref-test",
            ip_address="10.0.10.2",
            ssh_port=22,
            os_type="linux",
        )
        db_session.add(server)
        await db_session.commit()
        assert server.prefer_agent is False

        server.prefer_agent = True
        await db_session.commit()
        assert server.prefer_agent is True

    @pytest.mark.asyncio
    async def test_key_location_graph_layer(self, db_session):
        server = Server(hostname="gl-test", ip_address="10.0.10.3", ssh_port=22, os_type="linux")
        db_session.add(server)
        await db_session.flush()

        key = SSHKey(fingerprint_sha256="SHA256:gl_test_fp", key_type="ed25519")
        db_session.add(key)
        await db_session.flush()

        loc = KeyLocation(
            ssh_key_id=key.id,
            server_id=server.id,
            file_path="/root/.ssh/authorized_keys",
            file_type="authorized_keys",
        )
        db_session.add(loc)
        await db_session.commit()
        assert loc.graph_layer == "authorization"

    @pytest.mark.asyncio
    async def test_key_location_file_mtime(self, db_session):
        server = Server(hostname="mt-test", ip_address="10.0.10.4", ssh_port=22, os_type="linux")
        db_session.add(server)
        await db_session.flush()

        key = SSHKey(fingerprint_sha256="SHA256:mt_test_fp", key_type="rsa")
        db_session.add(key)
        await db_session.flush()

        mtime = datetime(2023, 6, 15, tzinfo=timezone.utc)
        loc = KeyLocation(
            ssh_key_id=key.id,
            server_id=server.id,
            file_path="/root/.ssh/authorized_keys",
            file_type="authorized_keys",
            file_mtime=mtime,
            file_size=2048,
        )
        db_session.add(loc)
        await db_session.commit()
        assert loc.file_mtime == mtime
        assert loc.file_size == 2048

    @pytest.mark.asyncio
    async def test_access_path_authorization_flags(self, db_session):
        server = Server(hostname="ap-test", ip_address="10.0.10.5", ssh_port=22, os_type="linux")
        db_session.add(server)
        await db_session.flush()

        path = AccessPath(
            target_server_id=server.id,
            username="root",
            event_count=3,
            is_active=True,
            is_authorized=True,
            is_used=False,
            first_seen_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc),
        )
        db_session.add(path)
        await db_session.commit()
        assert path.is_authorized is True
        assert path.is_used is False

    @pytest.mark.asyncio
    async def test_ssh_key_file_mtime(self, db_session):
        mtime = datetime(2022, 1, 1, tzinfo=timezone.utc)
        key = SSHKey(
            fingerprint_sha256="SHA256:age_test_fp",
            key_type="rsa",
            file_mtime=mtime,
            estimated_age_days=365,
        )
        db_session.add(key)
        await db_session.commit()
        assert key.file_mtime == mtime
        assert key.estimated_age_days == 365


class TestAgentStatusModel:
    @pytest.mark.asyncio
    async def test_create_agent_status(self, db_session):
        server = Server(hostname="as-test", ip_address="10.0.11.1", ssh_port=22, os_type="linux")
        db_session.add(server)
        await db_session.flush()

        agent = AgentStatus(
            server_id=server.id,
            deployment_status="active",
            agent_version="1.0.0",
            agent_token_hash="sha256hashhere",
        )
        db_session.add(agent)
        await db_session.commit()
        assert agent.id is not None
        assert agent.deployment_status == "active"
        assert agent.server_id == server.id

    @pytest.mark.asyncio
    async def test_agent_status_heartbeat(self, db_session):
        server = Server(hostname="hb-test", ip_address="10.0.11.2", ssh_port=22, os_type="linux")
        db_session.add(server)
        await db_session.flush()

        agent = AgentStatus(
            server_id=server.id,
            deployment_status="deploying",
            agent_token_hash="token_hash_2",
        )
        db_session.add(agent)
        await db_session.commit()

        agent.last_heartbeat_at = datetime.now(timezone.utc)
        agent.deployment_status = "active"
        await db_session.commit()
        assert agent.last_heartbeat_at is not None
        assert agent.deployment_status == "active"


class TestSudoEventModel:
    @pytest.mark.asyncio
    async def test_create_sudo_event(self, db_session):
        server = Server(hostname="sudo-test", ip_address="10.0.12.1", ssh_port=22, os_type="linux")
        db_session.add(server)
        await db_session.flush()

        event = SudoEvent(
            server_id=server.id,
            username="admin",
            command="/usr/bin/apt update",
            target_user="root",
            working_dir="/home/admin",
            tty="pts/0",
            event_time=datetime.now(timezone.utc),
            success=True,
            raw_log_line="Jan 5 10:00:00 host sudo[1]: admin : TTY=pts/0 ; ...",
        )
        db_session.add(event)
        await db_session.commit()
        assert event.id is not None
        assert event.username == "admin"
        assert event.command == "/usr/bin/apt update"
        assert event.success is True
