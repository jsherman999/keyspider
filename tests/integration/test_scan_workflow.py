"""Integration tests for the scan workflow."""

import pytest

from keyspider.models.server import Server
from keyspider.models.scan_job import ScanJob
from keyspider.models.ssh_key import SSHKey
from keyspider.models.key_location import KeyLocation


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
