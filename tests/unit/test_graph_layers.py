"""Tests for authorization vs usage graph layer classification."""

import pytest
from datetime import datetime, timezone

from keyspider.core.graph_builder import GraphBuilder
from keyspider.models.server import Server
from keyspider.models.access_path import AccessPath
from keyspider.models.ssh_key import SSHKey
from keyspider.models.key_location import KeyLocation

_NOW = datetime.now(timezone.utc)


class TestGraphLayers:
    @pytest.mark.asyncio
    async def test_build_full_graph_no_filter(self, db_session):
        s1 = Server(hostname="src", ip_address="10.0.0.1", ssh_port=22, os_type="linux")
        s2 = Server(hostname="dst", ip_address="10.0.0.2", ssh_port=22, os_type="linux")
        db_session.add_all([s1, s2])
        await db_session.flush()

        path = AccessPath(
            source_server_id=s1.id, target_server_id=s2.id,
            username="root", event_count=5, is_active=True,
            is_authorized=True, is_used=True, first_seen_at=_NOW, last_seen_at=_NOW,
        )
        db_session.add(path)
        await db_session.commit()

        builder = GraphBuilder(db_session)
        graph = await builder.build_full_graph()
        assert graph.node_count >= 2
        assert graph.edge_count >= 1

    @pytest.mark.asyncio
    async def test_build_full_graph_authorization_filter(self, db_session):
        s1 = Server(hostname="src-auth", ip_address="10.0.1.1", ssh_port=22, os_type="linux")
        s2 = Server(hostname="dst-auth", ip_address="10.0.1.2", ssh_port=22, os_type="linux")
        db_session.add_all([s1, s2])
        await db_session.flush()

        path_auth = AccessPath(
            source_server_id=s1.id, target_server_id=s2.id,
            username="deploy", event_count=0, is_active=True,
            is_authorized=True, is_used=False, first_seen_at=_NOW, last_seen_at=_NOW,
        )
        db_session.add(path_auth)
        await db_session.commit()

        builder = GraphBuilder(db_session)
        graph = await builder.build_full_graph(layer="authorization")
        auth_edges = [e for e in graph.edges if e.is_authorized]
        assert len(auth_edges) >= 1

    @pytest.mark.asyncio
    async def test_build_full_graph_usage_filter(self, db_session):
        s1 = Server(hostname="src-use", ip_address="10.0.2.1", ssh_port=22, os_type="linux")
        s2 = Server(hostname="dst-use", ip_address="10.0.2.2", ssh_port=22, os_type="linux")
        db_session.add_all([s1, s2])
        await db_session.flush()

        path_use = AccessPath(
            source_server_id=s1.id, target_server_id=s2.id,
            username="mystery_user", event_count=10, is_active=True,
            is_authorized=False, is_used=True, first_seen_at=_NOW, last_seen_at=_NOW,
        )
        db_session.add(path_use)
        await db_session.commit()

        builder = GraphBuilder(db_session)
        graph = await builder.build_full_graph(layer="usage")
        used_edges = [e for e in graph.edges if e.is_used]
        assert len(used_edges) >= 1


class TestLayeredGraph:
    @pytest.mark.asyncio
    async def test_build_layered_graph_all(self, db_session):
        s1 = Server(hostname="lg-src", ip_address="10.0.3.1", ssh_port=22, os_type="linux")
        s2 = Server(hostname="lg-dst", ip_address="10.0.3.2", ssh_port=22, os_type="linux")
        db_session.add_all([s1, s2])
        await db_session.flush()

        dormant = AccessPath(
            source_server_id=s1.id, target_server_id=s2.id,
            username="dormant", event_count=0, is_active=True,
            is_authorized=True, is_used=False, first_seen_at=_NOW, last_seen_at=_NOW,
        )
        mystery = AccessPath(
            source_server_id=s1.id, target_server_id=s2.id,
            username="mystery", event_count=5, is_active=True,
            is_authorized=False, is_used=True, first_seen_at=_NOW, last_seen_at=_NOW,
        )
        db_session.add_all([dormant, mystery])
        await db_session.commit()

        builder = GraphBuilder(db_session)
        graph = await builder.build_layered_graph("all", show_dormant=True, show_mystery=True)
        assert graph.edge_count >= 2

    @pytest.mark.asyncio
    async def test_build_layered_graph_hide_dormant(self, db_session):
        s1 = Server(hostname="hd-src", ip_address="10.0.4.1", ssh_port=22, os_type="linux")
        s2 = Server(hostname="hd-dst", ip_address="10.0.4.2", ssh_port=22, os_type="linux")
        db_session.add_all([s1, s2])
        await db_session.flush()

        dormant = AccessPath(
            source_server_id=s1.id, target_server_id=s2.id,
            username="dormant2", event_count=0, is_active=True,
            is_authorized=True, is_used=False, first_seen_at=_NOW, last_seen_at=_NOW,
        )
        normal = AccessPath(
            source_server_id=s1.id, target_server_id=s2.id,
            username="normal", event_count=3, is_active=True,
            is_authorized=True, is_used=True, first_seen_at=_NOW, last_seen_at=_NOW,
        )
        db_session.add_all([dormant, normal])
        await db_session.commit()

        builder = GraphBuilder(db_session)
        graph = await builder.build_layered_graph("all", show_dormant=False, show_mystery=True)
        dormant_edges = [e for e in graph.edges if e.is_authorized and not e.is_used]
        assert len(dormant_edges) == 0

    @pytest.mark.asyncio
    async def test_build_layered_graph_hide_mystery(self, db_session):
        s1 = Server(hostname="hm-src", ip_address="10.0.5.1", ssh_port=22, os_type="linux")
        s2 = Server(hostname="hm-dst", ip_address="10.0.5.2", ssh_port=22, os_type="linux")
        db_session.add_all([s1, s2])
        await db_session.flush()

        mystery = AccessPath(
            source_server_id=s1.id, target_server_id=s2.id,
            username="mystery3", event_count=7, is_active=True,
            is_authorized=False, is_used=True, first_seen_at=_NOW, last_seen_at=_NOW,
        )
        db_session.add_all([mystery])
        await db_session.commit()

        builder = GraphBuilder(db_session)
        graph = await builder.build_layered_graph("all", show_dormant=True, show_mystery=False)
        mystery_edges = [e for e in graph.edges if e.is_used and not e.is_authorized]
        assert len(mystery_edges) == 0


class TestKeyLocationGraphLayer:
    @pytest.mark.asyncio
    async def test_key_location_default_layer(self, db_session):
        server = Server(hostname="kl-test", ip_address="10.0.6.1", ssh_port=22, os_type="linux")
        db_session.add(server)
        await db_session.flush()

        key = SSHKey(fingerprint_sha256="SHA256:layer_test_fp", key_type="rsa")
        db_session.add(key)
        await db_session.flush()

        loc = KeyLocation(
            ssh_key_id=key.id, server_id=server.id,
            file_path="/root/.ssh/authorized_keys",
            file_type="authorized_keys",
        )
        db_session.add(loc)
        await db_session.commit()

        assert loc.graph_layer == "authorization"

    @pytest.mark.asyncio
    async def test_key_location_usage_layer(self, db_session):
        server = Server(hostname="kl-test2", ip_address="10.0.6.2", ssh_port=22, os_type="linux")
        db_session.add(server)
        await db_session.flush()

        key = SSHKey(fingerprint_sha256="SHA256:layer_test_fp2", key_type="ed25519")
        db_session.add(key)
        await db_session.flush()

        loc = KeyLocation(
            ssh_key_id=key.id, server_id=server.id,
            file_path="/root/.ssh/authorized_keys",
            file_type="authorized_keys",
            graph_layer="usage",
        )
        db_session.add(loc)
        await db_session.commit()

        assert loc.graph_layer == "usage"
