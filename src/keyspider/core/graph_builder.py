"""Access graph construction and queries."""

from __future__ import annotations

import logging
from collections import defaultdict, deque

from sqlalchemy import select, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from keyspider.models.access_path import AccessPath
from keyspider.models.server import Server
from keyspider.models.ssh_key import SSHKey
from keyspider.models.unreachable_source import UnreachableSource
from keyspider.schemas.graph import GraphEdge, GraphNode, GraphResponse, PathResponse

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Builds and queries the SSH access graph."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def build_full_graph(self, layer: str | None = None) -> GraphResponse:
        """Build the complete access graph from all access paths.

        Args:
            layer: Optional filter - "authorization", "usage", or None for all.
        """
        # Get all servers
        result = await self.session.execute(select(Server))
        servers = result.scalars().all()

        # Get all active access paths with optional layer filter
        stmt = select(AccessPath).where(AccessPath.is_active.is_(True))
        if layer == "authorization":
            stmt = stmt.where(AccessPath.is_authorized.is_(True))
        elif layer == "usage":
            stmt = stmt.where(AccessPath.is_used.is_(True))
        result = await self.session.execute(stmt)
        paths = result.scalars().all()

        # Get unreachable sources
        result = await self.session.execute(
            select(UnreachableSource).where(UnreachableSource.acknowledged.is_(False))
        )
        unreachables = result.scalars().all()

        nodes = {}
        edges = []

        # Add server nodes
        for server in servers:
            node_id = f"server-{server.id}"
            nodes[node_id] = GraphNode(
                id=node_id,
                label=server.hostname,
                type="server",
                ip_address=server.ip_address,
                os_type=server.os_type,
                is_reachable=server.is_reachable,
            )

        # Add unreachable source nodes
        for ur in unreachables:
            node_id = f"unreachable-{ur.id}"
            nodes[node_id] = GraphNode(
                id=node_id,
                label=ur.reverse_dns or ur.source_ip,
                type="unreachable",
                ip_address=ur.source_ip,
                is_reachable=False,
            )
            # Edge from unreachable to target
            edges.append(GraphEdge(
                id=f"ur-edge-{ur.id}",
                source=node_id,
                target=f"server-{ur.target_server_id}",
                label=f"{ur.severity} ({ur.event_count})",
                username=ur.username,
                event_count=ur.event_count,
                is_active=True,
            ))

        # Add access path edges
        for path in paths:
            if path.source_server_id:
                source = f"server-{path.source_server_id}"
            else:
                continue  # Skip paths without a source server (handled by unreachables)

            target = f"server-{path.target_server_id}"
            edge_id = f"path-{path.id}"

            # Get key type if available
            key_type = None
            if path.ssh_key_id:
                result = await self.session.execute(
                    select(SSHKey.key_type).where(SSHKey.id == path.ssh_key_id)
                )
                key_type = result.scalar_one_or_none()

            edges.append(GraphEdge(
                id=edge_id,
                source=source,
                target=target,
                label=path.username,
                key_type=key_type,
                username=path.username,
                event_count=path.event_count,
                is_active=path.is_active,
                is_authorized=path.is_authorized,
                is_used=path.is_used,
            ))

        node_list = list(nodes.values())
        return GraphResponse(
            nodes=node_list,
            edges=edges,
            node_count=len(node_list),
            edge_count=len(edges),
        )

    async def build_layered_graph(
        self,
        layer: str = "all",
        show_dormant: bool = True,
        show_mystery: bool = True,
    ) -> GraphResponse:
        """Build a graph with layer filtering.

        Args:
            layer: "all", "authorization", "usage"
            show_dormant: Include authorized but never used paths
            show_mystery: Include used but not authorized paths
        """
        stmt = select(AccessPath).where(AccessPath.is_active.is_(True))

        if layer == "authorization":
            stmt = stmt.where(AccessPath.is_authorized.is_(True))
        elif layer == "usage":
            stmt = stmt.where(AccessPath.is_used.is_(True))

        if not show_dormant:
            # Exclude paths that are authorized but not used
            stmt = stmt.where(
                ~(and_(AccessPath.is_authorized.is_(True), AccessPath.is_used.is_(False)))
            )
        if not show_mystery:
            # Exclude paths that are used but not authorized
            stmt = stmt.where(
                ~(and_(AccessPath.is_used.is_(True), AccessPath.is_authorized.is_(False)))
            )

        result = await self.session.execute(stmt)
        paths = result.scalars().all()

        # Collect server IDs
        server_ids = set()
        for path in paths:
            if path.source_server_id:
                server_ids.add(path.source_server_id)
            server_ids.add(path.target_server_id)

        nodes = {}
        if server_ids:
            result = await self.session.execute(
                select(Server).where(Server.id.in_(server_ids))
            )
            for server in result.scalars().all():
                node_id = f"server-{server.id}"
                nodes[node_id] = GraphNode(
                    id=node_id,
                    label=server.hostname,
                    type="server",
                    ip_address=server.ip_address,
                    os_type=server.os_type,
                    is_reachable=server.is_reachable,
                )

        edges = []
        for path in paths:
            if not path.source_server_id:
                continue
            edges.append(GraphEdge(
                id=f"path-{path.id}",
                source=f"server-{path.source_server_id}",
                target=f"server-{path.target_server_id}",
                username=path.username,
                event_count=path.event_count,
                is_active=path.is_active,
                is_authorized=path.is_authorized,
                is_used=path.is_used,
            ))

        node_list = list(nodes.values())
        return GraphResponse(
            nodes=node_list,
            edges=edges,
            node_count=len(node_list),
            edge_count=len(edges),
        )

    async def build_server_subgraph(self, server_id: int, depth: int = 2) -> GraphResponse:
        """Build a subgraph centered on a specific server."""
        visited = set()
        nodes = {}
        edges = []
        queue = deque([(server_id, 0)])

        while queue:
            current_id, current_depth = queue.popleft()
            if current_id in visited or current_depth > depth:
                continue
            visited.add(current_id)

            # Get server info
            result = await self.session.execute(
                select(Server).where(Server.id == current_id)
            )
            server = result.scalar_one_or_none()
            if not server:
                continue

            node_id = f"server-{server.id}"
            nodes[node_id] = GraphNode(
                id=node_id,
                label=server.hostname,
                type="server",
                ip_address=server.ip_address,
                os_type=server.os_type,
                is_reachable=server.is_reachable,
            )

            # Get paths where this server is source or target
            result = await self.session.execute(
                select(AccessPath).where(
                    or_(
                        AccessPath.source_server_id == current_id,
                        AccessPath.target_server_id == current_id,
                    ),
                    AccessPath.is_active.is_(True),
                )
            )
            paths = result.scalars().all()

            for path in paths:
                if path.source_server_id and path.source_server_id not in visited:
                    queue.append((path.source_server_id, current_depth + 1))
                if path.target_server_id not in visited:
                    queue.append((path.target_server_id, current_depth + 1))

                source = f"server-{path.source_server_id}" if path.source_server_id else None
                target = f"server-{path.target_server_id}"
                if source:
                    edges.append(GraphEdge(
                        id=f"path-{path.id}",
                        source=source,
                        target=target,
                        username=path.username,
                        event_count=path.event_count,
                        is_active=path.is_active,
                        is_authorized=path.is_authorized,
                        is_used=path.is_used,
                    ))

        # Add unreachable sources targeting visited servers
        result = await self.session.execute(
            select(UnreachableSource).where(
                UnreachableSource.target_server_id.in_(visited),
                UnreachableSource.acknowledged.is_(False),
            )
        )
        for ur in result.scalars().all():
            ur_node_id = f"unreachable-{ur.id}"
            nodes[ur_node_id] = GraphNode(
                id=ur_node_id,
                label=ur.reverse_dns or ur.source_ip,
                type="unreachable",
                ip_address=ur.source_ip,
                is_reachable=False,
            )
            edges.append(GraphEdge(
                id=f"ur-edge-{ur.id}",
                source=ur_node_id,
                target=f"server-{ur.target_server_id}",
                label=f"{ur.severity}",
                username=ur.username,
                event_count=ur.event_count,
            ))

        node_list = list(nodes.values())
        return GraphResponse(
            nodes=node_list,
            edges=edges,
            node_count=len(node_list),
            edge_count=len(edges),
        )

    async def build_key_subgraph(self, key_id: int) -> GraphResponse:
        """Build a subgraph showing all access paths for a specific key."""
        result = await self.session.execute(
            select(AccessPath).where(
                AccessPath.ssh_key_id == key_id,
                AccessPath.is_active.is_(True),
            )
        )
        paths = result.scalars().all()

        nodes = {}
        edges = []
        server_ids = set()

        for path in paths:
            if path.source_server_id:
                server_ids.add(path.source_server_id)
            server_ids.add(path.target_server_id)

            source = f"server-{path.source_server_id}" if path.source_server_id else None
            target = f"server-{path.target_server_id}"
            if source:
                edges.append(GraphEdge(
                    id=f"path-{path.id}",
                    source=source,
                    target=target,
                    username=path.username,
                    event_count=path.event_count,
                    is_active=path.is_active,
                    is_authorized=path.is_authorized,
                    is_used=path.is_used,
                ))

        # Fetch server info
        if server_ids:
            result = await self.session.execute(
                select(Server).where(Server.id.in_(server_ids))
            )
            for server in result.scalars().all():
                node_id = f"server-{server.id}"
                nodes[node_id] = GraphNode(
                    id=node_id,
                    label=server.hostname,
                    type="server",
                    ip_address=server.ip_address,
                    os_type=server.os_type,
                    is_reachable=server.is_reachable,
                )

        node_list = list(nodes.values())
        return GraphResponse(
            nodes=node_list,
            edges=edges,
            node_count=len(node_list),
            edge_count=len(edges),
        )

    async def find_paths(self, from_server_id: int, to_server_id: int) -> PathResponse:
        """Find all access paths between two servers using BFS."""
        # Build adjacency list from access paths
        result = await self.session.execute(
            select(AccessPath).where(AccessPath.is_active.is_(True))
        )
        all_paths = result.scalars().all()

        adjacency: dict[int, list[int]] = defaultdict(list)
        for path in all_paths:
            if path.source_server_id:
                adjacency[path.source_server_id].append(path.target_server_id)

        # BFS to find all simple paths
        found_paths: list[list[int]] = []
        queue: deque[list[int]] = deque([[from_server_id]])

        while queue and len(found_paths) < 100:  # Limit results
            current_path = queue.popleft()
            current_node = current_path[-1]

            if current_node == to_server_id:
                found_paths.append(current_path)
                continue

            if len(current_path) > 10:  # Max path length
                continue

            for neighbor in adjacency.get(current_node, []):
                if neighbor not in current_path:  # Avoid cycles
                    queue.append(current_path + [neighbor])

        # Build subgraph containing all found paths
        involved_servers = set()
        for path in found_paths:
            involved_servers.update(path)

        nodes = {}
        if involved_servers:
            result = await self.session.execute(
                select(Server).where(Server.id.in_(involved_servers))
            )
            for server in result.scalars().all():
                node_id = f"server-{server.id}"
                nodes[node_id] = GraphNode(
                    id=node_id,
                    label=server.hostname,
                    type="server",
                    ip_address=server.ip_address,
                    os_type=server.os_type,
                    is_reachable=server.is_reachable,
                )

        edges = []
        for ap in all_paths:
            if ap.source_server_id in involved_servers and ap.target_server_id in involved_servers:
                edges.append(GraphEdge(
                    id=f"path-{ap.id}",
                    source=f"server-{ap.source_server_id}" if ap.source_server_id else "",
                    target=f"server-{ap.target_server_id}",
                    username=ap.username,
                    event_count=ap.event_count,
                    is_authorized=ap.is_authorized,
                    is_used=ap.is_used,
                ))

        node_list = list(nodes.values())
        str_paths = [[f"server-{s}" for s in p] for p in found_paths]

        return PathResponse(
            paths=str_paths,
            graph=GraphResponse(
                nodes=node_list,
                edges=edges,
                node_count=len(node_list),
                edge_count=len(edges),
            ),
        )
