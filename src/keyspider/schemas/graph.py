"""Graph schemas."""

from __future__ import annotations

from pydantic import BaseModel


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # server | unreachable
    ip_address: str | None = None
    os_type: str | None = None
    is_reachable: bool = True
    key_count: int = 0
    event_count: int = 0


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str | None = None
    key_type: str | None = None
    username: str | None = None
    event_count: int = 0
    is_active: bool = True


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    node_count: int = 0
    edge_count: int = 0


class PathResponse(BaseModel):
    paths: list[list[str]]  # List of node ID sequences
    graph: GraphResponse
