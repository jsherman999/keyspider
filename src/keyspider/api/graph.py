"""Graph API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from keyspider.core.graph_builder import GraphBuilder
from keyspider.dependencies import CurrentUser, DbSession
from keyspider.schemas.graph import GraphResponse, PathResponse

router = APIRouter()


@router.get("", response_model=GraphResponse)
async def get_full_graph(
    db: DbSession,
    user: CurrentUser,
    layer: str | None = Query(None, description="Filter: authorization, usage, or None for all"),
):
    builder = GraphBuilder(db)
    return await builder.build_full_graph(layer=layer)


@router.get("/layered", response_model=GraphResponse)
async def get_layered_graph(
    db: DbSession,
    user: CurrentUser,
    layer: str = Query("all", description="all, authorization, or usage"),
    show_dormant: bool = Query(True, description="Show authorized but unused paths"),
    show_mystery: bool = Query(True, description="Show used but unauthorized paths"),
):
    builder = GraphBuilder(db)
    return await builder.build_layered_graph(layer, show_dormant, show_mystery)


@router.get("/server/{server_id}", response_model=GraphResponse)
async def get_server_graph(
    server_id: int,
    db: DbSession,
    user: CurrentUser,
    depth: int = Query(2, ge=1, le=10),
):
    builder = GraphBuilder(db)
    return await builder.build_server_subgraph(server_id, depth)


@router.get("/key/{key_id}", response_model=GraphResponse)
async def get_key_graph(key_id: int, db: DbSession, user: CurrentUser):
    builder = GraphBuilder(db)
    return await builder.build_key_subgraph(key_id)


@router.get("/path", response_model=PathResponse)
async def find_path(
    db: DbSession,
    user: CurrentUser,
    from_id: int = Query(..., alias="from"),
    to_id: int = Query(..., alias="to"),
):
    builder = GraphBuilder(db)
    return await builder.find_paths(from_id, to_id)
