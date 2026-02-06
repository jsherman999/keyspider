"""Main router aggregation."""

from fastapi import APIRouter

from keyspider.api.agent_receiver import router as agent_receiver_router
from keyspider.api.agents import router as agents_router
from keyspider.api.auth import router as auth_router
from keyspider.api.graph import router as graph_router
from keyspider.api.keys import router as keys_router
from keyspider.api.reports import router as reports_router
from keyspider.api.scans import router as scans_router
from keyspider.api.servers import router as servers_router
from keyspider.api.watch import router as watch_router
from keyspider.api.ws import router as ws_router

api_router = APIRouter()

api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
api_router.include_router(servers_router, prefix="/servers", tags=["servers"])
api_router.include_router(keys_router, prefix="/keys", tags=["keys"])
api_router.include_router(scans_router, prefix="/scans", tags=["scans"])
api_router.include_router(watch_router, prefix="/watch", tags=["watch"])
api_router.include_router(graph_router, prefix="/graph", tags=["graph"])
api_router.include_router(reports_router, prefix="/reports", tags=["reports"])
api_router.include_router(ws_router, prefix="/ws", tags=["websocket"])
api_router.include_router(agents_router, prefix="/agents", tags=["agents"])
api_router.include_router(agent_receiver_router, prefix="/agent", tags=["agent-receiver"])
