"""Watch session schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class WatchCreate(BaseModel):
    server_id: int
    auto_spider: bool = True
    spider_depth: int = 3


class WatchResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    server_id: int
    status: str
    last_event_at: datetime | None
    events_captured: int
    auto_spider: bool
    spider_depth: int
    error_message: str | None
    started_at: datetime
    stopped_at: datetime | None


class WatchListResponse(BaseModel):
    items: list[WatchResponse]
    total: int
