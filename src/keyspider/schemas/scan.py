"""Scan schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ScanCreate(BaseModel):
    job_type: str  # full_scan | server_scan | spider_crawl | key_scan
    seed_server_id: int | None = None
    max_depth: int = 10
    config: dict | None = None


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    job_type: str
    status: str
    initiated_by: str
    seed_server_id: int | None
    max_depth: int | None
    servers_scanned: int
    keys_found: int
    events_parsed: int
    unreachable_found: int
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int
    offset: int
    limit: int
