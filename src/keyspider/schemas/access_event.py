"""Access Event schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AccessEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_server_id: int
    source_ip: str
    source_server_id: int | None
    ssh_key_id: int | None
    fingerprint: str | None
    username: str
    auth_method: str | None
    event_type: str
    event_time: datetime
    raw_log_line: str | None
    log_source: str | None


class AccessEventListResponse(BaseModel):
    items: list[AccessEventResponse]
    total: int
    offset: int
    limit: int


class AccessPathResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_server_id: int | None
    target_server_id: int
    ssh_key_id: int | None
    username: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    is_active: bool
