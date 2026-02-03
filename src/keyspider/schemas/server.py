"""Server schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ServerCreate(BaseModel):
    hostname: str
    ip_address: str
    os_type: str = "linux"
    os_version: str | None = None
    ssh_port: int = 22
    discovered_via: str = "manual"


class ServerUpdate(BaseModel):
    hostname: str | None = None
    ip_address: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    ssh_port: int | None = None
    is_reachable: bool | None = None


class ServerResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    ip_address: str
    os_type: str
    os_version: str | None
    ssh_port: int
    is_reachable: bool
    last_scanned_at: datetime | None
    discovered_via: str | None
    created_at: datetime
    updated_at: datetime


class ServerSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    ip_address: str
    os_type: str
    is_reachable: bool
    last_scanned_at: datetime | None


class ServerImport(BaseModel):
    servers: list[ServerCreate]


class ServerListResponse(BaseModel):
    items: list[ServerResponse]
    total: int
    offset: int
    limit: int
