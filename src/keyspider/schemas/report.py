"""Report schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class UnreachableSourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_ip: str
    reverse_dns: str | None
    fingerprint: str | None
    ssh_key_id: int | None
    target_server_id: int
    username: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    severity: str
    notes: str | None
    acknowledged: bool
    acknowledged_by: int | None


class UnreachableListResponse(BaseModel):
    items: list[UnreachableSourceResponse]
    total: int
    offset: int
    limit: int


class KeyExposureItem(BaseModel):
    ssh_key_id: int
    fingerprint_sha256: str
    key_type: str
    comment: str | None
    server_count: int
    servers: list[str]


class StaleKeyItem(BaseModel):
    ssh_key_id: int
    fingerprint_sha256: str
    key_type: str
    server_id: int
    server_hostname: str
    file_path: str
    last_event: datetime | None
    days_since_use: int | None


class SummaryReport(BaseModel):
    total_servers: int
    reachable_servers: int
    unreachable_servers: int
    total_keys: int
    total_key_locations: int
    total_access_events: int
    total_access_paths: int
    active_watchers: int
    unreachable_sources: int
    critical_alerts: int
    high_alerts: int


class AlertAcknowledge(BaseModel):
    acknowledged: bool = True


class AlertNotes(BaseModel):
    notes: str
