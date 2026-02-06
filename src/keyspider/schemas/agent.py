"""Agent-related schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AgentStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    server_id: int
    agent_version: str | None
    deployment_status: str
    last_heartbeat_at: datetime | None
    last_event_at: datetime | None
    installed_at: datetime | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime


class AgentDeployRequest(BaseModel):
    api_url: str


class AgentDeployBatchRequest(BaseModel):
    server_ids: list[int]
    api_url: str


class AgentHeartbeat(BaseModel):
    server_id: int
    agent_version: str | None = None
    timestamp: str | None = None


class AgentSSHEvent(BaseModel):
    timestamp: str
    source_ip: str
    username: str
    auth_method: str | None = None
    event_type: str
    fingerprint: str | None = None
    port: int | None = None
    raw_line: str | None = None


class AgentEventsPayload(BaseModel):
    server_id: int
    events: list[AgentSSHEvent]


class AgentSudoEvent(BaseModel):
    timestamp: str
    username: str
    tty: str | None = None
    working_dir: str | None = None
    target_user: str | None = None
    command: str | None = None
    success: bool = True
    raw_line: str | None = None


class AgentSudoEventsPayload(BaseModel):
    server_id: int
    events: list[AgentSudoEvent]


class AgentKeyItem(BaseModel):
    public_key_data: str
    file_path: str
    file_type: str
    unix_owner: str | None = None
    unix_permissions: str | None = None
    file_mtime: str | None = None
    file_size: int | None = None
    is_host_key: bool = False


class AgentKeyInventory(BaseModel):
    server_id: int
    keys: list[AgentKeyItem]


class SudoEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    server_id: int
    username: str
    command: str | None
    target_user: str | None
    working_dir: str | None
    tty: str | None
    event_time: datetime
    success: bool
    created_at: datetime


class SudoEventListResponse(BaseModel):
    items: list[SudoEventResponse]
    total: int
    offset: int
    limit: int
