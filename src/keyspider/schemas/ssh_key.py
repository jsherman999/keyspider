"""SSH Key schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SSHKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    fingerprint_sha256: str
    fingerprint_md5: str | None
    key_type: str
    key_bits: int | None
    comment: str | None
    is_host_key: bool
    first_seen_at: datetime
    created_at: datetime


class SSHKeyDetail(SSHKeyResponse):
    public_key_data: str | None
    location_count: int = 0
    event_count: int = 0


class KeyLocationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ssh_key_id: int
    server_id: int
    file_path: str
    file_type: str
    unix_owner: str | None
    unix_permissions: str | None
    last_verified_at: datetime | None
    server_hostname: str | None = None


class SSHKeyListResponse(BaseModel):
    items: list[SSHKeyResponse]
    total: int
    offset: int
    limit: int
