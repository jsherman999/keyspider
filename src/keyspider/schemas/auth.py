"""Auth schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    display_name: str | None
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(BaseModel):
    username: str
    password: str
    display_name: str | None = None
    role: str = "viewer"


class APIKeyCreate(BaseModel):
    name: str
    permissions: list[str] = ["read"]
    expires_in_days: int | None = None


class APIKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    key_prefix: str
    name: str
    permissions: list[str]
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class APIKeyCreated(APIKeyResponse):
    """Response when creating a new API key - includes the actual key (shown only once)."""
    key: str
