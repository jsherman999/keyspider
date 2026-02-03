"""Auth API endpoints."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, status
from jose import jwt
from passlib.hash import bcrypt
from sqlalchemy import select

from keyspider.config import settings
from keyspider.dependencies import AdminUser, CurrentUser, DbSession
from keyspider.models.api_key import APIKey
from keyspider.models.user import User
from keyspider.schemas.auth import (
    APIKeyCreate,
    APIKeyCreated,
    APIKeyResponse,
    LoginRequest,
    TokenResponse,
    UserCreate,
    UserResponse,
)

router = APIRouter()


def _create_access_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {"sub": user_id, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: DbSession):
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()

    if not user or not bcrypt.verify(request.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    token = _create_access_token(user.id)
    return TokenResponse(access_token=token)


@router.post("/logout")
async def logout(user: CurrentUser):
    # JWT is stateless; client should discard the token
    return {"message": "Logged out"}


@router.get("/me", response_model=UserResponse)
async def get_me(user: CurrentUser):
    return user


@router.post("/users", response_model=UserResponse)
async def create_user(request: UserCreate, db: DbSession, admin: AdminUser):
    # Check uniqueness
    result = await db.execute(select(User).where(User.username == request.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        username=request.username,
        password_hash=bcrypt.hash(request.password),
        display_name=request.display_name,
        role=request.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/api-keys", response_model=APIKeyCreated)
async def create_api_key(request: APIKeyCreate, db: DbSession, user: CurrentUser):
    raw_key = secrets.token_urlsafe(48)
    key_hash = bcrypt.hash(raw_key)
    key_prefix = raw_key[:8]

    expires_at = None
    if request.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=request.expires_in_days)

    api_key = APIKey(
        user_id=user.id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        name=request.name,
        permissions=request.permissions,
        expires_at=expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)

    return APIKeyCreated(
        id=api_key.id,
        key_prefix=api_key.key_prefix,
        name=api_key.name,
        permissions=api_key.permissions,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        key=raw_key,
    )


@router.get("/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(db: DbSession, user: CurrentUser):
    result = await db.execute(select(APIKey).where(APIKey.user_id == user.id))
    return result.scalars().all()


@router.delete("/api-keys/{key_id}")
async def delete_api_key(key_id: int, db: DbSession, user: CurrentUser):
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    await db.delete(api_key)
    await db.commit()
    return {"message": "API key deleted"}
