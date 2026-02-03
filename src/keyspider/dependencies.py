"""FastAPI dependency injection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from keyspider.config import settings
from keyspider.db.session import get_session
from keyspider.models.api_key import APIKey
from keyspider.models.user import User

security = HTTPBearer(auto_error=False)


async def get_db() -> AsyncSession:
    """Get a database session."""
    async for session in get_session():
        yield session


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """Get the current authenticated user from JWT or API key."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    token = credentials.credentials

    # Try JWT first
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
        return user

    except JWTError:
        pass

    # Try API key
    from passlib.hash import bcrypt

    prefix = token[:8] if len(token) >= 8 else token
    result = await db.execute(
        select(APIKey).where(APIKey.key_prefix == prefix)
    )
    api_keys = result.scalars().all()

    for api_key in api_keys:
        if bcrypt.verify(token, api_key.key_hash):
            # Check expiry
            if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key expired")

            # Update last used
            api_key.last_used_at = datetime.now(timezone.utc)
            await db.commit()

            # Get the user
            result = await db.execute(select(User).where(User.id == api_key.user_id))
            user = result.scalar_one_or_none()
            if not user or not user.is_active:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
            return user

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


def require_role(*roles: str):
    """Dependency that requires the user to have one of the specified roles."""

    async def check_role(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(roles)}",
            )
        return user

    return check_role


# Common dependency aliases
DbSession = Annotated[AsyncSession, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_role("admin"))]
OperatorUser = Annotated[User, Depends(require_role("admin", "operator"))]
