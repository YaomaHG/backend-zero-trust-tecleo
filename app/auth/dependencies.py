from datetime import datetime, timezone
from typing import Optional
from fastapi import Depends, HTTPException, Request, status
import jwt
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database import get_db
from app.models import Session as UserSession, User


def is_account_locked(locked_until: Optional[datetime]) -> bool:
    """Checks whether an account is currently locked out."""
    if locked_until is None:
        return False
    now = datetime.now(timezone.utc)
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > now


def is_session_expired(expires_at: Optional[datetime]) -> bool:
    """Checks whether a session timestamp has expired."""
    if expires_at is None:
        return True
    now = datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at < now


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    Extracts and authenticates the current user from JWT in cookies or Authorization header.
    Validates token signature, expiration, and database session revocation state.
    (RF-01, RF-02, RF-08, CP-S01, CP-S02, CP-S03)
    """
    token = request.cookies.get("access_token")

    # Fallback to Authorization header if cookie is absent
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate signature and token expiration
    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token signature or payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing user_id",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check active session status in database
    session_record = (
        db.query(UserSession)
        .filter(UserSession.jwt_token == token)
        .first()
    )

    if session_record is None or session_record.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked or is invalid",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if is_session_expired(session_record.expires_at):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify user exists and is active
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Store state on request for downstream usage (e.g., logout or audit)
    request.state.current_user = user
    request.state.session = session_record
    request.state.token = token

    return user
