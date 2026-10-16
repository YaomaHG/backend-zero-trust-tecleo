import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import jwt
from passlib.context import CryptContext
from app.core.config import settings

# Password hashing context with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Creates a cryptographically signed JWT access token.

    Payload includes:
        sub: username
        user_id: user ID
        roles: list of role names
        jti: unique UUID4 string for session revocation
        iat: UTC timestamp of issuance
        exp: UTC timestamp of expiration
    """
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)

    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.setdefault("jti", str(uuid.uuid4()))
    to_encode["iat"] = now_utc
    to_encode["exp"] = expire

    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT token's signature and expiration.

    Returns:
        dict: The decoded payload dictionary.

    Raises:
        jwt.ExpiredSignatureError: If the token has expired.
        jwt.InvalidTokenError: If the signature is invalid or token is malformed.
    """
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
    return payload
