from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class UserCreate(BaseModel):
    """Schema for user registration."""
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: str = Field(..., min_length=5, max_length=255, description="Unique user email")
    password: str = Field(..., min_length=6, max_length=128, description="Plaintext password")


class UserLogin(BaseModel):
    """Schema for user login credentials."""
    username: str = Field(..., description="Registered username")
    password: str = Field(..., description="Account password")


class RoleResponse(BaseModel):
    """Schema for returning role information."""
    id: int
    name: str
    description: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class RoleAssign(BaseModel):
    """Schema for assigning a role to a user."""
    role_name: str = Field(..., description="Role name to assign (e.g. 'admin', 'user')")


class UserResponse(BaseModel):
    """Schema for returning user data and assigned roles."""
    id: int
    username: str
    email: str
    is_active: bool
    roles: List[str] = []
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_validator("roles", mode="before")
    @classmethod
    def serialize_roles(cls, v: Any) -> List[str]:
        if isinstance(v, list):
            res = []
            for item in v:
                if hasattr(item, "name"):
                    res.append(item.name)
                elif isinstance(item, dict) and "name" in item:
                    res.append(item["name"])
                else:
                    res.append(str(item))
            return res
        return v


class TokenResponse(BaseModel):
    """Schema for authentication token response."""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class AuditLogResponse(BaseModel):
    """Schema for security audit trail records."""
    id: int
    user_id: Optional[int] = None
    event_type: str
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class KeystrokeEnrollRequest(BaseModel):
    """Schema for keystroke profile enrollment (RF-03, RNF-08)."""
    vector: Optional[List[float]] = Field(None, description="Direct feature vector of timing dynamics")
    samples: Optional[List[List[float]]] = Field(None, description="Multiple sample vectors to calculate mean template")
    raw_events: Optional[List[Dict[str, float]]] = Field(None, description="Raw timing events (press/release) without key characters")


class KeystrokeVerifyRequest(BaseModel):
    """Schema for keystroke verification sample (RF-05, RNF-08)."""
    vector: Optional[List[float]] = Field(None, description="Verification timing feature vector")
    raw_events: Optional[List[Dict[str, float]]] = Field(None, description="Raw timing events (press/release) without key characters")


class KeystrokeVerifyResponse(BaseModel):
    """Schema for biometric verification result."""
    match: bool
    score: float
    threshold: float
    message: Optional[str] = None


class KeystrokeStatusResponse(BaseModel):
    """Schema for biometric enrollment status response."""
    enrolled: bool
    user_id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
