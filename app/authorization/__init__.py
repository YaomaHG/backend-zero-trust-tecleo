"""Authorization and RBAC administration module."""

from app.authorization.dependencies import require_role
from app.authorization.router import router

__all__ = ["router", "require_role"]
