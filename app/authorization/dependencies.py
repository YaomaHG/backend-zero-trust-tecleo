from typing import Callable
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit.service import get_client_ip, log_audit_event
from app.auth.dependencies import get_current_user
from app.database import get_db
from app.models import User


def require_role(role_name: str) -> Callable[..., User]:
    """
    Dependency factory that verifies the current user has the specified role (RF-06, RF-09, CP-S05).
    If unauthorized, logs an 'access_denied' event in audit_log and returns 403 Forbidden.
    """
    def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        user_roles = [r.name for r in current_user.roles]
        if role_name not in user_roles:
            client_ip = get_client_ip(request)
            log_audit_event(
                db=db,
                event_type="access_denied",
                user_id=current_user.id,
                ip_address=client_ip,
                details={
                    "required_role": role_name,
                    "user_roles": user_roles,
                    "path": request.url.path,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: '{role_name}' role is required.",
            )
        return current_user

    return role_checker
