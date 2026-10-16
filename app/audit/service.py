from typing import Any, Dict, Optional
from fastapi import Request
from sqlalchemy.orm import Session
from app.models import AuditLog


def get_client_ip(request: Request) -> str:
    """Extracts client IP address considering proxy headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


def log_audit_event(
    db: Session,
    event_type: str,
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Inserts a security audit record into the immutable audit_log table (RF-07, RNF-05).

    Args:
        db: SQLAlchemy session
        event_type: Categorical audit event identifier (e.g., 'login_success', 'account_locked')
        user_id: ID of the user performing or targeted by the action (if identified)
        ip_address: Source IPv4 or IPv6 address
        details: Additional structured context/metadata serialized to JSON

    Returns:
        AuditLog: The persisted audit record
    """
    audit_entry = AuditLog(
        user_id=user_id,
        event_type=event_type,
        ip_address=ip_address,
        details=details or {},
    )
    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry
