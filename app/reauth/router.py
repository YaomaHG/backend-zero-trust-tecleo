"""
FastAPI Router for Zero Trust Adaptive Reauthentication and Sensitive Corporate Operations
(RF-04, RF-05, RF-08, CP-S04, CP-S07, CP-S08).
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.audit.service import get_client_ip, log_audit_event
from app.auth.dependencies import get_current_user
from app.core.config import settings
from app.core.rate_limiter import check_reauth_rate_limit
from app.database import get_db
from app.models import ReauthEvent, Session as UserSession, User
from app.reauth.service import (
    anti_replay_store,
    evaluate_session_risk,
    verify_reauthentication,
)
from app.schemas import (
    ReauthChallengeResponse,
    ReauthEvaluateResponse,
    ReauthVerifyRequest,
    ReauthVerifyResponse,
    SensitiveActionRequest,
    SensitiveActionResponse,
)

reauth_router = APIRouter()
operations_router = APIRouter()


def require_zero_trust_verification(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserSession:
    """
    Zero Trust continuous verification dependency (RF-04, CP-S07).
    Validates current session context and raises 403 if reauthentication is required.
    """
    session: UserSession = request.state.session
    client_ip = get_client_ip(request)
    risk_info = evaluate_session_risk(session, client_ip)

    if risk_info["reauth_required"]:
        log_audit_event(
            db=db,
            event_type="risk_detected",
            user_id=current_user.id,
            ip_address=client_ip,
            details=risk_info,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "reauth_required": True,
                "risk_event": risk_info["risk_event"],
                "message": risk_info["reason"],
                "current_ip": client_ip,
                "session_ip": session.ip_address,
            },
        )

    return session


@reauth_router.get(
    "/evaluate",
    summary="Evaluate session continuous risk under Zero Trust (RF-04, CP-S07)",
)
def evaluate_risk(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Continuously evaluates session context (IP change, inactivity timeout).
    If risk is detected (e.g. CP-S07 IP change), responds with 403 Forbidden and logs audit.
    """
    session: UserSession = request.state.session
    client_ip = get_client_ip(request)
    risk_info = evaluate_session_risk(session, client_ip)

    if risk_info["reauth_required"]:
        log_audit_event(
            db=db,
            event_type="risk_detected",
            user_id=current_user.id,
            ip_address=client_ip,
            details={
                "session_id": session.id,
                "risk_event": risk_info["risk_event"],
                "reason": risk_info["reason"],
                "session_ip": session.ip_address,
                "current_ip": client_ip,
            },
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "reauth_required": True,
                "risk_event": risk_info["risk_event"],
                "detail": risk_info["reason"],
                "current_ip": client_ip,
                "session_ip": session.ip_address,
            },
        )

    return {
        "reauth_required": False,
        "risk_event": None,
        "detail": "Session trust level is valid.",
        "current_ip": client_ip,
        "session_ip": session.ip_address,
    }


@reauth_router.post(
    "/challenge",
    response_model=ReauthChallengeResponse,
    summary="Generate single-use challenge nonce for typing verification (CP-S04)",
)
def generate_challenge(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _rate_limit: None = Depends(check_reauth_rate_limit),
) -> ReauthChallengeResponse:
    """Generates an anti-replay challenge nonce for keystroke sample submission."""
    session: UserSession = request.state.session
    client_ip = get_client_ip(request)

    nonce = anti_replay_store.generate_challenge(current_user.id, session.id)

    log_audit_event(
        db=db,
        event_type="reauth_challenge_issued",
        user_id=current_user.id,
        ip_address=client_ip,
        details={"session_id": session.id, "nonce_prefix": nonce[:8]},
    )

    return ReauthChallengeResponse(
        challenge_nonce=nonce,
        target_phrase=settings.REAUTH_TARGET_PHRASE,
        expires_in=settings.CHALLENGE_NONCE_TTL_SECONDS,
    )


@reauth_router.post(
    "/verify",
    response_model=ReauthVerifyResponse,
    summary="Verify keystroke sample for adaptive reauthentication (RF-04, RF-05, CP-S04, CP-S08)",
)
def verify_reauth(
    payload: ReauthVerifyRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _rate_limit: None = Depends(check_reauth_rate_limit),
) -> ReauthVerifyResponse:
    """
    Validates anti-replay criteria, verifies keystroke dynamics pattern against encrypted profile,
    records results in reauth_events and audit_log, and updates or revokes the session.
    """
    session: UserSession = request.state.session
    client_ip = get_client_ip(request)

    result = verify_reauthentication(
        db=db,
        user=current_user,
        session=session,
        client_ip=client_ip,
        risk_event=payload.risk_event,
        challenge_nonce=payload.challenge_nonce,
        timestamp=payload.timestamp,
        vector=payload.vector,
        raw_events=payload.raw_events,
    )

    return ReauthVerifyResponse(**result)


@operations_router.post(
    "/sensitive-action",
    response_model=SensitiveActionResponse,
    summary="Simulate sensitive corporate operation under Zero Trust controls (Section 3.3, CP-S07)",
)
def execute_sensitive_action(
    action_in: SensitiveActionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Executes a sensitive corporate action (e.g. simulated fund transfer or critical setting change).
    Zero Trust Requirements:
    1. No unresolved IP change (CP-S07).
    2. Must possess a recent successful biometric reauthentication for 'sensitive_operation'.
    """
    session: UserSession = request.state.session
    client_ip = get_client_ip(request)

    # 1. Check for unverified IP address change (CP-S07)
    if session.ip_address != client_ip:
        log_audit_event(
            db=db,
            event_type="risk_detected",
            user_id=current_user.id,
            ip_address=client_ip,
            details={
                "risk_event": "ip_change",
                "session_ip": session.ip_address,
                "current_ip": client_ip,
                "action": action_in.action_type,
            },
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "reauth_required": True,
                "risk_event": "ip_change",
                "detail": f"IP change detected from {session.ip_address} to {client_ip}. Reauthentication required before executing sensitive operations.",
            },
        )

    # 2. Check for recent successful reauthentication for 'sensitive_operation' (within 5 minutes)
    five_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    recent_reauth = (
        db.query(ReauthEvent)
        .filter(
            ReauthEvent.session_id == session.id,
            ReauthEvent.user_id == current_user.id,
            ReauthEvent.risk_event == "sensitive_operation",
            ReauthEvent.result.is_(True),
            ReauthEvent.timestamp >= five_minutes_ago,
        )
        .order_by(ReauthEvent.timestamp.desc())
        .first()
    )

    if not recent_reauth:
        log_audit_event(
            db=db,
            event_type="reauth_required_sensitive_op",
            user_id=current_user.id,
            ip_address=client_ip,
            details={"action": action_in.action_type},
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "reauth_required": True,
                "risk_event": "sensitive_operation",
                "detail": "Sensitive corporate operation requires recent biometric reauthentication.",
            },
        )

    # 3. Authorized execution
    log_audit_event(
        db=db,
        event_type="sensitive_operation_executed",
        user_id=current_user.id,
        ip_address=client_ip,
        details={
            "action_type": action_in.action_type,
            "amount": action_in.amount,
            "destination_account": action_in.destination_account,
        },
    )

    return SensitiveActionResponse(
        status="success",
        operation=action_in.action_type,
        message="Sensitive corporate operation authorized and executed successfully under Zero Trust controls.",
        executed_at=datetime.now(timezone.utc),
        details={
            "amount": action_in.amount,
            "destination_account": action_in.destination_account,
        },
    )
