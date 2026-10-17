"""
Biometric Dynamics API Endpoints
(RF-03, RF-05, RNF-01, RNF-08, CP-S08)
"""

import logging
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, KeystrokeProfile
from app.auth.dependencies import get_current_user
from app.audit.service import log_audit_event, get_client_ip
from app.schemas.schemas import (
    KeystrokeEnrollRequest,
    KeystrokeVerifyRequest,
    KeystrokeVerifyResponse,
    KeystrokeStatusResponse,
)
from app.biometric.service import biometric_service
from app.core.crypto import decrypt_vector

logger = logging.getLogger("zero_trust_biometric_router")

router = APIRouter()


@router.post(
    "/enroll",
    status_code=status.HTTP_200_OK,
    summary="Enroll or update keystroke dynamics profile (RF-03)",
)
def enroll_keystroke_profile(
    payload: KeystrokeEnrollRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Enrolls or updates the biometric keystroke profile for the authenticated user (RF-03).
    Templates are encrypted at rest with AES-256-GCM (RNF-01).
    Logs 'biometric_enrolled' in audit_log.
    """
    ip = get_client_ip(request)
    profile = biometric_service.enroll_keystroke_profile(
        db=db,
        user=current_user,
        vector=payload.vector,
        samples=payload.samples,
        raw_events=payload.raw_events,
    )

    # Determine vector length for metadata audit
    decrypted = decrypt_vector(profile.vector_encrypted)
    vector_len = len(decrypted)

    log_audit_event(
        db=db,
        event_type="biometric_enrolled",
        user_id=current_user.id,
        ip_address=ip,
        details={
            "vector_length": vector_len,
            "samples_count": len(payload.samples) if payload.samples else 1,
            "profile_id": profile.id,
        },
    )

    return {
        "status": "success",
        "message": "Biometric keystroke dynamics profile enrolled successfully.",
        "vector_length": vector_len,
    }


@router.get(
    "/status",
    response_model=KeystrokeStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Check biometric profile enrollment status",
)
def get_biometric_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> KeystrokeStatusResponse:
    """
    Returns whether the current user has an enrolled keystroke profile.
    """
    profile = (
        db.query(KeystrokeProfile)
        .filter(KeystrokeProfile.user_id == current_user.id)
        .first()
    )

    return KeystrokeStatusResponse(
        enrolled=profile is not None,
        user_id=current_user.id,
        created_at=profile.created_at if profile else None,
        updated_at=profile.updated_at if profile else None,
    )


@router.post(
    "/verify",
    response_model=KeystrokeVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify keystroke pattern against enrolled template (RF-05, CP-S08)",
)
def verify_keystroke_pattern(
    payload: KeystrokeVerifyRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> KeystrokeVerifyResponse:
    """
    Verifies a keystroke dynamics timing sample against the user's enrolled profile (RF-05).
    Logs 'biometric_verify_success' or 'biometric_verify_failed' in audit_log.
    """
    ip = get_client_ip(request)
    result = biometric_service.verify_keystroke_pattern(
        db=db,
        user=current_user,
        vector=payload.vector,
        raw_events=payload.raw_events,
    )

    match = result["match"]
    score = result["score"]
    threshold = result["threshold"]

    if match:
        log_audit_event(
            db=db,
            event_type="biometric_verify_success",
            user_id=current_user.id,
            ip_address=ip,
            details={"score": score, "threshold": threshold},
        )
        message = "Keystroke biometric pattern verified successfully."
    else:
        log_audit_event(
            db=db,
            event_type="biometric_verify_failed",
            user_id=current_user.id,
            ip_address=ip,
            details={"score": score, "threshold": threshold},
        )
        message = "Keystroke biometric verification failed: score below security threshold."

    return KeystrokeVerifyResponse(
        match=match,
        score=score,
        threshold=threshold,
        message=message,
    )
