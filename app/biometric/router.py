"""
Enrutador de Endpoints de Biometría de Dinámica de Tecleo (app/biometric/router.py).
Expone las operaciones de enrolamiento de perfiles, consulta de estado y
verificación biométrica activa bajo el modelo Zero Trust.

Requerimientos y Casos de Prueba asociados:
- RF-03 / RNF-01: Enrolamiento de plantilla de tecleo cifrada en reposo (AES-256-GCM).
- RF-05 / CP-S08: Verificación biométrica con scoring híbrido frente a umbral óptimo.
- RNF-08: Minimización de datos (sin almacenar texto ni caracteres).
- RNF-05: Auditoría inmutable de eventos 'biometric_enrolled' y 'biometric_verify_success/failed'.
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
    Enrola o actualiza el perfil biométrico de tecleo del usuario autenticado (RF-03).

    Flujo:
    1. Recibe 3 a 5 muestras de la frase '.tie5Roanl' o eventos de tiempo puros (RNF-08).
    2. Calcula la media de referencia y la cifra con AES-256-GCM (RNF-01).
    3. Persiste el criptograma en la columna `vector_encrypted` (BYTEA) de PostgreSQL.
    4. Registra en `audit_log` el evento inmutable `biometric_enrolled` con la longitud del vector.
    """
    ip = get_client_ip(request)
    profile = biometric_service.enroll_keystroke_profile(
        db=db,
        user=current_user,
        vector=payload.vector,
        samples=payload.samples,
        raw_events=payload.raw_events,
    )

    # Determinar longitud del vector descifrado para auditoría técnica
    decrypted = decrypt_vector(profile.vector_encrypted)
    vector_len = len(decrypted)

    # RNF-05: Registro inmutable en auditoría
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
    Consulta si el usuario autenticado tiene enrolado un perfil biométrico activo.
    Permite al front-end decidir si mostrar el asistente de enrolamiento inicial.
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
    Verifica una muestra candidata de tecleo contra la plantilla del usuario (RF-05, CP-S08).

    Flujo:
    1. Procesa el vector recibido (o extrae características a partir de raw_events).
    2. Ejecuta la inferencia híbrida (Gradient Boosting + Similitud Estadística) en BiometricService.
    3. Compara el score resultante contra el umbral de seguridad (0.4024).
    4. Registra `biometric_verify_success` o `biometric_verify_failed` en la bitácora inmutable.
    5. Retorna si hubo coincidencia (`match`), el `score` obtenido y el `threshold` aplicado.
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

