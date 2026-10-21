"""
Enrutador de Reautenticación Adaptativa Zero Trust y Operaciones Sensibles (app/reauth/router.py).
Expone los endpoints que materializan la verificación continua de contexto y la
autorización escalonada (Step-Up Authentication) ante anomalías o transacciones críticas.

Requerimientos y Casos de Prueba asociados:
- RF-04 / CP-S07: Detección y respuesta ante cambio de dirección IP ('ip_change').
- CP-S04: Emisión de desafíos con Nonces de un solo uso (/challenge).
- RF-05 / CP-S08: Verificación biomecánica adaptativa y actualización de confianza (/verify).
- Sección 3.3 / RF-04: Protección de operaciones corporativas sensibles (/sensitive-action).
- RF-08: Revocación de sesiones en caso de fallo reiterado o cadencias fraudulentas.
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
    Dependencia de FastAPI para imponer verificación continua Zero Trust (RF-04, CP-S07).

    Intercepta la petición y valida el contexto de red del cliente:
    - Si la IP actual difiere de la IP de login, o si la ventana de 10 minutos expiró:
      Registra 'risk_detected' en la bitácora inmutable y rechaza con HTTP 403 Forbidden
      con el cuerpo `{"reauth_required": True, "risk_event": "ip_change"}`.
    - Si la confianza es plena, permite el paso hacia el endpoint.
    """
    session: UserSession = request.state.session
    client_ip = get_client_ip(request)
    risk_info = evaluate_session_risk(session, client_ip)

    if risk_info["reauth_required"]:
        # RNF-05: Auditoría inmutable de detección de anomalía contextual
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
    Evalúa continuamente el riesgo contextual de la sesión activa (Caso CP-S07).

    Permite al front-end consultar si la sesión sigue siendo de confianza:
    - Si se detecta un cambio de IP (CP-S07), responde HTTP 403 con `reauth_required: True`,
      detalles del evento `ip_change` y registra la alerta en `audit_log`.
    - Si la sesión es confiable, responde HTTP 200 con `reauth_required: False`.
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
                "message": risk_info["reason"],
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
    """
    Genera un desafío criptográfico de un solo uso (Nonce) para la reautenticación (CP-S04).

    Propiedades:
    - Protegido por limitador de tasa de 5 peticiones/minuto (RNF-03).
    - Entrega al cliente el `challenge_nonce` (32 bytes), la frase objetivo obligatoria
      ('.tie5Roanl') y el tiempo de vida en segundos (300 s / 5 minutos).
    - Emite el evento inmutable `reauth_challenge_issued` en `audit_log`.
    """
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
    Verifica la muestra de tecleo enviada en respuesta a un desafío Zero Trust (RF-05, CP-S08).

    Validaciones y Resultados:
    1. Comprueba y quema el Nonce de un solo uso (CP-S04).
    2. Compara el vector de 31 características contra la plantilla cifrada del usuario.
    3. Si el usuario es legítimo (Score >= 0.4024): Actualiza la sesión y retorna éxito (HTTP 200).
    4. Si falla o es impostor: Aplica la regla de 3 reintentos o revoca la sesión de inmediato
       si es un ataque burdo o acumula 3 fallos (HTTP 403 con `session_revoked: True`).
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

    if isinstance(result, JSONResponse):
        return result

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
    Simula una operación bancaria/corporativa sensible bajo directrices Zero Trust (Sección 3.3).

    Condiciones Cero Confianza para Autorizar la Acción:
    ----------------------------------------------------
    1. Ausencia de anomalías de red (CP-S07):
       Si la IP cambió y no ha sido verificada biométricamente, se deniega con HTTP 403
       y se exige reautenticación por evento `ip_change`.
    2. Elevación de Privilegios Biométrica Fresca (Step-Up Reauthentication):
       Debe existir un registro exitoso en `reauth_events` con `risk_event = 'sensitive_operation'`
       ejecutado en los últimos 5 minutos. Si no existe, se rechaza con HTTP 403 exigiendo
       teclear la frase de referencia obligatoria `.tie5Roanl`.
    3. Ejecución Autorizada:
       Se ejecuta la acción solicitada (ej. transferencia de $95,000 MXN) y se registra
       el evento inmutable `sensitive_operation_executed` en la bitácora de auditoría.
    """
    session: UserSession = request.state.session
    client_ip = get_client_ip(request)

    # 1. Comprobar si hubo cambio de IP no verificado (Caso CP-S07)
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
        msg = f"IP change detected from {session.ip_address} to {client_ip}. Reauthentication required before executing sensitive operations."
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "reauth_required": True,
                "risk_event": "ip_change",
                "detail": msg,
                "message": msg,
                "current_ip": client_ip,
                "session_ip": session.ip_address,
            },
        )

    # 2. Comprobar reautenticación biométrica reciente por 'sensitive_operation' (últimos 5 minutos)
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
        op_msg = "Sensitive corporate operation requires recent biometric reauthentication."
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "reauth_required": True,
                "risk_event": "sensitive_operation",
                "detail": op_msg,
                "message": op_msg,
                "current_ip": client_ip,
                "session_ip": session.ip_address,
            },
        )

    # 3. Ejecución autorizada de la operación sensible
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

