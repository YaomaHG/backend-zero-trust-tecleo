"""
Dependencias de Autenticación y Validación de Sesión Zero Trust (app/auth/dependencies.py).
Extrae y valida credenciales criptográficas (JWT) desde cookies seguras o cabeceras Bearer,
e impone la verificación continua de revocación en la base de datos relacional.

Requerimientos y Casos de Prueba asociados:
- RF-01 / CP-S01: Autenticación obligatoria para acceso a recursos.
- RF-02 / CP-S02: Detección y rechazo de tokens expirados ('Token has expired').
- CP-S03: Verificación criptográfica contra tokens alterados o con firma inválida.
- RF-08: Validación de que la sesión no haya sido revocada ('revoked == False') en BD.
- RNF-04 / CP-S06: Comprobación de estado de bloqueo de cuenta ('is_account_locked').
"""

from datetime import datetime, timezone
from typing import Optional
from fastapi import Depends, HTTPException, Request, status
import jwt
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database import get_db
from app.models import Session as UserSession, User


def is_account_locked(locked_until: Optional[datetime]) -> bool:
    """
    Verifica si una cuenta se encuentra actualmente bloqueada por fuerza bruta (RNF-04, CP-S06).

    Args:
        locked_until (Optional[datetime]): Marca temporal límite del bloqueo.

    Returns:
        bool: True si la fecha actual es anterior a locked_until; False si ya expiró o es None.
    """
    if locked_until is None:
        return False
    now = datetime.now(timezone.utc)
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return locked_until > now


def is_session_expired(expires_at: Optional[datetime]) -> bool:
    """
    Verifica si una sesión ha superado su fecha de expiración configurada (CP-S02).

    Args:
        expires_at (Optional[datetime]): Marca temporal de expiración de la sesión.

    Returns:
        bool: True si la sesión expiró o es nula; False si aún se encuentra en ventana válida.
    """
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
    Dependencia central de FastAPI para autenticar peticiones bajo principios Zero Trust.

    Pasos de Verificación Continua:
    -------------------------------
    1. Extracción de Token Prioritaria:
       Busca primero la cookie segura `access_token` (inyectada con HttpOnly y SameSite=Strict).
       Si no existe, busca la cabecera `Authorization: Bearer <token>` para compatibilidad con APIs.
       Si ninguna está presente, rechaza con HTTP 401 Unauthorized (CP-S01).

    2. Validación Criptográfica del Token JWT (RF-02):
       Invoca `decode_access_token`:
       - Si la firma HMAC-SHA256 fue alterada (CP-S03), arroja `jwt.InvalidTokenError` -> HTTP 401.
       - Si la fecha 'exp' venció (CP-S02), arroja `jwt.ExpiredSignatureError` -> HTTP 401.

    3. Verificación de Estado en Base de Datos (RF-08 - "Never Trust, Always Verify"):
       A diferencia de sistemas JWT ingenuos que aceptan el token sin consultar el backend,
       aquí se consulta la tabla `sessions`:
       - Si el registro no existe o `session_record.revoked == True` (debido a logout o
         a detección de un impostor biométrico), se rechaza de inmediato con HTTP 401.
       - Si la sesión en BD está vencida (`is_session_expired`), se rechaza con HTTP 401.

    4. Comprobación del Usuario:
       Valida que el usuario exista en la BD y mantenga su estado `is_active = True`.

    5. Inyección en el Contexto de la Petición:
       Almacena `request.state.current_user`, `request.state.session` y `request.state.token`
       para que dependencias posteriores (como auditoría o reautenticación) no dupliquen consultas.

    Returns:
        User: Entidad del usuario autenticado y verificado.
    """
    # 1. Extracción desde cookie HttpOnly
    token = request.cookies.get("access_token")

    # Respaldo en cabecera Authorization Bearer
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

    # 2. Validación de firma criptográfica y expiración del JWT (CP-S02, CP-S03)
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

    # 3. Comprobación de estado activo y no revocado en la tabla 'sessions' (RF-08)
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

    # 4. Validar existencia del usuario y su estado activo
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 5. Guardar estado en el request para uso posterior en cascada
    request.state.current_user = user
    request.state.session = session_record
    request.state.token = token

    return user

