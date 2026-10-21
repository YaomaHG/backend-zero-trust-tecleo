"""
Enrutador de Autenticación de Usuarios y Gestión de Sesiones (app/auth/router.py).
Implementa los flujos de registro, inicio de sesión seguro, cierre de sesión y consulta
del perfil actual bajo directrices de seguridad defensiva y principios Zero Trust.

Requerimientos y Casos de Prueba asociados:
- RF-01 / CP-S01: Registro y autenticación de usuarios.
- RF-02: Emisión de tokens de acceso y cookies de sesión seguras.
- RNF-04 / CP-S06: Protección contra ataques de fuerza bruta (bloqueo tras 10 intentos fallidos).
- RF-08: Revocación inmediata de sesión en base de datos al cerrar sesión.
- RNF-03: Limitación de tasa de peticiones mediante RateLimiter.
"""

import uuid
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.audit.service import get_client_ip, log_audit_event
from app.auth.dependencies import get_current_user, is_account_locked
from app.core.config import settings
from app.core.rate_limiter import check_rate_limit
from app.core.security import create_access_token, hash_password, verify_password
from app.database import get_db
from app.models import Role, Session as UserSession, User
from app.schemas import TokenResponse, UserCreate, UserLogin, UserResponse

router = APIRouter()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account (RF-01)",
)
def register(
    user_in: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    Registra una nueva cuenta de usuario en el sistema (RF-01).

    Flujo de ejecución:
    1. Captura la dirección IP del cliente para trazabilidad forense.
    2. Valida unicidad de nombre de usuario y correo electrónico.
    3. Asigna automáticamente el rol base 'user' (RBAC).
    4. Hashea la contraseña en texto plano utilizando bcrypt con sal única (RNF-04).
    5. Persiste el registro en la tabla 'users' de PostgreSQL (CP-S09).
    6. Emite un evento inmutable en 'audit_log' ('user_registered').
    """
    client_ip = get_client_ip(request)

    # Validación de duplicados para evitar colisiones
    if db.query(User).filter(User.username == user_in.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username is already registered",
        )
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is already registered",
        )

    # Obtener o aprovisionar el rol por defecto 'user'
    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        user_role = Role(name="user", description="Default user role")
        db.add(user_role)
        db.commit()
        db.refresh(user_role)

    # Creación del usuario con contraseña hasheada con bcrypt
    new_user = User(
        username=user_in.username,
        email=user_in.email,
        password_hash=hash_password(user_in.password),
        is_active=True,
    )
    new_user.roles.append(user_role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # RNF-05: Registro inmutable en auditoría
    log_audit_event(
        db=db,
        event_type="user_registered",
        user_id=new_user.id,
        ip_address=client_ip,
        details={"username": new_user.username, "email": new_user.email},
    )

    return UserResponse.model_validate(new_user)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and issue JWT cookie/token (RF-02, RNF-03, RNF-04, CP-S06)",
)
def login(
    login_in: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    _rate_limit: None = Depends(check_rate_limit),
) -> TokenResponse:
    """
    Autentica credenciales y emite tokens JWT y cookies seguras.

    Flujo detallado de Seguridad y Casos de Prueba:
    -------------------------------------------------
    1. Mitigación de Enumeración de Usuarios:
       Si el usuario no existe, se registra 'login_failed' y se devuelve HTTP 401 genérico
       ('Invalid username or password') para evitar revelar si un nombre de usuario existe.

    2. Verificación de Bloqueo por Fuerza Bruta (RNF-04 / Caso CP-S06):
       Se evalúa si `user.locked_until` está activo en el tiempo presente.
       Si la cuenta está bloqueada, se rechaza de inmediato con HTTP 403 Forbidden
       sin procesar la contraseña, impidiendo ataques de fuerza bruta continuos.

    3. Verificación de Contraseña y Bloqueo Escalonado (CP-S06):
       - Se valida la contraseña con `verify_password` (bcrypt).
       - Si es incorrecta: se incrementa `user.failed_login_attempts`.
         * Si alcanza 10 intentos consecutivos: se establece `user.locked_until = now + 15 min`,
           se registra `account_locked` en auditoría y se responde HTTP 403 Forbidden.
         * Si es menor a 10: se responde HTTP 401 Unauthorized y se registra `login_failed`.

    4. Autenticación Exitosa y Restablecimiento de Contadores:
       - Se reinician `failed_login_attempts = 0` y `locked_until = None`.

    5. Generación de Token JWT y Registro de Sesión (RF-01, RF-02, RF-08):
       - Se genera un identificador único `jti` (UUIDv4).
       - Se firma el token JWT con expiración de 30 minutos.
       - Se persiste la sesión en la tabla 'sessions' con `revoked = False`,
         la IP actual del cliente y la marca temporal biométrica inicial.

    6. Inyección de Cookie Segura (HttpOnly & SameSite=Strict):
       - `httponly=True`: Impide el acceso al token mediante JavaScript (`document.cookie`),
         neutralizando ataques de robo de sesión por XSS (Cross-Site Scripting).
       - `samesite="strict"`: El navegador solo adjunta la cookie en peticiones del
         mismo origen, neutralizando ataques CSRF (Cross-Site Request Forgery).
    """
    client_ip = get_client_ip(request)
    user = db.query(User).filter(User.username == login_in.username).first()

    if not user:
        # Prevención de ataques de enumeración de nombres de usuario
        log_audit_event(
            db=db,
            event_type="login_failed",
            user_id=None,
            ip_address=client_ip,
            details={"username": login_in.username, "reason": "user_not_found"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # 1. Comprobar si la cuenta se encuentra actualmente bloqueada (RNF-04 / CP-S06)
    if is_account_locked(user.locked_until):
        log_audit_event(
            db=db,
            event_type="login_blocked",
            user_id=user.id,
            ip_address=client_ip,
            details={
                "username": user.username,
                "reason": "account_temporarily_locked",
                "locked_until": str(user.locked_until),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is temporarily locked due to multiple failed login attempts. Please try again later.",
        )

    # 2. Verificar contraseña con bcrypt
    if not verify_password(login_in.password, user.password_hash):
        user.failed_login_attempts += 1
        # Al alcanzar 10 intentos fallidos: bloqueo temporal de 15 minutos (RNF-04 / CP-S06)
        if user.failed_login_attempts >= 10:
            user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            db.commit()
            log_audit_event(
                db=db,
                event_type="account_locked",
                user_id=user.id,
                ip_address=client_ip,
                details={
                    "username": user.username,
                    "failed_attempts": user.failed_login_attempts,
                    "locked_until": str(user.locked_until),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account locked due to 10 consecutive failed login attempts. Try again in 15 minutes.",
            )
        else:
            db.commit()
            log_audit_event(
                db=db,
                event_type="login_failed",
                user_id=user.id,
                ip_address=client_ip,
                details={
                    "username": user.username,
                    "failed_attempts": user.failed_login_attempts,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

    # 3. Login exitoso: restablecer contadores de fuerza bruta
    user.failed_login_attempts = 0
    user.locked_until = None

    jti = str(uuid.uuid4())
    roles = [r.name for r in user.roles]
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = datetime.now(timezone.utc) + expires_delta

    # Crear token JWT firmado con claims de identidad y roles RBAC (RF-02, RF-06)
    token = create_access_token(
        data={
            "sub": user.username,
            "user_id": user.id,
            "roles": roles,
            "jti": jti,
        },
        expires_delta=expires_delta,
    )

    # Almacenar sesión activa en base de datos para trazabilidad y revocación (RF-08)
    session_record = UserSession(
        user_id=user.id,
        jwt_token=token,
        ip_address=client_ip,
        expires_at=expires_at,
        revoked=False,
        last_biometric_verified_at=datetime.now(timezone.utc),
    )
    db.add(session_record)
    db.commit()
    db.refresh(session_record)

    log_audit_event(
        db=db,
        event_type="login_success",
        user_id=user.id,
        ip_address=client_ip,
        details={"session_id": session_record.id, "jti": jti},
    )

    # Inyectar cookie segura con flags HttpOnly y SameSite=Strict
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,   # Mitiga robo de token vía XSS
        samesite="strict", # Mitiga ataques CSRF
        secure=False,    # True en HTTPS de producción
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Revoke session and clear access token cookie (RF-08)",
)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """
    Revoca la sesión actual en la base de datos y destruye la cookie de acceso (RF-08).

    A diferencia de arquitecturas JWT convencionales sin estado, aquí el principio
    Zero Trust revoca inmediatamente el registro en la tabla 'sessions' (`revoked = True`),
    haciendo que el token no pueda ser reutilizado aunque no haya vencido.
    """
    client_ip = get_client_ip(request)
    session_record = getattr(request.state, "session", None)

    # Invalidar sesión en BD para revocar el token de forma permanente (RF-08)
    if session_record:
        session_record.revoked = True
        db.commit()
    else:
        token = getattr(request.state, "token", None)
        if token:
            s = db.query(UserSession).filter(UserSession.jwt_token == token).first()
            if s:
                s.revoked = True
                db.commit()

    # Eliminar la cookie HttpOnly en el cliente
    response.delete_cookie(
        key="access_token",
        httponly=True,
        samesite="strict",
    )

    log_audit_event(
        db=db,
        event_type="logout",
        user_id=current_user.id,
        ip_address=client_ip,
        details={"session_id": session_record.id if session_record else None},
    )

    return {"message": "Logged out successfully"}


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current authenticated user info and roles (RF-06)",
)
def get_me(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Retorna los datos del usuario autenticado y sus roles asignados (RF-06)."""
    return UserResponse.model_validate(current_user)

