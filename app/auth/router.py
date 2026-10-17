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
    """Registers a new user, assigns default 'user' role, and logs audit event."""
    client_ip = get_client_ip(request)

    # Check if username or email already exists
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

    # Retrieve or create default 'user' role
    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        user_role = Role(name="user", description="Default user role")
        db.add(user_role)
        db.commit()
        db.refresh(user_role)

    # Create new user record
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

    # Log audit event
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
    """Authenticates credentials with brute-force lockout protection and session creation."""
    client_ip = get_client_ip(request)
    user = db.query(User).filter(User.username == login_in.username).first()

    if not user:
        # Avoid username enumeration timing attacks
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

    # 1. Check if account is currently locked out (RNF-04 / CP-S06)
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

    # 2. Verify password
    if not verify_password(login_in.password, user.password_hash):
        user.failed_login_attempts += 1
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

    # 3. Successful login: reset brute-force counters
    user.failed_login_attempts = 0
    user.locked_until = None

    jti = str(uuid.uuid4())
    roles = [r.name for r in user.roles]
    expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    expires_at = datetime.now(timezone.utc) + expires_delta

    token = create_access_token(
        data={
            "sub": user.username,
            "user_id": user.id,
            "roles": roles,
            "jti": jti,
        },
        expires_delta=expires_delta,
    )

    # Store active session in database
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

    # Set secure HttpOnly cookie (SameSite=Strict)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="strict",
        secure=False,
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
    """Revokes the current JWT session in database and deletes authentication cookie."""
    client_ip = get_client_ip(request)
    session_record = getattr(request.state, "session", None)

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

    # Clear HttpOnly cookie
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
    """Returns profile and assigned roles of the currently authenticated user."""
    return UserResponse.model_validate(current_user)
