"""
Enrutador de Autorización Administrativa y Auditoría (app/authorization/router.py).
Expone las operaciones protegidas por el esquema de control de acceso RBAC
exclusivas para usuarios con el rol 'admin'.

Requerimientos y Casos de Prueba asociados:
- RF-06 / RF-09: Gestión y asignación de roles a usuarios.
- RF-07 / RNF-05: Consulta y visualización de la bitácora inmutable de auditoría.
- CP-S05: Protección de endpoints mediante la dependencia 'require_role("admin")'.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit.service import get_client_ip, log_audit_event
from app.authorization.dependencies import require_role
from app.database import get_db
from app.models import AuditLog, Role, User
from app.schemas import AuditLogResponse, RoleAssign, UserResponse

router = APIRouter()


@router.get(
    "/users",
    response_model=List[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="List all registered users (RF-09, requires 'admin' role)",
    dependencies=[Depends(require_role("admin"))],
)
def list_users(
    db: Session = Depends(get_db),
) -> List[UserResponse]:
    """
    Lista todos los usuarios registrados y sus roles asociados (RF-09).
    Restringido exclusivamente a administradores mediante `require_role("admin")`.
    """
    users = db.query(User).order_by(User.id.asc()).all()
    return [UserResponse.model_validate(u) for u in users]


@router.post(
    "/users/{user_id}/roles",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Assign role to a user (RF-06, RF-09, requires 'admin' role)",
)
def assign_role_to_user(
    user_id: int,
    role_data: RoleAssign,
    request: Request,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_role("admin")),
) -> UserResponse:
    """
    Asigna un nuevo rol de seguridad RBAC a un usuario objetivo (RF-06, RF-09).

    Flujo:
    1. Valida que el usuario que ejecuta la acción tenga el rol 'admin' (CP-S05).
    2. Valida la existencia del usuario objetivo en la base de datos.
    3. Valida la existencia del rol solicitado en el catálogo de roles.
    4. Vincula el rol en la tabla asociativa `user_roles`.
    5. Emite un evento inmutable de auditoría ('role_assigned') con los datos del administrador
       y el rol otorgado para estricta trazabilidad de privilegios.
    """
    client_ip = get_client_ip(request)

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target user not found",
        )

    role = db.query(Role).filter(Role.name == role_data.role_name).first()
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Role '{role_data.role_name}' does not exist",
        )

    if role not in target_user.roles:
        target_user.roles.append(role)
        db.commit()
        db.refresh(target_user)

    # RNF-05: Auditoría inmutable de elevación de privilegios
    log_audit_event(
        db=db,
        event_type="role_assigned",
        user_id=admin_user.id,
        ip_address=client_ip,
        details={
            "target_user_id": target_user.id,
            "target_username": target_user.username,
            "assigned_role": role.name,
        },
    )

    return UserResponse.model_validate(target_user)


@router.get(
    "/audit-logs",
    response_model=List[AuditLogResponse],
    status_code=status.HTTP_200_OK,
    summary="List security audit logs (RF-07, RNF-05, requires 'admin' role)",
    dependencies=[Depends(require_role("admin"))],
)
def list_audit_logs(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> List[AuditLogResponse]:
    """
    Consulta la bitácora inmutable de auditoría forense (RF-07, RNF-05).
    Exclusivo para administradores. Retorna eventos ordenados cronológicamente
    de forma descendente con soporte de paginación ('limit' y 'offset').
    """
    logs = (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [AuditLogResponse.model_validate(log) for log in logs]

