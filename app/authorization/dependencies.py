"""
Dependencias de Autorización y Control de Acceso RBAC (app/authorization/dependencies.py).
Implementa la verificación de permisos basada en roles (Role-Based Access Control)
para restringir el acceso a funciones y endpoints privilegiados.

Requerimientos y Casos de Prueba asociados:
- RF-06 / RF-09: Control de acceso basado en roles para administración del sistema.
- CP-S05: Rechazo de usuarios sin privilegios (HTTP 403 Forbidden) y auditoría inmutable.
- RNF-05: Registro inmutable de eventos 'access_denied' en la tabla audit_log.
"""

from typing import Callable
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit.service import get_client_ip, log_audit_event
from app.auth.dependencies import get_current_user
from app.database import get_db
from app.models import User


def require_role(role_name: str) -> Callable[..., User]:
    """
    Fábrica de dependencias (Dependency Factory) para autorizar accesos por rol (RBAC).

    ¿Cómo opera el control de acceso en el Caso de Prueba CP-S05?
    --------------------------------------------------------------
    1. Inyección Previa del Usuario Autenticado:
       Invoca `get_current_user`, asegurando que el token sea válido, no haya expirado
       y su sesión en la BD no esté revocada.
    2. Inspección de Roles Asignados:
       Extrae los nombres de los roles vinculados al usuario desde la tabla asociativa `user_roles`.
    3. Evaluación de Privilegios:
       - Si el rol requerido (ej. 'admin') está presente en `user_roles`, la petición
         continúa sin fricción retornando el objeto `current_user`.
       - Si el usuario carece del rol (ej. un usuario común 'user' intentando acceder a
         /api/admin/users o /api/admin/audit-logs):
         * Captura la IP de origen del cliente.
         * Inserta un registro inmutable en `audit_log` con tipo de evento `access_denied`
           y detalles forenses (ruta solicitada, roles del usuario y rol exigido).
         * Interrumpe la petición con HTTP 403 Forbidden: "Forbidden: '<role>' role is required."

    Args:
        role_name (str): Nombre del rol exigido para la operación (ej. 'admin').

    Returns:
        Callable: Función validadora que FastAPI ejecuta como dependencia.
    """
    def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        user_roles = [r.name for r in current_user.roles]
        if role_name not in user_roles:
            client_ip = get_client_ip(request)
            # RNF-05 / CP-S05: Registrar intento de acceso no autorizado en bitácora inmutable
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
            # Rechazar tajantemente con HTTP 403 Forbidden
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: '{role_name}' role is required.",
            )
        return current_user

    return role_checker

