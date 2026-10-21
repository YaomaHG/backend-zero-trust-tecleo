"""
Módulo de Seguridad, Hashing y Tokens JWT (app/core/security.py).
Implementa la gestión de credenciales con hashing adaptativo (bcrypt) y la
emisión y validación de JSON Web Tokens (JWT) bajo la especificación RFC 7519.

Requerimientos y Casos de Prueba asociados:
- RF-01 / CP-S01: Autenticación de usuarios y generación de sesión.
- RF-02 / CP-S02: Expiración de tokens de acceso (validación de claim 'exp').
- CP-S03: Integridad de tokens y detección de firmas alteradas ('InvalidTokenError').
- RF-06 / CP-S05: Inclusión de roles en el token para control de acceso RBAC ('roles').
- RF-08: Revocación de sesiones mediante el identificador único 'jti' (UUIDv4).
- RNF-04: Hashing seguro de contraseñas con sal aleatoria (bcrypt).
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import jwt
from passlib.context import CryptContext
from app.core.config import settings

# =============================================================================
# CONTEXTO DE HASHING DE CONTRASEÑAS (BCRYPT) - RNF-04
# Bcrypt utiliza un factor de costo adaptativo y genera automáticamente una sal
# (salt) criptográfica aleatoria de 128 bits para cada contraseña. Esto evita
# ataques de tablas arcoíris (Rainbow Tables) y retarda ataques de fuerza bruta.
# =============================================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Calcula el hash seguro de una contraseña en texto plano utilizando bcrypt (RNF-04).

    El resultado incluye el identificador de algoritmo ($2b$), el costo ($12$),
    la sal generada aleatoriamente y el digest final, todo empaquetado en una cadena.

    Args:
        password (str): Contraseña en texto plano ingresada por el usuario.

    Returns:
        str: Hash seguro resultante de 60 caracteres.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica si una contraseña en texto plano coincide con el hash bcrypt almacenado.

    Utiliza comparación en tiempo constante para mitigar ataques de tiempo (Timing Attacks).

    Args:
        plain_password (str): Contraseña en texto plano a verificar.
        hashed_password (str): Hash almacenado en la base de datos.

    Returns:
        bool: True si la contraseña es correcta; False en caso contrario.
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Crea y firma criptográficamente un token de acceso JWT (JSON Web Token) con HS256.

    Estructura detallada del Payload (Claims del JWT):
    --------------------------------------------------
    - 'sub' (Subject): Identificador principal del sujeto (username del usuario).
    - 'user_id': Clave primaria entera del usuario en la base de datos relacional.
    - 'roles': Arreglo de cadenas con los nombres de roles para RBAC (ej. ["admin", "user"]).
               Requisito RF-06 y Caso de Prueba CP-S05.
    - 'jti' (JWT ID): Identificador criptográfico único global (UUIDv4).
               Vínculo clave con la tabla `sessions.jwt_token` en PostgreSQL.
               Permite invalidar/revocar una sesión específica inmediatamente (RF-08)
               incluso antes de que el token alcance su tiempo de expiración 'exp'.
    - 'iat' (Issued At): Marca de tiempo UTC del momento exacto de emisión.
    - 'exp' (Expiration Time): Marca de tiempo UTC en que el token expira (30 minutos).
               Requisito RF-02 y Caso de Prueba CP-S02.

    Args:
        data (Dict[str, Any]): Datos de identidad a empaquetar en los claims.
        expires_delta (Optional[timedelta]): Tiempo de vida personalizado opcional.

    Returns:
        str: Token JWT codificado y firmado con la clave simétrica y algoritmo HS256.
    """
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)

    # Determinar el tiempo de expiración (por defecto 30 minutos según config)
    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Asignar jti único para trazabilidad y revocación si no viene predefinido
    to_encode.setdefault("jti", str(uuid.uuid4()))
    to_encode["iat"] = now_utc
    to_encode["exp"] = expire

    # Firmar el payload con la clave secreta HMAC-SHA256
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodifica y valida criptográficamente la firma y vigencia de un token JWT.

    Validaciones realizadas:
    ------------------------
    1. Verifica que la firma HMAC coincida con settings.JWT_SECRET_KEY.
       Si un atacante modificó los claims o el header (CP-S03), arroja `jwt.InvalidTokenError`.
    2. Verifica que la marca temporal 'exp' sea posterior al instante UTC actual.
       Si el token ha caducado (CP-S02), arroja `jwt.ExpiredSignatureError`.

    Args:
        token (str): Cadena del token JWT recibido desde la cookie o cabecera Authorization.

    Returns:
        Dict[str, Any]: Diccionario con el payload decodificado y verificado.

    Raises:
        jwt.ExpiredSignatureError: Cuando el token ha expirado (CP-S02).
        jwt.InvalidTokenError: Cuando la firma no es válida o el token está corrupto (CP-S03).
    """
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
    )
    return payload

