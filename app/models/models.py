"""
Modelos Relacionales de Base de Datos con SQLAlchemy 2.0 (app/models/models.py).
Define el esquema relacional en Tercera Forma Normal (3FN) con 7 entidades
diseñadas para soportar la arquitectura Zero Trust, el control de acceso RBAC,
la biometría de tecleo cifrada y la auditoría inmutable de eventos de seguridad.

Requerimientos y Casos de Prueba asociados:
- CP-S09: Resistencia contra Inyección SQL mediante tipos estrictos y ORM.
- CP-S06 / RNF-04: Bloqueo de cuenta por fuerza bruta ('failed_login_attempts', 'locked_until').
- CP-S10 / RNF-01: Almacenamiento cifrado de biometría en reposo ('vector_encrypted').
- RF-08 / CP-S01: Revocación explícita de sesiones en base de datos ('revoked').
- CP-S07 / RF-04: Motor de riesgo contextual Zero Trust ('ip_address', 'last_biometric_verified_at').
- CP-S05 / RF-06: Control de acceso basado en roles RBAC ('Role', 'user_roles').
- RNF-05 / RF-07: Bitácora inmutable de auditoría ('AuditLog').
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    LargeBinary,
    ForeignKey,
    Table,
    Index,
    JSON,
    func,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import relationship

from app.database import Base

# =============================================================================
# TIPO JSON PORTABLE
# Utiliza JSONB nativo de alto rendimiento en PostgreSQL, y retrocede a JSON
# estándar al ejecutarse en SQLite durante la suite de pruebas automatizadas.
# =============================================================================
JSON_TYPE = postgresql.JSONB().with_variant(JSON, "sqlite")

# =============================================================================
# TABLA 1: user_roles (Tabla Asociativa Muchos a Muchos)
# Conecta las entidades 'users' y 'roles' mediante una clave primaria compuesta.
# Soporta RBAC (Role-Based Access Control) para RF-06 y el caso de prueba CP-S05.
# La cláusula ondelete="CASCADE" asegura limpieza íntegra si se elimina un usuario.
# =============================================================================
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column(
        "user_id",
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "role_id",
        Integer,
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


# =============================================================================
# TABLA 2: roles (Catálogo de Roles de Seguridad RBAC)
# Define los niveles de privilegio en el sistema ('admin' y 'user').
# Utilizado por la dependencia `require_role` en app/authorization/dependencies.py.
# =============================================================================
class Role(Base):
    """Modelo relacional para el catálogo de roles del sistema (RF-06, CP-S05)."""
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    users = relationship("User", secondary=user_roles, back_populates="roles")

    def __repr__(self) -> str:
        return f"<Role(name={self.name})>"


# =============================================================================
# TABLA 3: users (Cuentas de Usuario y Controles de Seguridad de Acceso)
# Gestiona credenciales y estado de autenticación.
#
# Columnas Clave de Seguridad:
# - failed_login_attempts: Contador de intentos fallidos consecutivos de contraseña.
#   Se incrementa en cada fallo de login. Al llegar a 10 intentos, activa el bloqueo.
# - locked_until: Marca temporal UTC de expiración del bloqueo de cuenta (15 minutos).
#   Requisito RNF-04 y Caso de Prueba CP-S06: Si locked_until > now(), el login
#   se rechaza tajantemente con HTTP 403 Forbidden, incluso si el atacante
#   envía la contraseña correcta.
# =============================================================================
class User(Base):
    """Modelo relacional de usuarios con mecanismos de protección contra fuerza bruta."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)  # Hash bcrypt con sal (RNF-04)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    is_active = Column(Boolean, default=True, nullable=False)
    # Seguridad: Contador de fallos para protección de fuerza bruta (RNF-04 / CP-S06)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    # Seguridad: Bloqueo temporal por 15 minutos al décimo fallo consecutivo (CP-S06)
    locked_until = Column(DateTime(timezone=True), nullable=True)

    roles = relationship("Role", secondary=user_roles, back_populates="users")
    keystroke_profile = relationship(
        "KeystrokeProfile",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    sessions = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="user",
    )
    reauth_events = relationship(
        "ReauthEvent",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<User(username={self.username})>"


# =============================================================================
# TABLA 4: keystroke_profiles (Plantilla Biométrica de Dinámica de Tecleo)
# Almacena el perfil biomecánico de referencia del usuario (RF-03).
#
# Columna Clave de Seguridad:
# - vector_encrypted: Almacenamiento en binario puro (BYTEA en PostgreSQL).
#   Contiene el vector de 31 características numéricas cifrado en reposo con
#   AES-256-GCM (Nonce 12B + Criptograma + Tag 16B). Cumple con el requisito
#   RNF-01 y es verificado en el caso de prueba CP-S10 (detección de manipulación de bits).
# =============================================================================
class KeystrokeProfile(Base):
    """Modelo relacional para almacenar plantillas biométricas cifradas en reposo."""
    __tablename__ = "keystroke_profiles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    # Seguridad: Vector biométrico cifrado con AES-256-GCM (BYTEA en PostgreSQL) (RNF-01, CP-S10)
    vector_encrypted = Column(LargeBinary, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    user = relationship("User", back_populates="keystroke_profile")

    def __repr__(self) -> str:
        return f"<KeystrokeProfile(user_id={self.user_id})>"


# =============================================================================
# TABLA 5: sessions (Gestión de Sesiones Activas y Motor Zero Trust)
# Rastrea el estado en tiempo real de cada sesión abierta en el sistema.
#
# Columnas Clave de Seguridad:
# - jwt_token: Token JWT firmado (HS256) emitido en el login. Permite contrastar
#   la cookie entrante con el estado real de la sesión.
# - ip_address: Dirección IP de origen donde se inició la sesión. El motor Zero Trust
#   compara esta IP en cada petición; si cambia (Caso CP-S07), exige reautenticación.
# - revoked: Bandera de revocación de sesión (RF-08). Si el usuario hace logout,
#   o si el evaluador biométrico detecta un impostor tras 3 fallos (CP-S08),
#   'revoked' se cambia a True, invalidando el token JWT de forma definitiva.
# - last_biometric_verified_at: Marca de tiempo de la última prueba de vida/tecleo.
#   Si han pasado más de 10 minutos (settings.REAUTH_TIMEOUT_MINUTES), el motor
#   suspende la confianza y solicita reautenticación (RF-04).
# =============================================================================
class Session(Base):
    """Modelo relacional para sesiones activas con revocación y monitoreo continuo Zero Trust."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    jwt_token = Column(String(500), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)  # IP de origen monitoreada para CP-S07
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    # Seguridad: Revocación explícita e inmediata del token en BD (RF-08)
    revoked = Column(Boolean, default=False, nullable=False)
    # Seguridad: Ventana temporal de confianza biométrica de 10 minutos (RF-04)
    last_biometric_verified_at = Column(
        DateTime(timezone=True),
        default=func.now(),
        server_default=func.now(),
        nullable=True,
    )

    user = relationship("User", back_populates="sessions")
    reauth_events = relationship(
        "ReauthEvent",
        back_populates="session",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Session(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"


# =============================================================================
# TABLA 6: audit_log (Bitácora Inmutable de Auditoría de Ciberseguridad)
# Almacena de forma inalterable todos los eventos de seguridad del sistema
# (login, logout, fallos biométricos, ataques de repetición, accesos denegados).
#
# Propiedad de Inmutabilidad (RNF-05 / RF-07):
# Solo admite operaciones INSERT. El servicio no expone endpoints para UPDATE ni DELETE.
# Posee un índice compuesto sobre (user_id, timestamp) para agilizar búsquedas forenses.
# =============================================================================
class AuditLog(Base):
    """Modelo relacional inmutable para la pista de auditoría y trazabilidad forense."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type = Column(String(100), nullable=False, index=True)  # Ej. 'login_failed', 'ip_change'
    details = Column(JSON_TYPE, nullable=True)  # Metadatos del evento en formato JSON estructurado
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user = relationship("User", back_populates="audit_logs")

    # Índice compuesto para optimizar consultas de auditoría por usuario y fecha
    __table_args__ = (
        Index("ix_audit_log_user_id_timestamp", "user_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(event={self.event_type}, user_id={self.user_id})>"


# =============================================================================
# TABLA 7: reauth_events (Historial de Desafíos de Reautenticación Continua)
# Registra cada disparo del motor Zero Trust cuando se evalúa un riesgo adaptativo.
#
# Columnas:
# - risk_event: Razón de la reautenticación ('ip_change', 'sensitive_operation', 'session_timeout').
# - result: Booleano que indica si el usuario superó la prueba biométrica (True)
#   o si fue clasificado como impostor (False). Requisito RF-04, RF-05, CP-S07, CP-S08.
# =============================================================================
class ReauthEvent(Base):
    """Modelo relacional para el registro de evaluaciones de riesgo Zero Trust."""
    __tablename__ = "reauth_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    session_id = Column(
        Integer,
        ForeignKey("sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    risk_event = Column(String(100), nullable=False)  # Tipo de anomalía de riesgo detectada
    result = Column(Boolean, nullable=False)          # Resultado de la comparación biométrica
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user = relationship("User", back_populates="reauth_events")
    session = relationship("Session", back_populates="reauth_events")

    # Índice compuesto para auditoría de reautenticaciones por usuario y tiempo
    __table_args__ = (
        Index("ix_reauth_events_user_id_timestamp", "user_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<ReauthEvent(user_id={self.user_id}, risk_event={self.risk_event}, "
            f"result={self.result})>"
        )

