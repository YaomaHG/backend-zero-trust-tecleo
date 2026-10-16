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

# Portable JSON type: JSONB in PostgreSQL, JSON in SQLite/others
JSON_TYPE = postgresql.JSONB().with_variant(JSON, "sqlite")

# Association table for User <-> Role (Many-to-Many)
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


class Role(Base):
    """Roles table for RBAC authorization."""
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    users = relationship("User", secondary=user_roles, back_populates="roles")

    def __repr__(self) -> str:
        return f"<Role(name={self.name})>"


class User(Base):
    """User accounts table."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
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
    failed_login_attempts = Column(Integer, default=0, nullable=False)
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


class KeystrokeProfile(Base):
    """Encrypted biometric keystroke dynamics vector templates."""
    __tablename__ = "keystroke_profiles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    # Stored as BYTEA in PostgreSQL, encrypted with AES-256-GCM
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


class Session(Base):
    """User active sessions."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    jwt_token = Column(String(500), unique=True, nullable=False, index=True)
    ip_address = Column(String(45), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="sessions")
    reauth_events = relationship(
        "ReauthEvent",
        back_populates="session",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Session(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"


class AuditLog(Base):
    """Immutable security audit trail."""
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type = Column(String(100), nullable=False, index=True)
    details = Column(JSON_TYPE, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user = relationship("User", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_audit_log_user_id_timestamp", "user_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return f"<AuditLog(event={self.event_type}, user_id={self.user_id})>"


class ReauthEvent(Base):
    """Continuous reauthentication risk assessment records."""
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
    risk_event = Column(String(100), nullable=False)
    result = Column(Boolean, nullable=False)
    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user = relationship("User", back_populates="reauth_events")
    session = relationship("Session", back_populates="reauth_events")

    __table_args__ = (
        Index("ix_reauth_events_user_id_timestamp", "user_id", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<ReauthEvent(user_id={self.user_id}, risk_event={self.risk_event}, "
            f"result={self.result})>"
        )
