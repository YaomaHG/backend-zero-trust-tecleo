"""
Módulo de Base de Datos y Gestión de Sesiones ORM (app/database.py).
Configura la conexión relacional mediante SQLAlchemy 2.0 y provee el generador
de sesiones dependientes para inyección de dependencias en FastAPI.

Requerimientos y Casos de Prueba asociados:
- CP-S09: Resistencia contra Inyección SQL mediante sentencias preparadas y parametrizadas.
- Integridad referencial y transaccional para los modelos de datos de la tesis.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

# =============================================================================
# MOTOR DE CONEXIÓN A BASE DE DATOS (SQLAlchemy Engine)
# - pool_pre_ping=True: Verifica la salud de las conexiones en el pool antes de
#   entregarlas, evitando errores por conexiones caídas o reinicios del motor DB.
# =============================================================================
engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
)

# Fábrica de sesiones de base de datos transaccionales (no autocommit, no autoflush)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Clase base declarativa para el mapeo relacional de las 7 entidades de la tesis
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    Generador de sesión de base de datos para inyección de dependencias en FastAPI.

    Ciclo de vida:
    1. Abre una sesión transaccional limpia para la petición HTTP.
    2. Cede el control al endpoint o servicio (`yield db`).
    3. Garantiza el cierre seguro (`db.close()`) en el bloque `finally`,
       evitando fugas de conexiones en el pool.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

