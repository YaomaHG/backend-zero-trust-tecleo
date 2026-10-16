from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency that provides a database session and ensures closure."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
