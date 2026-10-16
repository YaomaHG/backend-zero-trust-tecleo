import logging
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import engine, Base, SessionLocal, get_db
# Import all models to ensure they are registered with Base.metadata
import app.models  # noqa: F401
from app.models import Role

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("zero_trust_api")


def init_db() -> None:
    """Create database tables and seed baseline roles if not present."""
    try:
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        try:
            default_roles = [
                ("admin", "Administrator with full system access and audit privileges"),
                ("user", "Standard user with basic profile and session access"),
            ]
            for role_name, description in default_roles:
                existing_role = db.query(Role).filter(Role.name == role_name).first()
                if not existing_role:
                    new_role = Role(name=role_name, description=description)
                    db.add(new_role)
            db.commit()
            logger.info("Base roles verified/seeded successfully.")
        except Exception as e:
            db.rollback()
            logger.error(f"Error seeding initial roles: {e}")
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Database connection during startup: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager: runs initialization on startup."""
    init_db()
    yield


app = FastAPI(
    title="Zero Trust Keystroke Authentication API",
    description="Back-end seguro con reautenticación adaptativa basada en dinámica de tecleo bajo principios Zero Trust.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health", status_code=status.HTTP_200_OK, tags=["Health"])
def health_check(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Healthcheck endpoint that verifies database connectivity via SELECT 1."""
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "db": "connected"}
    except Exception as exc:
        logger.error(f"Healthcheck database error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"status": "error", "db": "disconnected", "error": str(exc)},
        )
