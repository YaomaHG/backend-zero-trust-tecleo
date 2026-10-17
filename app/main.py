import logging
import os
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.database import engine, Base, SessionLocal, get_db
# Import all models to ensure they are registered with Base.metadata
import app.models  # noqa: F401
from app.models import Role, User
from app.core.security import hash_password
from app.auth.router import router as auth_router
from app.authorization.router import router as admin_router
from app.biometric.router import router as biometric_router
from app.reauth.router import operations_router, reauth_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("zero_trust_api")

# Static assets directory configuration
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


def init_db(db_session: Session = None) -> None:
    """Create database tables and seed baseline roles and default admin user if not present."""
    close_db = False
    if db_session is None:
        try:
            Base.metadata.create_all(bind=engine)
            db = SessionLocal()
            close_db = True
        except Exception as e:
            logger.warning(f"Database connection during startup: {e}")
            return
    else:
        db = db_session

    try:
        # 1. Seed baseline roles
        default_roles = [
            ("admin", "Administrator with full system access and audit privileges"),
            ("user", "Standard user with basic profile and session access"),
        ]
        role_map = {}
        for role_name, description in default_roles:
            existing_role = db.query(Role).filter(Role.name == role_name).first()
            if not existing_role:
                existing_role = Role(name=role_name, description=description)
                db.add(existing_role)
                db.flush()
            role_map[role_name] = existing_role

        # 2. Seed default admin user for live thesis demonstrations
        admin_user = db.query(User).filter(User.username == "admin").first()
        if not admin_user:
            admin_user = User(
                username="admin",
                email="admin@zerotrust.local",
                password_hash=hash_password("AdminZeroTrust2026!"),
                is_active=True,
            )
            admin_user.roles.append(role_map["admin"])
            admin_user.roles.append(role_map["user"])
            db.add(admin_user)
            logger.info("Default admin user ('admin' / 'AdminZeroTrust2026!') created.")

        db.commit()
        logger.info("Base roles and default admin verified/seeded successfully.")
    except Exception as e:
        db.rollback()
        logger.error(f"Error seeding initial database entities: {e}")
    finally:
        if close_db:
            db.close()


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

# Register API Routers
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])
app.include_router(admin_router, prefix="/api/admin", tags=["Administration"])
app.include_router(biometric_router, prefix="/api/biometric", tags=["Biometrics"])
app.include_router(reauth_router, prefix="/api/reauth", tags=["Zero Trust Reauthentication"])
app.include_router(operations_router, prefix="/api/operations", tags=["Sensitive Operations"])

# Static Files mount for SPA
if not os.path.exists(STATIC_DIR):
    os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def serve_index() -> FileResponse:
    """Serves the Single Page Application HTML interface."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="SPA index.html not found.",
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


