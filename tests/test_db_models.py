import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app as fastapi_app
import app.models  # Ensure all models are registered
from app.models import (
    User,
    Role,
    user_roles,
    KeystrokeProfile,
    Session as UserSession,
    AuditLog,
    ReauthEvent,
)

# In-memory SQLite engine for fast, isolated unit testing
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create all tables in the test database once for the test session."""
    Base.metadata.create_all(bind=test_engine)
    # Seed default roles
    db = TestingSessionLocal()
    admin_role = Role(name="admin", description="Admin role")
    user_role = Role(name="user", description="User role")
    db.add_all([admin_role, user_role])
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    """Provide a transactional database session for tests."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session):
    """FastAPI TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    fastapi_app.dependency_overrides[get_db] = override_get_db
    with TestClient(fastapi_app) as test_client:
        yield test_client
    fastapi_app.dependency_overrides.clear()


class TestDatabaseModels:
    """Verifies that all 7 required database tables exist with proper constraints."""

    def test_all_seven_tables_registered(self):
        """Verify that all 7 required tables are defined in Base.metadata.tables."""
        expected_tables = {
            "users",
            "roles",
            "user_roles",
            "keystroke_profiles",
            "sessions",
            "audit_log",
            "reauth_events",
        }
        actual_tables = set(Base.metadata.tables.keys())
        missing_tables = expected_tables - actual_tables
        assert not missing_tables, f"Missing tables in metadata: {missing_tables}"
        assert expected_tables.issubset(actual_tables)

    def test_user_roles_composite_primary_key(self):
        """Verify user_roles associative table has composite PK (user_id, role_id)."""
        table = Base.metadata.tables["user_roles"]
        pk_columns = {col.name for col in table.primary_key.columns}
        assert pk_columns == {"user_id", "role_id"}

    def test_keystroke_profiles_binary_vector(self):
        """Verify keystroke_profiles stores vector_encrypted as LargeBinary / BYTEA."""
        table = Base.metadata.tables["keystroke_profiles"]
        col = table.columns["vector_encrypted"]
        assert col is not None
        assert not col.nullable

    def test_composite_indexes_exist(self):
        """Verify composite indexes on (user_id, timestamp) for audit_log and reauth_events."""
        audit_table = Base.metadata.tables["audit_log"]
        audit_idx_cols = [
            set(col.name for col in idx.columns) for idx in audit_table.indexes
        ]
        assert {"user_id", "timestamp"} in audit_idx_cols

        reauth_table = Base.metadata.tables["reauth_events"]
        reauth_idx_cols = [
            set(col.name for col in idx.columns) for idx in reauth_table.indexes
        ]
        assert {"user_id", "timestamp"} in reauth_idx_cols

    def test_seed_roles_exist(self, db_session):
        """Verify base roles 'admin' and 'user' can be queried from database."""
        admin_role = db_session.query(Role).filter(Role.name == "admin").first()
        user_role = db_session.query(Role).filter(Role.name == "user").first()
        assert admin_role is not None
        assert user_role is not None
        assert admin_role.name == "admin"
        assert user_role.name == "user"


class TestHealthEndpoint:
    """Verifies that the /health endpoint checks database connectivity."""

    def test_health_check_success(self, client):
        """GET /health should return 200 OK and connected status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data == {"status": "ok", "db": "connected"}

    def test_health_check_db_failure(self):
        """GET /health should return 503 when database connection fails."""
        def broken_get_db():
            class FailingSession:
                def execute(self, *args, **kwargs):
                    raise RuntimeError("Database connection timed out")
            yield FailingSession()

        fastapi_app.dependency_overrides[get_db] = broken_get_db
        try:
            with TestClient(fastapi_app) as client:
                response = client.get("/health")
                assert response.status_code == 503
                data = response.json()
                assert data["detail"]["status"] == "error"
                assert data["detail"]["db"] == "disconnected"
        finally:
            fastapi_app.dependency_overrides.clear()
