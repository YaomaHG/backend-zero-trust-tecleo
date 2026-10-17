import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app as fastapi_app
import app.models  # noqa: F401
from app.models import Role

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
    """Create all tables in the test database once for the test session and seed baseline entities."""
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()
    from app.main import init_db
    init_db(db)
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


@pytest.fixture(autouse=True)
def configure_test_rate_limiter():
    """Keep rate limiter reset and disabled by default across unit tests unless explicitly enabled."""
    from app.core.rate_limiter import rate_limiter
    rate_limiter.reset()
    previous = rate_limiter.enabled
    rate_limiter.enabled = False
    yield
    rate_limiter.reset()
    rate_limiter.enabled = previous
