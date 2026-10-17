from typing import Optional
from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "Zero Trust Keystroke Authentication API"
    API_V1_STR: str = "/api/v1"

    # PostgreSQL Configuration
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "zero_trust_db"
    DATABASE_URL: Optional[str] = None

    @computed_field
    @property
    def SQLALCHEMY_DATABASE_URL(self) -> str:
        url = self.DATABASE_URL
        if not url:
            url = (
                f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        elif url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url

    # JWT Authentication
    JWT_SECRET_KEY: str = "11357ec518b9d215ff08365bcf5ee74ab40e9c959157490d3ee7cacf1847cc53"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # AES-256-GCM Master Key (32 bytes = 64 hex characters)
    AES_MASTER_KEY: str = "1d9ae387b1344cf4f972226bf26edfaed57494d2026c12688583721b9cfec597"

    # Zero Trust Continuous Reauthentication & Risk Engine
    REAUTH_TIMEOUT_MINUTES: int = 10
    CHALLENGE_NONCE_TTL_SECONDS: int = 300
    REAUTH_TARGET_PHRASE: str = ".tie5Roanl"

    # Rate Limiting (RNF-03)
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_MAX_REQUESTS: int = 5
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    @property
    def AES_KEY_BYTES(self) -> bytes:
        key_bytes = bytes.fromhex(self.AES_MASTER_KEY)
        if len(key_bytes) != 32:
            raise ValueError("AES_MASTER_KEY must be exactly 32 bytes (64 hex characters).")
        return key_bytes

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )


settings = Settings()
