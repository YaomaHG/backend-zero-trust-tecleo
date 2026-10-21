"""
Módulo de Configuración Global del Sistema (app/core/config.py).
Define las variables de entorno, credenciales y parámetros de seguridad para la
arquitectura Zero Trust con biometría de tecleo.

Requerimientos y Casos de Prueba asociados:
- RF-02 / CP-S02, CP-S03: Configuración de tokens JWT criptográficos (HS256).
- RNF-01 / CP-S10: Llave maestra para cifrado en reposo AES-256-GCM.
- RNF-03: Parámetros del Rate Limiter (5 peticiones / 60 segundos).
- RF-04 / CP-S04, CP-S07: Tiempos de vida (TTL) para nonces anti-replay y reautenticación.
"""

from typing import Optional
from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Configuración centralizada de la aplicación usando Pydantic Settings.
    Carga variables desde el archivo .env o variables de entorno del SO.
    """
    PROJECT_NAME: str = "Zero Trust Keystroke Authentication API"
    API_V1_STR: str = "/api/v1"

    # =========================================================================
    # CONFIGURACIÓN DE BASE DE DATOS (PostgreSQL 15 / SQLite para pruebas)
    # CP-S09: Resistencia contra Inyección SQL mediante SQLAlchemy ORM
    # =========================================================================
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "zero_trust_db"
    DATABASE_URL: Optional[str] = None

    @computed_field
    @property
    def SQLALCHEMY_DATABASE_URL(self) -> str:
        """
        Genera la URL de conexión compatible con SQLAlchemy.
        Si se especifica DATABASE_URL (ej. en pruebas con SQLite o en despliegue),
        se utiliza directamente ajustando el driver a psycopg2 si es PostgreSQL.
        """
        url = self.DATABASE_URL
        if not url:
            url = (
                f"postgresql+psycopg2://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )
        elif url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        return url

    # =========================================================================
    # AUTENTICACIÓN JWT (RF-02, CP-S02, CP-S03)
    # Firma criptográfica simétrica con algoritmo HMAC-SHA256 (HS256).
    # Duración de sesión: 30 minutos (tiempo de vida estándar antes de expiración).
    # =========================================================================
    JWT_SECRET_KEY: str = "11357ec518b9d215ff08365bcf5ee74ab40e9c959157490d3ee7cacf1847cc53"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # =========================================================================
    # CIFRADO EN REPOSO AES-256-GCM (RNF-01, CP-S10)
    # Llave maestra criptográfica simétrica de 256 bits (32 bytes = 64 caracteres hex).
    # Utilizada para cifrar y descifrar los vectores biométricos en la base de datos.
    # =========================================================================
    AES_MASTER_KEY: str = "1d9ae387b1344cf4f972226bf26edfaed57494d2026c12688583721b9cfec597"

    # =========================================================================
    # PARÁMETROS DEL MOTOR ZERO TRUST Y REAUTENTICACIÓN CONTINUA (RF-04, CP-S04, CP-S07)
    # - REAUTH_TIMEOUT_MINUTES: Ventana máxima de confianza biométrica (10 min).
    # - CHALLENGE_NONCE_TTL_SECONDS: Tiempo de vida del nonce de un solo uso (300 s / 5 min).
    # - REAUTH_TARGET_PHRASE: Frase fija alfanumérica estándar de Carnegie Mellon (.tie5Roanl).
    # =========================================================================
    REAUTH_TIMEOUT_MINUTES: int = 10
    CHALLENGE_NONCE_TTL_SECONDS: int = 300
    REAUTH_TARGET_PHRASE: str = ".tie5Roanl"

    # =========================================================================
    # LIMITADOR DE TASA / RATE LIMITING (RNF-03)
    # Protección por ventana deslizante contra ataques de fuerza bruta y DoS:
    # Máximo 5 peticiones por ventana de 60 segundos por dirección IP.
    # =========================================================================
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_MAX_REQUESTS: int = 5
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    @property
    def AES_KEY_BYTES(self) -> bytes:
        """
        Convierte la cadena hexadecimal de la llave maestra a un arreglo binario de 32 bytes.
        Valida que cumpla estrictamente con la longitud de 256 bits requerida por AES-256.
        """
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


# Instancia global singleton de configuración accesible en toda la aplicación
settings = Settings()

