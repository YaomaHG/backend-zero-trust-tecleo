"""
Servicio de Limitación de Tasa (Rate Limiting) basado en IP (app/core/rate_limiter.py).
Implementa un algoritmo de ventana deslizante (Sliding Window) en memoria con seguridad
para hilos (Thread-safe) para mitigar ataques de fuerza bruta, adivinación y DoS.

Requerimiento de Tesis:
- RNF-03 (Tasa de peticiones permitidas): Limita a un máximo de 5 peticiones por minuto
  por dirección IP en endpoints sensibles de autenticación y reautenticación biométrica.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session

from app.audit.service import get_client_ip, log_audit_event
from app.core.config import settings
from app.database import get_db


class RateLimiter:
    """
    Limitador de tasa basado en el algoritmo de Ventana Deslizante (Sliding Window Counter).

    ¿Cómo funciona el Algoritmo de Ventana Deslizante (RNF-03)?
    -----------------------------------------------------------
    1. Llave Compuesta: Se genera una clave que combina el ámbito y la IP del cliente
       (ej. 'auth:192.168.1.15' o 'reauth:10.0.0.1').
    2. Almacenamiento Temporal: Cada petición exitosa registra su marca de tiempo en
       segundos (timestamp = time.time()) en una lista en memoria.
    3. Purga Dinámica de la Ventana: Ante una nueva petición, se calcula el inicio de la
       ventana activa: `window_start = now - window_seconds` (ej. los últimos 60 segundos).
       Todas las marcas de tiempo anteriores a ese umbral se descartan de inmediato.
    4. Evaluación de Capacidad: Si el número de marcas de tiempo restantes dentro de la
       ventana deslizante alcanza o supera el límite permitido (5 peticiones):
       - Se registra una alerta en la bitácora inmutable de auditoría (`rate_limit_exceeded`).
       - Se interrumpe la ejecución arrojando una excepción HTTP 429 Too Many Requests con
         la cabecera 'Retry-After: 60'.
    5. Aceptación: Si está dentro del margen permitido, se agrega la marca de tiempo actual
       y la petición procede con normalidad.
    6. Concurrencia Segura: Todas las operaciones críticas de lectura y escritura sobre el
       diccionario están protegidas por un `threading.Lock()`, evitando condiciones de carrera.
    """

    def __init__(
        self,
        max_requests: int = 5,
        window_seconds: int = 60,
        enabled: Optional[bool] = None,
    ):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.enabled = enabled if enabled is not None else settings.RATE_LIMIT_ENABLED
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_enabled(self) -> bool:
        """Indica si la limitación de tasa está activa globalmente."""
        return self.enabled

    def set_enabled(self, enabled: bool) -> None:
        """Activa o desactiva dinámicamente el limitador de tasa."""
        self.enabled = enabled

    def set_limit(self, max_requests: int, window_seconds: int = 60) -> None:
        """Ajusta en tiempo de ejecución el umbral de peticiones y tamaño de la ventana."""
        with self._lock:
            self.max_requests = max_requests
            self.window_seconds = window_seconds

    def reset(self) -> None:
        """Limpia todos los registros de marcas de tiempo acumuladas en memoria."""
        with self._lock:
            self._requests.clear()

    def check(
        self,
        request: Request,
        db: Optional[Session] = None,
        scope: str = "auth",
        override_max: Optional[int] = None,
    ) -> None:
        """
        Ejecuta la verificación de la ventana deslizante para la IP de la petición entrante.

        Args:
            request (Request): Objeto de petición HTTP entrante de FastAPI.
            db (Optional[Session]): Sesión de base de datos para registrar auditoría si se supera.
            scope (str): Ámbito de la limitación ('auth', 'reauth', 'general').
            override_max (Optional[int]): Límite temporal específico si se desea sobreescribir.

        Raises:
            HTTPException (429): Si el cliente ha superado el número de peticiones permitidas.
        """
        if not self.enabled:
            return

        ip = get_client_ip(request)
        key = f"{scope}:{ip}"
        now = time.time()
        effective_limit = override_max if override_max is not None else self.max_requests
        window_start = now - self.window_seconds

        with self._lock:
            # Filtrar y conservar únicamente las peticiones dentro de la ventana de 60 segundos
            timestamps = [t for t in self._requests[key] if t > window_start]

            # Si ya se alcanzó el límite máximo de peticiones (ej. 5 req/min)
            if len(timestamps) >= effective_limit:
                if db is not None:
                    try:
                        # RNF-05: Registro inmutable en auditoría del exceso de peticiones
                        log_audit_event(
                            db=db,
                            event_type="rate_limit_exceeded",
                            ip_address=ip,
                            details={
                                "scope": scope,
                                "limit": effective_limit,
                                "window_seconds": self.window_seconds,
                                "attempt_count": len(timestamps) + 1,
                            },
                        )
                    except Exception:
                        pass

                # Respuesta estándar HTTP 429 para frenar al cliente atacante
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded: maximum {effective_limit} requests per {self.window_seconds} seconds.",
                    headers={"Retry-After": str(self.window_seconds)},
                )

            # Si está dentro del límite, registrar la marca de tiempo de la petición actual
            timestamps.append(now)
            self._requests[key] = timestamps


# =============================================================================
# INSTANCIA GLOBAL DEL LIMITADOR DE TASA
# =============================================================================
rate_limiter = RateLimiter(
    max_requests=settings.RATE_LIMIT_MAX_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    enabled=settings.RATE_LIMIT_ENABLED,
)


def check_rate_limit(
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    """Dependencia de FastAPI para aplicar rate limiting general en rutas protegidas."""
    rate_limiter.check(request=request, db=db, scope="general")


def check_reauth_rate_limit(
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    """
    Dependencia de FastAPI específica para la reautenticación biométrica (RNF-03).
    Asegura un límite de 5 peticiones por minuto en la verificación de patrones de tecleo.
    """
    rate_limiter.check(request=request, db=db, scope="reauth")

