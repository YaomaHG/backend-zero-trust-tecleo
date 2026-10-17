"""
IP-based Rate Limiting Service (RNF-03).
Protects authentication and reauthentication endpoints against brute force and automated attacks.
Configurable to avoid interference during test suites (e.g. CP-S06 20-attempt lockout test).
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
    Sliding window rate limiter indexed by IP address.
    Thread-safe and configurable per endpoint scope.
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
        return self.enabled

    def set_enabled(self, enabled: bool) -> None:
        self.enabled = enabled

    def set_limit(self, max_requests: int, window_seconds: int = 60) -> None:
        with self._lock:
            self.max_requests = max_requests
            self.window_seconds = window_seconds

    def reset(self) -> None:
        """Clears all stored rate limit records."""
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
        Validates whether the incoming client IP has exceeded the allowed rate limit.
        If exceeded, logs a 'rate_limit_exceeded' security event to audit_log and raises 429.
        """
        if not self.enabled:
            return

        ip = get_client_ip(request)
        key = f"{scope}:{ip}"
        now = time.time()
        effective_limit = override_max if override_max is not None else self.max_requests
        window_start = now - self.window_seconds

        with self._lock:
            # Purge timestamps outside the active sliding window
            timestamps = [t for t in self._requests[key] if t > window_start]

            if len(timestamps) >= effective_limit:
                if db is not None:
                    try:
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

                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded: maximum {effective_limit} requests per {self.window_seconds} seconds.",
                    headers={"Retry-After": str(self.window_seconds)},
                )

            timestamps.append(now)
            self._requests[key] = timestamps


# Global rate limiter instance
rate_limiter = RateLimiter(
    max_requests=settings.RATE_LIMIT_MAX_REQUESTS,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
    enabled=settings.RATE_LIMIT_ENABLED,
)


def check_rate_limit(
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    """FastAPI dependency to enforce rate limiting on sensitive routes."""
    rate_limiter.check(request=request, db=db, scope="general")


def check_reauth_rate_limit(
    request: Request,
    db: Session = Depends(get_db),
) -> None:
    """FastAPI dependency specifically for reauthentication routes (5 req/min)."""
    rate_limiter.check(request=request, db=db, scope="reauth")
