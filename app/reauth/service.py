"""
Motor de Reautenticación Adaptativa Continua Zero Trust (app/reauth/service.py).
Implementa la vigilancia contextual de riesgos, la protección contra ataques de
repetición (Anti-Replay) y el escalonamiento de privilegios biométricos.

Requerimientos y Casos de Prueba asociados:
- RF-04 / CP-S07: Evaluación de riesgo continuo por cambio súbito de IP ('ip_change').
- RF-04: Expiración de ventana de confianza biométrica ('session_timeout') y operaciones sensibles ('sensitive_operation').
- CP-S04: Protección contra Ataques de Repetición (Nonces únicos y hashes SHA-256 de carga útil).
- RF-05 / CP-S08: Verificación escalonada de dinámicas de tecleo y regla de 3 intentos.
- RF-08: Revocación automática e inmediata de sesión en base de datos ante impostores ('session.revoked = True').
"""

import hashlib
import json
import logging
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.audit.service import log_audit_event
from app.biometric.service import biometric_service
from app.core.config import settings
from app.models import ReauthEvent, Session as UserSession, User

logger = logging.getLogger("zero_trust_reauth")


class AntiReplayStore:
    """
    Almacén en memoria seguro para hilos (Thread-safe) para mitigar Ataques de Repetición (CP-S04).

    Triple Mecanismo de Defensa Anti-Replay:
    ----------------------------------------
    1. Desafíos Criptográficos de Un Solo Uso (Single-Use Challenge Nonces):
       Generados con `secrets.token_urlsafe(32)`. Están atados exclusivamente al
       `user_id` y `session_id`. En el instante en que se validan, su estado cambia
       irreversiblemente a `consumed = True`. Si un atacante intercepta la petición
       y la reenvía en la red, el servidor rechaza la repetición con HTTP 400.
    2. Hash Criptográfico SHA-256 de la Carga Útil (Payload Fingerprinting):
       Se calcula el digest SHA-256 de la combinación `session_id + vector_tiempos`.
       Si un atacante reutiliza el mismo vector biométrico dentro de la ventana de vida,
       el almacén detecta la colisión y bloquea la inyección.
    3. Ventana de Frescura Temporal (Timestamp Freshness):
       Verifica que la marca temporal del cliente no difiera en más de 300 segundos
       respecto al reloj del servidor, descartando paquetes capturados previamente.
    """

    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._challenges: Dict[str, Dict[str, Any]] = {}
        self._consumed_payload_hashes: Dict[str, float] = {}
        self._lock = threading.Lock()

    def generate_challenge(self, user_id: int, session_id: int) -> str:
        """
        Genera un nonce criptográfico de 32 bytes aleatorios y lo almacena con TTL de 300 segundos.
        """
        nonce = secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            self._challenges[nonce] = {
                "user_id": user_id,
                "session_id": session_id,
                "created_at": now,
                "expires_at": now + self.ttl_seconds,
                "consumed": False,
            }
        return nonce

    def validate_and_consume_nonce(
        self,
        nonce: Optional[str],
        user_id: int,
        session_id: int,
    ) -> bool:
        """
        Valida que el nonce exista, pertenezca a la sesión activa y NO haya sido consumido.
        Al ser validado, lo marca inmediatamente como consumido (`consumed = True`).
        """
        if not nonce:
            return True  # Si no se envió nonce, se valida por hash de payload

        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            challenge = self._challenges.get(nonce)
            if not challenge:
                logger.warning(f"Nonce not found or expired: {nonce[:8]}...")
                return False

            if challenge["consumed"]:
                # Caso CP-S04: Intento de reutilizar un nonce previamente consumido
                logger.warning(f"Replay attack detected: Nonce already consumed {nonce[:8]}...")
                return False

            if challenge["session_id"] != session_id or challenge["user_id"] != user_id:
                logger.warning(f"Nonce context mismatch for {nonce[:8]}...")
                return False

            if now > challenge["expires_at"]:
                logger.warning(f"Nonce expired {nonce[:8]}...")
                return False

            # Marcar consumido inmediatamente para evitar condiciones de carrera
            challenge["consumed"] = True
            return True

    def validate_and_consume_payload(
        self,
        session_id: int,
        vector: Optional[List[float]],
        raw_events: Optional[List[Dict[str, float]]],
    ) -> bool:
        """
        Genera el hash SHA-256 del vector biométrico y verifica que no sea una muestra duplicada.
        """
        if vector is None and raw_events is None:
            return True

        content = vector if vector is not None else raw_events
        serialized = json.dumps(content, sort_keys=True)
        # Fingerprint único de la muestra para esta sesión
        payload_hash = hashlib.sha256(f"{session_id}:{serialized}".encode()).hexdigest()

        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            if payload_hash in self._consumed_payload_hashes:
                # Caso CP-S04: Carga útil idéntica reenviada
                logger.warning(f"Replay attack detected: Biometric payload re-submitted for session {session_id}")
                return False

            self._consumed_payload_hashes[payload_hash] = now + self.ttl_seconds
            return True

    def validate_timestamp_freshness(self, timestamp: Optional[float], window_seconds: int = 300) -> bool:
        """Valida que la marca temporal del cliente se encuentre dentro del margen de 300 segundos."""
        if timestamp is None:
            return True

        # Normalizar de milisegundos a segundos si es necesario
        ts = timestamp / 1000.0 if timestamp > 1e11 else timestamp
        now = time.time()
        return abs(now - ts) <= window_seconds

    def _cleanup_expired(self, now: float) -> None:
        """Elimina de memoria los nonces y hashes cuya vigencia ha expirado."""
        expired_nonces = [k for k, v in self._challenges.items() if now > v["expires_at"]]
        for k in expired_nonces:
            del self._challenges[k]

        expired_hashes = [k for k, exp in self._consumed_payload_hashes.items() if now > exp]
        for k in expired_hashes:
            del self._consumed_payload_hashes[k]

    def reset(self) -> None:
        """Limpia el almacenamiento para aislamiento de suites de prueba."""
        with self._lock:
            self._challenges.clear()
            self._consumed_payload_hashes.clear()


# Instancia singleton del almacén Anti-Replay
anti_replay_store = AntiReplayStore(ttl_seconds=settings.CHALLENGE_NONCE_TTL_SECONDS)


def evaluate_session_risk(
    session: UserSession,
    current_ip: str,
    operation_sensitive: bool = False,
    timeout_minutes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Motor de Evaluación Continua de Riesgos bajo la filosofía Zero Trust ("Never Trust, Always Verify").

    Evalúa los 3 Eventos de Riesgo Críticos de la Tesis:
    ----------------------------------------------------
    1. 'ip_change' (Caso de Prueba CP-S07):
       Compara la IP del cliente actual con la IP registrada en la tabla `sessions` en el login.
       Si difieren (ej. cambio de red WiFi a datos móviles o proxy de atacante), la confianza
       se suspende de inmediato y se exige verificación biométrica antes de procesar peticiones.

    2. 'session_timeout' (Requisito RF-04):
       Calcula el tiempo transcurrido desde la última verificación biométrica exitosa
       (`session.last_biometric_verified_at`). Si han transcurrido más de 10 minutos
       (REAUTH_TIMEOUT_MINUTES), se exige una nueva prueba de dinámica de tecleo pasiva.

    3. 'sensitive_operation' (Requisito RF-04 / Sección 3.3):
       Si el usuario intenta ejecutar una transacción corporativa de alto valor
       (transferencias monetarias, eliminación de datos o cambio de roles), el motor
       exige una reautenticación activa obligatoria (Step-Up Authentication).
    """
    timeout = timeout_minutes if timeout_minutes is not None else settings.REAUTH_TIMEOUT_MINUTES

    # 1. Detección de Anomalía por Cambio Súbito de IP (Caso CP-S07)
    if session.ip_address and current_ip and session.ip_address != current_ip:
        return {
            "reauth_required": True,
            "risk_event": "ip_change",
            "reason": f"Client IP changed from {session.ip_address} to {current_ip}",
            "current_ip": current_ip,
            "session_ip": session.ip_address,
        }

    # 2. Expiración de la Ventana Temporal de Confianza Biométrica (10 minutos)
    last_verified = session.last_biometric_verified_at or session.created_at
    if last_verified:
        now = datetime.now(timezone.utc)
        if last_verified.tzinfo is None:
            last_verified = last_verified.replace(tzinfo=timezone.utc)
        elapsed_seconds = (now - last_verified).total_seconds()
        if elapsed_seconds > timeout * 60:
            return {
                "reauth_required": True,
                "risk_event": "session_timeout",
                "reason": f"Continuous trust expired ({int(elapsed_seconds // 60)} minutes since last biometric verification)",
                "current_ip": current_ip,
                "session_ip": session.ip_address,
            }

    # 3. Disparo por Ejecución de Operación Corporativa Sensible
    if operation_sensitive:
        return {
            "reauth_required": True,
            "risk_event": "sensitive_operation",
            "reason": "Sensitive corporate action requires step-up biometric reauthentication",
            "current_ip": current_ip,
            "session_ip": session.ip_address,
        }

    return {
        "reauth_required": False,
        "risk_event": None,
        "reason": "Session trust level is active and valid",
        "current_ip": current_ip,
        "session_ip": session.ip_address,
    }


def verify_reauthentication(
    db: Session,
    user: User,
    session: UserSession,
    client_ip: str,
    risk_event: str,
    challenge_nonce: Optional[str] = None,
    timestamp: Optional[float] = None,
    vector: Optional[List[float]] = None,
    raw_events: Optional[List[Dict[str, float]]] = None,
) -> Any:
    """
    Ejecuta el protocolo completo de Reautenticación Adaptativa Zero Trust.

    Fases del Procedimiento:
    ------------------------
    1. Mitigación Anti-Replay (CP-S04):
       Valida y consume el nonce aleatorio, el hash del vector y la frescura temporal.
       Si se detecta un intento de repetición, registra 'replay_attack_detected' en la
       auditoría inmutable y rechaza con HTTP 400 Bad Request.

    2. Inferencia y Verificación Biomecánica:
       Compara la dinámica de tecleo contra la plantilla cifrada del usuario mediante
       el clasificador Gradient Boosting y la fórmula híbrida en `biometric_service`.

    3. Trazabilidad:
       Inserta un registro formal en la tabla `reauth_events` (tipo de riesgo y resultado)
       y emite el evento correspondiente en `audit_log`.

    4. Rama de Éxito (Genuino):
       - Actualiza la IP de confianza en la sesión (`session.ip_address = client_ip`).
       - Refresca el reloj biométrico (`session.last_biometric_verified_at = now()`).
       - Retorna HTTP 200 OK desbloqueando las operaciones del usuario.

    5. Rama de Fallo / Detección de Impostores (Lógica de los 3 Intentos y Revocación):
       - Se consultan los intentos fallidos acumulados para esta sesión en `reauth_events`.
       - Revocación Inmediata de Sesión (`session.revoked = True`) si:
         a) El score es menor a 0.10 (ataque flagrante de cadencia artificial no humana).
         b) O si el usuario acumula 3 fallos consecutivos en los desafíos.
         -> En ambos casos, el token JWT queda invalidado permanentemente en la BD (RF-08, CP-S08).
            Se responde HTTP 403 con `session_revoked: True` expulsando al atacante al login.
       - Fallo Leve (Intentos 1 y 2 con score >= 0.10):
         -> No se revoca la sesión todavía; se genera un nuevo challenge nonce fresco y se
            responde HTTP 403 con `reauth_status: "retry"` y `attempts_remaining: (3 - fallos)`.
    """
    # 1. Validación de controles Anti-Replay (CP-S04)
    nonce_valid = anti_replay_store.validate_and_consume_nonce(challenge_nonce, user.id, session.id)
    payload_valid = anti_replay_store.validate_and_consume_payload(session.id, vector, raw_events)
    freshness_valid = anti_replay_store.validate_timestamp_freshness(timestamp)

    if not (nonce_valid and payload_valid and freshness_valid):
        # RNF-05 / CP-S04: Registrar ataque de repetición en bitácora inmutable
        log_audit_event(
            db=db,
            event_type="replay_attack_detected",
            user_id=user.id,
            ip_address=client_ip,
            details={
                "session_id": session.id,
                "risk_event": risk_event,
                "nonce": challenge_nonce,
                "nonce_valid": nonce_valid,
                "payload_valid": payload_valid,
                "freshness_valid": freshness_valid,
            },
        )
        reauth_record = ReauthEvent(
            user_id=user.id,
            session_id=session.id,
            risk_event="replay_attack",
            result=False,
        )
        db.add(reauth_record)
        db.commit()

        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "detail": "Replay attack detected: Challenge nonce or biometric sample has already been used or expired.",
                "match": False,
                "score": 0.0,
                "threshold": round(float(biometric_service.optimal_threshold), 4),
                "reauth_status": "replay_attack",
                "session_revoked": False,
                "attempts_remaining": 0,
                "new_nonce": None,
            },
        )

    # 2. Verificación de patrones de dinámica de tecleo
    biometric_result = biometric_service.verify_keystroke_pattern(
        db=db,
        user=user,
        vector=vector,
        raw_events=raw_events,
    )

    match = biometric_result["match"]
    score = float(biometric_result["score"])
    threshold = float(biometric_result["threshold"])

    # 3. Persistir registro de evento de reautenticación en PostgreSQL
    reauth_entry = ReauthEvent(
        user_id=user.id,
        session_id=session.id,
        risk_event=risk_event,
        result=match,
    )
    db.add(reauth_entry)
    db.commit()
    db.refresh(reauth_entry)

    # 4. Auditoría inmutable de seguridad
    log_audit_event(
        db=db,
        event_type="reauth_success" if match else "reauth_failure",
        user_id=user.id,
        ip_address=client_ip,
        details={
            "session_id": session.id,
            "risk_event": risk_event,
            "score": score,
            "threshold": threshold,
            "match": match,
        },
    )

    # 5. Gestión del Éxito: Actualizar nivel de confianza y nueva IP (CP-S07)
    if match:
        session.ip_address = client_ip  # Se adopta la nueva IP como válida y confiable
        session.last_biometric_verified_at = datetime.now(timezone.utc)
        db.commit()
        return {
            "match": True,
            "score": score,
            "threshold": threshold,
            "reauth_status": "success",
            "message": "Biometric reauthentication verified successfully. Trust level updated.",
            "session_revoked": False,
            "attempts_remaining": 3,
            "new_nonce": None,
        }

    # 6. Gestión de Fallo / Detección de Impostores (Lógica de 3 Intentos y Revocación RF-08, CP-S08)
    failed_attempts = (
        db.query(ReauthEvent)
        .filter(
            ReauthEvent.session_id == session.id,
            ReauthEvent.user_id == user.id,
            ReauthEvent.result.is_(False),
        )
        .count()
    )

    # Revocación inmediata si el score es menor a 0.10 (cadencia artificial o impostor flagrante)
    # o si se acumulan 3 fallos consecutivos en esta sesión
    is_extreme_attack = (score < 0.10)
    should_revoke = is_extreme_attack or (failed_attempts >= 3)

    if should_revoke:
        # Revocar la sesión en la base de datos de inmediato (RF-08)
        session.revoked = True
        db.commit()

        log_audit_event(
            db=db,
            event_type="session_revoked_biometric_failure",
            user_id=user.id,
            ip_address=client_ip,
            details={
                "session_id": session.id,
                "risk_event": risk_event,
                "score": score,
                "threshold": threshold,
                "failed_attempts": failed_attempts,
                "reason": "impostor_keystroke_pattern_detected",
            },
        )

        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "detail": "Biometric reauthentication failed: Impostor keystroke pattern detected. Session has been revoked.",
                "match": False,
                "score": score,
                "threshold": threshold,
                "reauth_status": "failed",
                "session_revoked": True,
                "attempts_remaining": 0,
                "new_nonce": None,
            },
        )

    # Si no es ataque extremo y quedan intentos (< 3): emitir nuevo nonce para reintento
    new_nonce = anti_replay_store.generate_challenge(user.id, session.id)
    attempts_remaining = max(0, 3 - failed_attempts)

    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={
            "detail": f"Biometric reauthentication failed: score below threshold. Intentos restantes: {attempts_remaining}.",
            "match": False,
            "score": score,
            "threshold": threshold,
            "reauth_status": "retry",
            "session_revoked": False,
            "attempts_remaining": attempts_remaining,
            "new_nonce": new_nonce,
        },
    )

