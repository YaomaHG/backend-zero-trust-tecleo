"""
Zero Trust Adaptive Reauthentication Engine (RF-04, RF-05, RF-08, CP-S04, CP-S07, CP-S08).
Evaluates continuous risk, manages anti-replay nonces, and updates session trust states.
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
from sqlalchemy.orm import Session

from app.audit.service import log_audit_event
from app.biometric.service import biometric_service
from app.core.config import settings
from app.models import ReauthEvent, Session as UserSession, User

logger = logging.getLogger("zero_trust_reauth")


class AntiReplayStore:
    """
    In-memory thread-safe store for single-use challenge nonces and sample hashes (CP-S04).
    Prevents replay attacks by ensuring freshness and uniqueness of tokens and payloads.
    """

    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self._challenges: Dict[str, Dict[str, Any]] = {}
        self._consumed_payload_hashes: Dict[str, float] = {}
        self._lock = threading.Lock()

    def generate_challenge(self, user_id: int, session_id: int) -> str:
        """Generates and stores a unique cryptographic challenge nonce."""
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
        Validates nonce existence, session ownership, freshness, and single-use status.
        Returns True if valid and consumed; False if replay or invalid.
        """
        if not nonce:
            return True  # If no nonce is supplied, payload-hash validation is checked instead

        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            challenge = self._challenges.get(nonce)
            if not challenge:
                logger.warning(f"Nonce not found or expired: {nonce[:8]}...")
                return False

            if challenge["consumed"]:
                logger.warning(f"Replay attack detected: Nonce already consumed {nonce[:8]}...")
                return False

            if challenge["session_id"] != session_id or challenge["user_id"] != user_id:
                logger.warning(f"Nonce context mismatch for {nonce[:8]}...")
                return False

            if now > challenge["expires_at"]:
                logger.warning(f"Nonce expired {nonce[:8]}...")
                return False

            # Mark consumed immediately
            challenge["consumed"] = True
            return True

    def validate_and_consume_payload(
        self,
        session_id: int,
        vector: Optional[List[float]],
        raw_events: Optional[List[Dict[str, float]]],
    ) -> bool:
        """
        Hashes sample payload and ensures it has not been submitted previously in this session.
        Returns True if fresh; False if replay attack.
        """
        if vector is None and raw_events is None:
            return True

        content = vector if vector is not None else raw_events
        serialized = json.dumps(content, sort_keys=True)
        payload_hash = hashlib.sha256(f"{session_id}:{serialized}".encode()).hexdigest()

        now = time.time()
        with self._lock:
            self._cleanup_expired(now)
            if payload_hash in self._consumed_payload_hashes:
                logger.warning(f"Replay attack detected: Biometric payload re-submitted for session {session_id}")
                return False

            self._consumed_payload_hashes[payload_hash] = now + self.ttl_seconds
            return True

    def validate_timestamp_freshness(self, timestamp: Optional[float], window_seconds: int = 300) -> bool:
        """Validates that client timestamp is within an acceptable time window."""
        if timestamp is None:
            return True

        # Normalize milliseconds to seconds if necessary
        ts = timestamp / 1000.0 if timestamp > 1e11 else timestamp
        now = time.time()
        return abs(now - ts) <= window_seconds

    def _cleanup_expired(self, now: float) -> None:
        """Purges expired nonces and payload hashes."""
        expired_nonces = [k for k, v in self._challenges.items() if now > v["expires_at"]]
        for k in expired_nonces:
            del self._challenges[k]

        expired_hashes = [k for k, exp in self._consumed_payload_hashes.items() if now > exp]
        for k in expired_hashes:
            del self._consumed_payload_hashes[k]

    def reset(self) -> None:
        """Clears all challenges and payload hashes."""
        with self._lock:
            self._challenges.clear()
            self._consumed_payload_hashes.clear()


# Global Anti-Replay Store
anti_replay_store = AntiReplayStore(ttl_seconds=settings.CHALLENGE_NONCE_TTL_SECONDS)


def evaluate_session_risk(
    session: UserSession,
    current_ip: str,
    operation_sensitive: bool = False,
    timeout_minutes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Evaluates continuous risk triggers under Zero Trust principles (RF-04, CP-S07):
    1. 'ip_change': Current IP differs from session IP registered at login.
    2. 'session_timeout': Trust window has expired since last biometric verification.
    3. 'sensitive_operation': Accessing critical business operations requires fresh reauth.
    """
    timeout = timeout_minutes if timeout_minutes is not None else settings.REAUTH_TIMEOUT_MINUTES

    # 1. IP Address Change Detection (CP-S07)
    if session.ip_address and current_ip and session.ip_address != current_ip:
        return {
            "reauth_required": True,
            "risk_event": "ip_change",
            "reason": f"Client IP changed from {session.ip_address} to {current_ip}",
            "current_ip": current_ip,
            "session_ip": session.ip_address,
        }

    # 2. Continuous Biometric Verification Timeout
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

    # 3. Sensitive Operation Trigger
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
) -> Dict[str, Any]:
    """
    Executes Zero Trust adaptive step-up reauthentication:
    1. Validates Anti-Replay protection (CP-S04).
    2. Compares keystroke dynamics against stored template (RF-05).
    3. Records result to reauth_events and audit_log.
    4. On success: updates session trust and IP.
    5. On failure / impostor: revokes session on critical anomaly (RF-08, CP-S08).
    """
    # 1. Anti-Replay Validation (CP-S04)
    nonce_valid = anti_replay_store.validate_and_consume_nonce(challenge_nonce, user.id, session.id)
    payload_valid = anti_replay_store.validate_and_consume_payload(session.id, vector, raw_events)
    freshness_valid = anti_replay_store.validate_timestamp_freshness(timestamp)

    if not (nonce_valid and payload_valid and freshness_valid):
        # Register replay attack detection in audit log and reauth_events
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

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Replay attack detected: Challenge nonce or biometric sample has already been used or expired.",
        )

    # 2. Verify keystroke dynamics pattern
    biometric_result = biometric_service.verify_keystroke_pattern(
        db=db,
        user=user,
        vector=vector,
        raw_events=raw_events,
    )

    match = biometric_result["match"]
    score = biometric_result["score"]
    threshold = biometric_result["threshold"]

    # 3. Persist reauth event record
    reauth_entry = ReauthEvent(
        user_id=user.id,
        session_id=session.id,
        risk_event=risk_event,
        result=match,
    )
    db.add(reauth_entry)
    db.commit()
    db.refresh(reauth_entry)

    # 4. Audit logging
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

    # 5. Handle success
    if match:
        session.ip_address = client_ip  # Trust state updated for verified IP
        session.last_biometric_verified_at = datetime.now(timezone.utc)
        db.commit()
        return {
            "match": True,
            "score": score,
            "threshold": threshold,
            "reauth_status": "success",
            "message": "Biometric reauthentication verified successfully. Trust level updated.",
            "session_revoked": False,
        }

    # 6. Handle failure / Impostor (CP-S08, RF-08)
    # Severe anomaly or impostor during reauthentication triggers session revocation
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
            "reason": "impostor_keystroke_pattern_detected",
        },
    )

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Biometric reauthentication failed: Impostor keystroke pattern detected. Session has been revoked.",
    )
