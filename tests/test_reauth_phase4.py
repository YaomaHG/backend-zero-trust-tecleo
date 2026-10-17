"""
Unit and Integration Tests for Phase 4: Zero Trust Adaptive Reauthentication Engine
Covers:
- CP-S07: Continuous risk evaluation and IP change detection (RF-04, CP-S07)
- RF-04 / RF-05: Sensitive corporate operation flow with step-up biometric reauth
- CP-S04: Anti-Replay protection via single-use nonces and payload hashing
- CP-S08 / RF-08: Impostor pattern rejection and session revocation during reauth
- CP-S09: SQL Injection sanitization and data integrity verification
- RNF-03: IP-based Rate Limiting (5 requests/minute threshold and audit logging)
"""

import time
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.rate_limiter import rate_limiter
from app.models import AuditLog, KeystrokeProfile, ReauthEvent, Role, Session as UserSession, User
from app.reauth.service import anti_replay_store


SAMPLE_31_VECTOR = [
    0.098, 0.215, 0.117,
    0.105, 0.180, 0.075,
    0.092, 0.220, 0.128,
    0.110, 0.240, 0.130,
    0.095, 0.280, 0.185,
    0.145, 0.190, 0.045,
    0.102, 0.205, 0.103,
    0.099, 0.210, 0.111,
    0.108, 0.195, 0.087,
    0.101, 0.235, 0.134,
    0.120
]

IMPOSTOR_31_VECTOR = [0.850] * 31


def register_and_login_user(
    client: TestClient,
    username: str,
    email: str,
    password: str = "StrongPass123!",
    ip_address: str = "127.0.0.1",
) -> dict:
    """Helper to register and log in a user with a specific IP address header."""
    headers = {"X-Forwarded-For": ip_address}
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
        headers=headers,
    )
    assert reg_resp.status_code == 201

    login_resp = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers=headers,
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    user_data = login_resp.json()["user"]

    # Explicitly set auth token on client for subsequent authenticated calls
    client.headers.update({"Authorization": f"Bearer {token}"})
    return {"token": token, "user": user_data, "headers": headers}


def enroll_user_profile(client: TestClient, vector: list = SAMPLE_31_VECTOR) -> None:
    """Helper to enroll biometric keystroke profile for currently authenticated user."""
    resp = client.post("/api/biometric/enroll", json={"vector": vector})
    assert resp.status_code in [200, 201]


# -----------------------------------------------------------------------------
# 1. CP-S07: IP Change Triggers Reauthentication
# -----------------------------------------------------------------------------
def test_cp_s07_ip_change_triggers_reauth(client: TestClient, db_session: Session):
    """
    CP-S07: User logs in from 192.168.1.10, then attempts to operate from 10.0.0.99.
    System detects IP change, returns 403 Forbidden with reauth_required=True,
    logs risk event in audit_log, and restores trust after successful biometric reauth.
    """
    anti_replay_store.reset()
    user_info = register_and_login_user(
        client,
        username="ip_shift_user",
        email="ip_shift@example.com",
        ip_address="192.168.1.10",
    )
    user_id = user_info["user"]["id"]
    enroll_user_profile(client, SAMPLE_31_VECTOR)

    # 1. Access from original IP: evaluate should return 200 OK (no risk)
    resp_orig = client.get("/api/reauth/evaluate", headers={"X-Forwarded-For": "192.168.1.10"})
    assert resp_orig.status_code == 200
    assert resp_orig.json()["reauth_required"] is False

    # 2. Access from a different IP (10.0.0.99): triggers CP-S07 risk event
    resp_risk = client.get("/api/reauth/evaluate", headers={"X-Forwarded-For": "10.0.0.99"})
    assert resp_risk.status_code == 403
    body = resp_risk.json()
    assert body["reauth_required"] is True
    assert body["risk_event"] == "ip_change"

    # Verify audit_log recorded risk_detected
    db_session.expire_all()
    audit_risk = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "risk_detected")
        .first()
    )
    assert audit_risk is not None
    assert audit_risk.details.get("risk_event") == "ip_change"

    # 3. Request challenge nonce from new IP
    challenge_resp = client.post(
        "/api/reauth/challenge",
        headers={"X-Forwarded-For": "10.0.0.99"},
    )
    assert challenge_resp.status_code == 200
    nonce = challenge_resp.json()["challenge_nonce"]
    assert len(nonce) > 16

    # 4. Perform step-up biometric reauthentication from new IP with legitimate vector
    verify_resp = client.post(
        "/api/reauth/verify",
        json={
            "risk_event": "ip_change",
            "challenge_nonce": nonce,
            "vector": SAMPLE_31_VECTOR,
            "timestamp": time.time(),
        },
        headers={"X-Forwarded-For": "10.0.0.99"},
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["match"] is True
    assert verify_resp.json()["reauth_status"] == "success"

    # Verify reauth_events recorded result=True
    db_session.expire_all()
    reauth_rec = (
        db_session.query(ReauthEvent)
        .filter(ReauthEvent.user_id == user_id, ReauthEvent.risk_event == "ip_change")
        .order_by(ReauthEvent.id.desc())
        .first()
    )
    assert reauth_rec is not None
    assert reauth_rec.result is True

    # Verify session IP was updated to 10.0.0.99 in DB
    session_rec = (
        db_session.query(UserSession)
        .filter(UserSession.user_id == user_id, UserSession.revoked.is_(False))
        .first()
    )
    assert session_rec.ip_address == "10.0.0.99"

    # 5. Subsequent evaluate from 10.0.0.99 now succeeds (trusted)
    resp_post = client.get("/api/reauth/evaluate", headers={"X-Forwarded-For": "10.0.0.99"})
    assert resp_post.status_code == 200
    assert resp_post.json()["reauth_required"] is False


# -----------------------------------------------------------------------------
# 2. RF-04 / RF-05: Sensitive Corporate Operation Flow
# -----------------------------------------------------------------------------
def test_rf04_rf05_sensitive_operation_flow(client: TestClient, db_session: Session):
    """
    RF-04 / RF-05: Executing /api/operations/sensitive-action without prior reauth
    demands step-up biometric verification (reauth_required=True). After verifying
    legitimate dynamics, operation succeeds (200 OK) and registers in reauth_events.
    """
    anti_replay_store.reset()
    user_info = register_and_login_user(
        client,
        username="sensitive_user",
        email="sensitive@example.com",
        ip_address="192.168.1.50",
    )
    user_id = user_info["user"]["id"]
    enroll_user_profile(client, SAMPLE_31_VECTOR)

    headers = {"X-Forwarded-For": "192.168.1.50"}

    # 1. Attempt sensitive action before step-up reauthentication
    resp_initial = client.post(
        "/api/operations/sensitive-action",
        json={"action_type": "simulated_transfer", "amount": 5000.0, "destination_account": "ACC-998877"},
        headers=headers,
    )
    assert resp_initial.status_code == 403
    assert resp_initial.json()["reauth_required"] is True
    assert resp_initial.json()["risk_event"] == "sensitive_operation"

    # 2. Obtain challenge nonce
    chal_resp = client.post("/api/reauth/challenge", headers=headers)
    assert chal_resp.status_code == 200
    nonce = chal_resp.json()["challenge_nonce"]

    # 3. Perform biometric reauthentication for sensitive operation
    verify_resp = client.post(
        "/api/reauth/verify",
        json={
            "risk_event": "sensitive_operation",
            "challenge_nonce": nonce,
            "vector": SAMPLE_31_VECTOR,
            "timestamp": time.time(),
        },
        headers=headers,
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["match"] is True

    # Verify reauth_events persisted success
    db_session.expire_all()
    event_entry = (
        db_session.query(ReauthEvent)
        .filter(ReauthEvent.user_id == user_id, ReauthEvent.risk_event == "sensitive_operation")
        .first()
    )
    assert event_entry is not None
    assert event_entry.result is True

    # 4. Re-execute sensitive action -> Now proceeds successfully (200 OK)
    resp_success = client.post(
        "/api/operations/sensitive-action",
        json={"action_type": "simulated_transfer", "amount": 5000.0, "destination_account": "ACC-998877"},
        headers=headers,
    )
    assert resp_success.status_code == 200
    body = resp_success.json()
    assert body["status"] == "success"
    assert body["operation"] == "simulated_transfer"

    # Verify audit trail contains sensitive_operation_executed
    db_session.expire_all()
    audit_entry = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "sensitive_operation_executed")
        .first()
    )
    assert audit_entry is not None
    assert audit_entry.details.get("amount") == 5000.0


# -----------------------------------------------------------------------------
# 3. CP-S04: Anti-Replay Protection
# -----------------------------------------------------------------------------
def test_cp_s04_replay_attack_rejected(client: TestClient, db_session: Session):
    """
    CP-S04: Captures a valid reauth request payload and resends it (or reuses a consumed nonce).
    The system immediately rejects with 400 Bad Request, logs replay_attack_detected in
    audit_log, and saves a failed record in reauth_events.
    """
    anti_replay_store.reset()
    user_info = register_and_login_user(
        client,
        username="replay_victim",
        email="replay_victim@example.com",
    )
    user_id = user_info["user"]["id"]
    enroll_user_profile(client, SAMPLE_31_VECTOR)

    # 1. Get single-use challenge nonce
    chal_resp = client.post("/api/reauth/challenge")
    assert chal_resp.status_code == 200
    nonce = chal_resp.json()["challenge_nonce"]

    payload = {
        "risk_event": "ip_change",
        "challenge_nonce": nonce,
        "vector": SAMPLE_31_VECTOR,
        "timestamp": time.time(),
    }

    # 2. First submission succeeds
    resp1 = client.post("/api/reauth/verify", json=payload)
    assert resp1.status_code == 200
    assert resp1.json()["match"] is True

    # 3. Second submission of the exact same payload (Replay Attack - CP-S04)
    resp2 = client.post("/api/reauth/verify", json=payload)
    assert resp2.status_code == 400
    assert "replay attack detected" in resp2.json()["detail"].lower()

    # 4. Check audit log for replay_attack_detected
    db_session.expire_all()
    replay_audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "replay_attack_detected")
        .first()
    )
    assert replay_audit is not None
    assert replay_audit.details.get("nonce") == nonce

    # 5. Check reauth_events for replay failure record
    replay_event = (
        db_session.query(ReauthEvent)
        .filter(ReauthEvent.user_id == user_id, ReauthEvent.risk_event == "replay_attack")
        .first()
    )
    assert replay_event is not None
    assert replay_event.result is False


# -----------------------------------------------------------------------------
# 4. CP-S08 / RF-08: Impostor Reauth Revokes Session
# -----------------------------------------------------------------------------
def test_cp_s08_impostor_during_reauth_revokes_session(client: TestClient, db_session: Session):
    """
    CP-S08 & RF-08: During step-up reauthentication, an impostor typing pattern is submitted.
    Verification fails (result=False in reauth_events), and the session is revoked (sessions.revoked = True).
    Subsequent requests with that token return 401 Unauthorized.
    """
    anti_replay_store.reset()
    user_info = register_and_login_user(
        client,
        username="legit_owner",
        email="legit_owner@example.com",
    )
    user_id = user_info["user"]["id"]
    token = user_info["token"]
    enroll_user_profile(client, SAMPLE_31_VECTOR)

    # Impostor triggers reauth with wildly different timing vector
    chal_resp = client.post("/api/reauth/challenge")
    nonce = chal_resp.json()["challenge_nonce"]

    impostor_payload = {
        "risk_event": "ip_change",
        "challenge_nonce": nonce,
        "vector": IMPOSTOR_31_VECTOR,
        "timestamp": time.time(),
    }

    resp_impostor = client.post("/api/reauth/verify", json=impostor_payload)
    # Impostor attempt must be rejected with 403 Forbidden
    assert resp_impostor.status_code == 403
    assert "impostor" in resp_impostor.json()["detail"].lower() or "revoked" in resp_impostor.json()["detail"].lower()

    # Verify reauth_events recorded result=False
    db_session.expire_all()
    failed_reauth = (
        db_session.query(ReauthEvent)
        .filter(ReauthEvent.user_id == user_id, ReauthEvent.risk_event == "ip_change")
        .order_by(ReauthEvent.id.desc())
        .first()
    )
    assert failed_reauth is not None
    assert failed_reauth.result is False

    # Verify session is marked revoked in database (RF-08)
    session_rec = (
        db_session.query(UserSession)
        .filter(UserSession.jwt_token == token)
        .first()
    )
    assert session_rec is not None
    assert session_rec.revoked is True

    # Verify audit_log recorded session_revoked_biometric_failure
    audit_revoked = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "session_revoked_biometric_failure")
        .first()
    )
    assert audit_revoked is not None

    # Subsequent request using this revoked token must fail with 401 Unauthorized
    resp_blocked = client.get("/api/auth/me")
    assert resp_blocked.status_code == 401
    assert "revoked" in resp_blocked.json()["detail"].lower()


# -----------------------------------------------------------------------------
# 5. CP-S09: SQL Injection Sanitization
# -----------------------------------------------------------------------------
def test_cp_s09_sql_injection_sanitization(client: TestClient, db_session: Session):
    """
    CP-S09: Sends SQL injection payloads (e.g. admin' OR '1'='1' --, '; DROP TABLE users; --)
    into registration, login, and query endpoints.
    Verifies that ORM parameterization neutralizes injections without data damage or syntax errors.
    """
    sqli_payloads = [
        "admin' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT id, username, password_hash FROM users --",
        "1' OR '1' = '1",
    ]

    # Count initial tables state
    initial_users_count = db_session.query(User).count()
    initial_roles_count = db_session.query(Role).count()

    for payload in sqli_payloads:
        # 1. SQL Injection attempt via Login endpoint
        login_resp = client.post(
            "/api/auth/login",
            json={"username": payload, "password": "' OR '1'='1"},
        )
        # Must fail safely with 401 Unauthorized (no unauthorized admin session created, no 500 error)
        assert login_resp.status_code in [401, 400]

        # 2. SQL Injection attempt via Registration endpoint
        reg_resp = client.post(
            "/api/auth/register",
            json={
                "username": f"sqli_{payload[:10]}",
                "email": f"sqli_{hash(payload)}@example.com",
                "password": "ValidPassword123!",
            },
        )
        # Even if created or rejected, it must never execute raw SQL drop
        assert reg_resp.status_code in [201, 400]

    # Verify tables remain intact and accessible
    db_session.expire_all()
    final_users_count = db_session.query(User).count()
    final_roles_count = db_session.query(Role).count()

    assert final_users_count >= initial_users_count
    assert final_roles_count == initial_roles_count

    # Role table should still have 'admin' and 'user'
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    assert admin_role is not None


# -----------------------------------------------------------------------------
# 6. RNF-03: Rate Limiting by IP
# -----------------------------------------------------------------------------
def test_rnf03_rate_limiting(client: TestClient, db_session: Session):
    """
    RNF-03: Verifies that exceeding the 5 requests/minute threshold from a single IP
    returns 429 Too Many Requests, logs rate_limit_exceeded in audit_log,
    and includes Retry-After header.
    """
    test_ip = "198.51.100.42"
    headers = {"X-Forwarded-For": test_ip}

    # Enable and calibrate rate limiter for test
    rate_limiter.reset()
    rate_limiter.set_limit(max_requests=5, window_seconds=60)
    rate_limiter.set_enabled(True)

    try:
        # Send 5 requests (all should succeed or return non-429)
        for i in range(5):
            resp = client.post(
                "/api/auth/login",
                json={"username": f"user_{i}", "password": "WrongPassword!"},
                headers=headers,
            )
            assert resp.status_code != 429, f"Request {i+1} should not be rate limited"

        # 6th request from the same IP must trigger 429 Too Many Requests
        resp_6 = client.post(
            "/api/auth/login",
            json={"username": "user_overflow", "password": "WrongPassword!"},
            headers=headers,
        )
        assert resp_6.status_code == 429
        assert "rate limit exceeded" in resp_6.json()["detail"].lower()
        assert "Retry-After" in resp_6.headers

        # Verify rate_limit_exceeded audit log
        db_session.expire_all()
        audit_entry = (
            db_session.query(AuditLog)
            .filter(AuditLog.ip_address == test_ip, AuditLog.event_type == "rate_limit_exceeded")
            .first()
        )
        assert audit_entry is not None
        assert audit_entry.details.get("limit") == 5

        # Verify a different IP is unaffected
        resp_other_ip = client.post(
            "/api/auth/login",
            json={"username": "other_ip_user", "password": "WrongPassword!"},
            headers={"X-Forwarded-For": "198.51.100.43"},
        )
        assert resp_other_ip.status_code != 429

    finally:
        rate_limiter.reset()
        rate_limiter.set_enabled(False)
