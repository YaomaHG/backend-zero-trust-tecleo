from datetime import datetime, timedelta, timezone
import pytest
from cryptography.exceptions import InvalidTag

from app.core.crypto import decrypt_vector, encrypt_vector
from app.core.security import create_access_token, hash_password
from app.models import AuditLog, KeystrokeProfile, Role, Session as UserSession, User


def test_cp_s01_no_token(client):
    """CP-S01: Accessing protected endpoint without token returns 401 Unauthorized."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    assert "token" in response.json()["detail"].lower() or "missing" in response.json()["detail"].lower()


def test_cp_s02_expired_token(client, db_session):
    """CP-S02: Accessing protected endpoint with expired JWT returns 401 Unauthorized."""
    user = User(
        username="user_expired",
        email="expired@example.com",
        password_hash=hash_password("Pass1234!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Issue a token with expiration in the past
    expired_token = create_access_token(
        data={"sub": user.username, "user_id": user.id, "roles": ["user"]},
        expires_delta=timedelta(minutes=-15),
    )

    # Also register the session in DB
    session = UserSession(
        user_id=user.id,
        jwt_token=expired_token,
        ip_address="127.0.0.1",
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=15),
        revoked=False,
    )
    db_session.add(session)
    db_session.commit()

    # 1. Via Authorization Bearer header
    header_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert header_resp.status_code == 401
    assert "expired" in header_resp.json()["detail"].lower()

    # 2. Via Cookie
    client.cookies.set("access_token", expired_token)
    cookie_resp = client.get("/api/auth/me")
    assert cookie_resp.status_code == 401
    assert "expired" in cookie_resp.json()["detail"].lower()
    client.cookies.clear()


def test_cp_s03_modified_token(client):
    """CP-S03: Accessing protected endpoint with altered JWT payload/signature returns 401."""
    # Register and login to obtain a valid signed JWT
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "user_tamper", "email": "tamper@example.com", "password": "Pass12345!"},
    )
    assert reg_resp.status_code == 201

    login_resp = client.post(
        "/api/auth/login",
        json={"username": "user_tamper", "password": "Pass12345!"},
    )
    assert login_resp.status_code == 200
    valid_token = login_resp.json()["access_token"]
    client.cookies.clear()  # Clear valid login cookie from test client jar

    # Tamper with the cryptographic signature
    parts = valid_token.split(".")
    tampered_sig = parts[2][:-4] + ("xxxx" if not parts[2].endswith("xxxx") else "yyyy")
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    # 1. Test altered signature via Authorization header
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert response.status_code == 401
    assert "invalid" in response.json()["detail"].lower()

    # 2. Test altered signature via Cookie
    client.cookies.set("access_token", tampered_token)
    cookie_resp = client.get("/api/auth/me")
    assert cookie_resp.status_code == 401
    assert "invalid" in cookie_resp.json()["detail"].lower()
    client.cookies.clear()


def test_cp_s05_privilege_escalation_rbac(client, db_session):
    """CP-S05: Normal user attempting to access admin endpoints returns 403 and logs access_denied."""
    # Register normal user (defaults to 'user' role)
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "normie_user", "email": "normie@example.com", "password": "Pass12345!"},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    login_resp = client.post(
        "/api/auth/login",
        json={"username": "normie_user", "password": "Pass12345!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Attempt to access restricted administrative endpoint
    admin_resp = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert admin_resp.status_code == 403
    assert "forbidden" in admin_resp.json()["detail"].lower() or "role" in admin_resp.json()["detail"].lower()

    # Verify audit_log recorded 'access_denied' event
    audit_record = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "access_denied")
        .first()
    )
    assert audit_record is not None
    assert audit_record.details.get("required_role") == "admin"


def test_cp_s06_brute_force_lockout(client, db_session):
    """CP-S06: 10 consecutive failed logins trigger 15-minute account lockout (RNF-04)."""
    username = "target_lockout"
    correct_password = "CorrectPassword123!"
    wrong_password = "WrongPassword999!"

    reg_resp = client.post(
        "/api/auth/register",
        json={"username": username, "email": "lockout@example.com", "password": correct_password},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    # Attempts 1 to 9: wrong password -> 401
    for attempt in range(1, 10):
        resp = client.post(
            "/api/auth/login",
            json={"username": username, "password": wrong_password},
        )
        assert resp.status_code == 401, f"Attempt {attempt} expected 401"

    # Attempt 10: reaches threshold -> account locked -> returns 403
    resp_10 = client.post(
        "/api/auth/login",
        json={"username": username, "password": wrong_password},
    )
    assert resp_10.status_code == 403, "Attempt 10 should lock account and return 403"
    assert "locked" in resp_10.json()["detail"].lower()

    # Attempts 11 to 19: subsequent attempts remain blocked -> 403
    for attempt in range(11, 20):
        resp = client.post(
            "/api/auth/login",
            json={"username": username, "password": wrong_password},
        )
        assert resp.status_code == 403, f"Attempt {attempt} expected 403"

    # Attempt 20: sends CORRECT password -> MUST STILL BE REJECTED with 403
    resp_20 = client.post(
        "/api/auth/login",
        json={"username": username, "password": correct_password},
    )
    assert resp_20.status_code == 403, "Attempt 20 with valid password must still return 403 while locked"
    assert "locked" in resp_20.json()["detail"].lower()

    # Verify user state in database
    db_session.expire_all()
    user = db_session.query(User).filter(User.id == user_id).first()
    assert user.failed_login_attempts >= 10
    assert user.locked_until is not None

    # Verify audit trail has 'account_locked' and 'login_blocked' events
    locked_events = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "account_locked")
        .all()
    )
    blocked_events = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "login_blocked")
        .all()
    )
    assert len(locked_events) >= 1
    assert len(blocked_events) >= 1


def test_cp_s10_biometric_template_encryption(db_session):
    """CP-S10: Biometric template AES-256-GCM encryption at rest, tampering detection (RNF-01)."""
    raw_vector = [0.125, 0.240, 0.095]
    encrypted_bytes = encrypt_vector(raw_vector)

    assert isinstance(encrypted_bytes, bytes)
    assert len(encrypted_bytes) >= 28  # 12-byte nonce + 16-byte tag

    # Verify no plaintext float values leaked in ciphertext
    assert b"0.125" not in encrypted_bytes
    assert b"0.240" not in encrypted_bytes
    assert b"0.095" not in encrypted_bytes

    # Persist into KeystrokeProfile model
    user = User(
        username="template_owner",
        email="template@example.com",
        password_hash=hash_password("TemplatePass123!"),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    profile = KeystrokeProfile(
        user_id=user.id,
        vector_encrypted=encrypted_bytes,
    )
    db_session.add(profile)
    db_session.commit()
    db_session.refresh(profile)

    # Read from DB and decrypt
    fetched = (
        db_session.query(KeystrokeProfile)
        .filter(KeystrokeProfile.user_id == user.id)
        .first()
    )
    decrypted_vector = decrypt_vector(fetched.vector_encrypted)
    assert decrypted_vector == pytest.approx(raw_vector, abs=1e-6)

    # Tamper with 1 byte of the encrypted data (flip last bit)
    tampered_bytes = bytearray(fetched.vector_encrypted)
    tampered_bytes[-1] ^= 0x01

    # Decrypting tampered bytes must fail GCM authentication and raise an exception
    with pytest.raises((InvalidTag, Exception)):
        decrypt_vector(bytes(tampered_bytes))


def test_token_revocation_logout(client):
    """RF-08: Logging out revokes session in DB and prevents further use of the same JWT."""
    # Register and login
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": "session_user", "email": "session@example.com", "password": "SessionPass123!"},
    )
    assert reg_resp.status_code == 201

    login_resp = client.post(
        "/api/auth/login",
        json={"username": "session_user", "password": "SessionPass123!"},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    # Verify access succeeds before logout
    me_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_resp.status_code == 200
    assert me_resp.json()["username"] == "session_user"

    # Call logout
    logout_resp = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert logout_resp.status_code == 200

    # Attempt access with the revoked token -> 401 Unauthorized
    after_logout_resp = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert after_logout_resp.status_code == 401
    assert "revoked" in after_logout_resp.json()["detail"].lower()


def test_admin_role_assignment_and_audit_logs(client, db_session):
    """Verifies admin user listing, role assignment, and audit log retrieval."""
    # 1. Create an admin user directly
    admin_role = db_session.query(Role).filter(Role.name == "admin").first()
    admin_user = User(
        username="super_admin",
        email="admin@example.com",
        password_hash=hash_password("AdminPass123!"),
        is_active=True,
    )
    admin_user.roles.append(admin_role)
    db_session.add(admin_user)
    db_session.commit()
    db_session.refresh(admin_user)

    # Login as admin
    admin_login = client.post(
        "/api/auth/login",
        json={"username": "super_admin", "password": "AdminPass123!"},
    )
    assert admin_login.status_code == 200
    admin_token = admin_login.json()["access_token"]

    # 2. Register regular user
    user_reg = client.post(
        "/api/auth/register",
        json={"username": "promotee", "email": "promotee@example.com", "password": "UserPass123!"},
    )
    assert user_reg.status_code == 201
    promotee_id = user_reg.json()["id"]

    # 3. Admin lists users
    list_resp = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert list_resp.status_code == 200
    users_data = list_resp.json()
    assert any(u["username"] == "promotee" for u in users_data)

    # 4. Admin assigns 'admin' role to promotee
    assign_resp = client.post(
        f"/api/admin/users/{promotee_id}/roles",
        json={"role_name": "admin"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert assign_resp.status_code == 200
    assert "admin" in assign_resp.json()["roles"]

    # 5. Admin views audit logs
    audit_resp = client.get(
        "/api/admin/audit-logs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert audit_resp.status_code == 200
    audit_data = audit_resp.json()
    assert any(log["event_type"] == "role_assigned" for log in audit_data)
