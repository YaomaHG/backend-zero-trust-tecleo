"""
Phase 5 Test Suite: Front-end SPA Static Serving & Full E2E Zero Trust Workflow
(Sections 3.3, 3.4, 3.6.3, RF-01 to RF-09, RNF-01, RNF-08, CP-S01 to CP-S10)
"""

import os
from typing import List
import pytest
from fastapi.testclient import TestClient

from app.models import User, KeystrokeProfile, Session as UserSession, AuditLog


# Standard 31-dimensional synthetic keystroke timing vectors (in seconds)
SAMPLE_GENUINE_1: List[float] = [
    0.095, 0.170, 0.075,
    0.090, 0.165, 0.075,
    0.088, 0.160, 0.072,
    0.092, 0.180, 0.088,
    0.100, 0.190, 0.090,
    0.095, 0.175, 0.080,
    0.090, 0.160, 0.070,
    0.085, 0.155, 0.070,
    0.089, 0.165, 0.076,
    0.094, 0.185, 0.091,
    0.105
]

SAMPLE_GENUINE_2: List[float] = [
    0.096, 0.172, 0.076,
    0.089, 0.164, 0.075,
    0.090, 0.162, 0.072,
    0.091, 0.179, 0.088,
    0.099, 0.189, 0.090,
    0.096, 0.174, 0.078,
    0.089, 0.159, 0.070,
    0.086, 0.156, 0.070,
    0.088, 0.166, 0.078,
    0.095, 0.184, 0.089,
    0.104
]

SAMPLE_GENUINE_3: List[float] = [
    0.094, 0.169, 0.075,
    0.091, 0.166, 0.075,
    0.087, 0.159, 0.072,
    0.093, 0.181, 0.088,
    0.101, 0.191, 0.090,
    0.094, 0.176, 0.082,
    0.091, 0.161, 0.070,
    0.084, 0.154, 0.070,
    0.090, 0.164, 0.074,
    0.093, 0.186, 0.093,
    0.106
]


def test_serve_index_html(client: TestClient):
    """
    Verifies GET / returns 200 OK with the SPA HTML interface and key elements.
    """
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html_content = response.text

    # Verify key SPA structural anchors
    assert "Zero Trust Keystroke Shield" in html_content
    assert "keystroke.js" in html_content
    assert "app.js" in html_content
    assert "styles.css" in html_content
    assert "display-target-phrase" in html_content
    assert "modal-reauth" in html_content


def test_serve_static_assets(client: TestClient):
    """
    Verifies that static assets (CSS and JavaScript files) are properly served under /static.
    """
    # 1. CSS styles
    css_resp = client.get("/static/css/styles.css")
    assert css_resp.status_code == 200
    assert "text/css" in css_resp.headers["content-type"]
    assert "--cyan-neon" in css_resp.text

    # 2. Keystroke dynamics engine
    keystroke_resp = client.get("/static/js/keystroke.js")
    assert keystroke_resp.status_code == 200
    assert ("javascript" in keystroke_resp.headers["content-type"] or
            "text/plain" in keystroke_resp.headers["content-type"])
    assert "class KeystrokeCapture" in keystroke_resp.text
    assert "performance.now()" in keystroke_resp.text

    # 3. SPA controller
    app_resp = client.get("/static/js/app.js")
    assert app_resp.status_code == 200
    assert ("javascript" in app_resp.headers["content-type"] or
            "text/plain" in app_resp.headers["content-type"])
    assert "apiFetch" in app_resp.text
    assert "handleZeroTrustRiskTrigger" in app_resp.text


def test_default_admin_user_seeded(client: TestClient, db_session):
    """
    Verifies that the default admin user ('admin' / 'AdminZeroTrust2026!') exists
    and can successfully authenticate and access RBAC protected resources.
    """
    admin_login_resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "AdminZeroTrust2026!"},
    )
    assert admin_login_resp.status_code == 200
    data = admin_login_resp.json()
    assert data["user"]["username"] == "admin"
    roles = [r["name"] if isinstance(r, dict) else r for r in data["user"]["roles"]]
    assert "admin" in roles

    # Verify admin can access audit logs
    admin_token = data["access_token"]
    audit_resp = client.get(
        "/api/admin/audit-logs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert audit_resp.status_code == 200
    assert isinstance(audit_resp.json(), list)


def test_complete_e2e_frontend_flow(client: TestClient, db_session):
    """
    Comprehensive End-to-End Test validating the full Zero Trust lifecycle:
    1. User Registration (RF-01)
    2. Authentication & JWT Cookie Session (RF-02)
    3. Biometric Enrollment with 3 repetitions (RF-03, RNF-08) -> AES-256-GCM (RNF-01)
    4. Sensitive Corporate Operation Attempt (RF-04) -> 403 Forbidden with reauth_required
    5. Single-use Challenge Nonce Generation (CP-S04)
    6. Adaptive Reauthentication with Legitimate Keystroke Vector (RF-05, CP-S08) -> Match
    7. Retried Sensitive Operation Authorization -> 200 OK
    8. Context Anomaly Detection (CP-S07: IP Address Change) -> 403 Forbidden
    9. Admin Inspection of Immutable Audit Trail (RF-07, RNF-05)
    """
    # -------------------------------------------------------------
    # 1. Register a fresh user
    # -------------------------------------------------------------
    username = "e2e_analyst_user"
    email = "analyst@zerotrust.local"
    password = "SecOpsZeroTrust2026!"

    reg_resp = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert reg_resp.status_code == 201
    user_id = reg_resp.json()["id"]

    # -------------------------------------------------------------
    # 2. Login as newly registered user (Initial IP: 127.0.0.1)
    # -------------------------------------------------------------
    login_resp = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}

    # Verify session cookie was set
    assert "access_token" in login_resp.cookies

    # -------------------------------------------------------------
    # 3. Check Initial Biometric Status (Should be pending)
    # -------------------------------------------------------------
    status_resp = client.get("/api/biometric/status", headers=auth_headers)
    assert status_resp.status_code == 200
    assert status_resp.json()["enrolled"] is False

    # -------------------------------------------------------------
    # 4. Guided Biometric Enrollment (3 repetitions, RNF-08 compliant)
    # -------------------------------------------------------------
    enroll_resp = client.post(
        "/api/biometric/enroll",
        headers=auth_headers,
        json={"samples": [SAMPLE_GENUINE_1, SAMPLE_GENUINE_2, SAMPLE_GENUINE_3]},
    )
    assert enroll_resp.status_code == 200
    assert enroll_resp.json()["vector_length"] == 31

    # Verify template is now encrypted at rest in DB
    profile = db_session.query(KeystrokeProfile).filter(KeystrokeProfile.user_id == user_id).first()
    assert profile is not None
    assert profile.vector_encrypted is not None

    # Biometric status should now be enrolled
    status_resp2 = client.get("/api/biometric/status", headers=auth_headers)
    assert status_resp2.status_code == 200
    assert status_resp2.json()["enrolled"] is True

    # -------------------------------------------------------------
    # 5. Attempt Sensitive Operation without prior reauth -> 403 Forbidden
    # -------------------------------------------------------------
    op_payload = {
        "action_type": "wire_transfer",
        "amount": 95000.00,
        "destination_account": "ES91-2100-0418-4502-0005-1337"
    }
    op_resp = client.post(
        "/api/operations/sensitive-action",
        headers=auth_headers,
        json=op_payload,
    )
    assert op_resp.status_code == 403
    op_data = op_resp.json()
    assert op_data["reauth_required"] is True
    assert op_data["risk_event"] == "sensitive_operation"

    # -------------------------------------------------------------
    # 6. Issue Anti-Replay Challenge Nonce (CP-S04)
    # -------------------------------------------------------------
    challenge_resp = client.post("/api/reauth/challenge", headers=auth_headers)
    assert challenge_resp.status_code == 200
    challenge_data = challenge_resp.json()
    nonce = challenge_data["challenge_nonce"]
    assert len(nonce) > 16
    assert challenge_data["target_phrase"] == "tie5Roanl"
    assert challenge_data["expires_in"] == 300

    # -------------------------------------------------------------
    # 7. Adaptive Reauthentication Verification with Genuine Keystroke Timing
    # -------------------------------------------------------------
    import time
    reauth_payload = {
        "risk_event": "sensitive_operation",
        "challenge_nonce": nonce,
        "timestamp": time.time(),
        "vector": SAMPLE_GENUINE_2,
    }
    reauth_resp = client.post(
        "/api/reauth/verify",
        headers=auth_headers,
        json=reauth_payload,
    )
    assert reauth_resp.status_code == 200
    reauth_data = reauth_resp.json()
    assert reauth_data["match"] is True
    assert reauth_data["score"] >= reauth_data["threshold"]
    assert reauth_data["reauth_status"] == "success"

    # -------------------------------------------------------------
    # 8. Retried Sensitive Operation is Now Authorized (200 OK)
    # -------------------------------------------------------------
    op_retry_resp = client.post(
        "/api/operations/sensitive-action",
        headers=auth_headers,
        json=op_payload,
    )
    assert op_retry_resp.status_code == 200
    op_retry_data = op_retry_resp.json()
    assert op_retry_data["status"] == "success"
    assert op_retry_data["operation"] == "wire_transfer"

    # -------------------------------------------------------------
    # 9. Context Anomaly Detection (CP-S07: Sudden IP Change)
    # -------------------------------------------------------------
    spoofed_ip = "189.203.45.12"
    spoofed_headers = {
        "Authorization": f"Bearer {token}",
        "X-Forwarded-For": spoofed_ip,
    }

    # Immediate detection of IP change
    risk_resp = client.get("/api/reauth/evaluate", headers=spoofed_headers)
    assert risk_resp.status_code == 403
    risk_data = risk_resp.json()
    assert risk_data["reauth_required"] is True
    assert risk_data["risk_event"] == "ip_change"

    # -------------------------------------------------------------
    # 10. Audit Trail Verification by Administrator (RF-07, RNF-05)
    # -------------------------------------------------------------
    admin_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "AdminZeroTrust2026!"},
    )
    admin_token = admin_login.json()["access_token"]
    audit_resp = client.get(
        "/api/admin/audit-logs?limit=50",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert audit_resp.status_code == 200
    logs = audit_resp.json()
    events = [l["event_type"] for l in logs]

    # Verify key audit trail events were immutably recorded
    assert "user_registered" in events
    assert "biometric_enrolled" in events
    assert "reauth_challenge_issued" in events
    assert "reauth_success" in events
    assert "sensitive_operation_executed" in events
    assert "risk_detected" in events
