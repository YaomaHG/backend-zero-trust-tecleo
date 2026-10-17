"""
Unit and Integration Tests for Phase 3: Keystroke Dynamics Biometrics
Covers RF-03, RF-05, RNF-01, RNF-08, and CP-S08.
"""

import os
import pytest
import numpy as np
import joblib
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import User, KeystrokeProfile, AuditLog
from app.core.crypto import decrypt_vector
from app.biometric.service import biometric_service


@pytest.fixture(autouse=True)
def reload_biometric_model():
    """Ensure biometric service reloads the latest model from disk."""
    biometric_service._load_model()


def register_and_login_user(client: TestClient, username: str, email: str, password: str = "SecurePass123!") -> dict:
    """Helper to register and log in a test user, returning client cookies and user info."""
    reg_resp = client.post(
        "/api/auth/register",
        json={"username": username, "email": email, "password": password},
    )
    assert reg_resp.status_code == 201

    login_resp = client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    user_data = login_resp.json()["user"]
    return {"token": token, "user": user_data, "cookies": login_resp.cookies}


# Baseline 31-dimensional timing feature vector (Hold and Flight times in seconds)
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


def test_cmu_model_metrics():
    """
    Validates that the CMU Keystroke Dynamics trained model exists,
    loads properly, and satisfies biometric benchmark criteria:
    - EER < 0.20 (Section 3.8.3)
    - AUC >= 0.85
    - Optimal threshold calibrated
    - Artifacts generated (report markdown and ROC plot)
    """
    model_path = os.path.join("ml_models", "keystroke_gb_model.pkl")
    assert os.path.exists(model_path), f"Trained model not found at {model_path}"

    bundle = joblib.load(model_path)
    assert "model" in bundle
    assert "optimal_threshold" in bundle
    assert "eer" in bundle
    assert "auc" in bundle

    eer = bundle["eer"]
    auc = bundle["auc"]
    threshold = bundle["optimal_threshold"]

    # Biometric performance assertions
    assert eer < 0.20, f"EER ({eer:.4f}) must be under 0.20"
    assert auc >= 0.85, f"AUC ({auc:.4f}) must be >= 0.85"
    assert 0.15 <= threshold <= 0.85, f"Threshold ({threshold:.4f}) out of expected bounds"

    # Evaluation report and ROC graphic assertions
    report_path = os.path.join("docs", "BIOMETRIC_EVALUATION_REPORT.md")
    assert os.path.exists(report_path), "Evaluation report markdown missing"

    roc_plot_path = os.path.join("docs", "roc_curve_eer.png")
    assert os.path.exists(roc_plot_path), "ROC / EER plot missing"
    assert os.path.getsize(roc_plot_path) > 1000, "ROC plot file is empty"


def test_rf03_biometric_enrollment(client: TestClient, db_session: Session):
    """
    RF-03: Biometric enrollment.
    Verifies that an authenticated user can enroll their keystroke dynamics template,
    the template is encrypted with AES-256-GCM in keystroke_profiles (RNF-01),
    no keystrokes/text are stored (RNF-08), and 'biometric_enrolled' is logged in audit_log.
    """
    auth = register_and_login_user(client, "alice_enroll", "alice@example.com")
    cookies = auth["cookies"]
    user_id = auth["user"]["id"]

    # Check initial status (not enrolled)
    status_resp = client.get("/api/biometric/status", cookies=cookies)
    assert status_resp.status_code == 200
    assert status_resp.json()["enrolled"] is False

    # Enroll single vector
    enroll_resp = client.post(
        "/api/biometric/enroll",
        json={"vector": SAMPLE_31_VECTOR},
        cookies=cookies,
    )
    assert enroll_resp.status_code == 200
    data = enroll_resp.json()
    assert data["status"] == "success"
    assert data["vector_length"] == 31

    # Check updated status
    status_resp = client.get("/api/biometric/status", cookies=cookies)
    assert status_resp.status_code == 200
    assert status_resp.json()["enrolled"] is True

    # Database verification: AES-256-GCM encryption in keystroke_profiles
    profile = db_session.query(KeystrokeProfile).filter(KeystrokeProfile.user_id == user_id).first()
    assert profile is not None
    assert isinstance(profile.vector_encrypted, bytes)
    assert len(profile.vector_encrypted) >= 28  # Nonce (12) + Tag (16) + Ciphertext

    # Decrypt in memory and verify values match
    decrypted_vec = decrypt_vector(profile.vector_encrypted)
    assert len(decrypted_vec) == 31
    for orig, dec in zip(SAMPLE_31_VECTOR, decrypted_vec):
        assert abs(orig - dec) < 1e-4

    # Audit log verification
    audit_entry = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "biometric_enrolled")
        .first()
    )
    assert audit_entry is not None
    assert audit_entry.details.get("vector_length") == 31


def test_rf03_biometric_enrollment_with_samples(client: TestClient, db_session: Session):
    """
    RF-03: Multi-sample enrollment.
    Verifies that enrolling with 3-5 sample repetitions computes an accurate mean reference template.
    """
    auth = register_and_login_user(client, "bob_samples", "bob@example.com")
    cookies = auth["cookies"]
    user_id = auth["user"]["id"]

    # 3 repetitions with slight natural variation
    sample1 = [x * 0.98 for x in SAMPLE_31_VECTOR]
    sample2 = [x * 1.00 for x in SAMPLE_31_VECTOR]
    sample3 = [x * 1.02 for x in SAMPLE_31_VECTOR]

    enroll_resp = client.post(
        "/api/biometric/enroll",
        json={"samples": [sample1, sample2, sample3]},
        cookies=cookies,
    )
    assert enroll_resp.status_code == 200
    assert enroll_resp.json()["vector_length"] == 31

    profile = db_session.query(KeystrokeProfile).filter(KeystrokeProfile.user_id == user_id).first()
    assert profile is not None
    decrypted = decrypt_vector(profile.vector_encrypted)
    # The mean of (0.98, 1.00, 1.02) * x is exactly 1.00 * x
    for orig, mean_val in zip(SAMPLE_31_VECTOR, decrypted):
        assert abs(orig - mean_val) < 1e-3


def test_rf05_legitimate_user_verification(client: TestClient, db_session: Session):
    """
    RF-05: Legitimate user verification.
    Enrolls a template and verifies with a genuine keystroke sample with natural typing variation.
    Expects match == True, score >= threshold, and 'biometric_verify_success' audit entry.
    """
    auth = register_and_login_user(client, "charlie_legit", "charlie@example.com")
    cookies = auth["cookies"]
    user_id = auth["user"]["id"]

    # Enroll user template
    client.post(
        "/api/biometric/enroll",
        json={"vector": SAMPLE_31_VECTOR},
        cookies=cookies,
    )

    # Legitimate attempt: minor 2% noise consistent with same user typing
    legit_sample = [round(x * 1.015, 6) for x in SAMPLE_31_VECTOR]

    verify_resp = client.post(
        "/api/biometric/verify",
        json={"vector": legit_sample},
        cookies=cookies,
    )
    assert verify_resp.status_code == 200
    res = verify_resp.json()
    assert res["match"] is True
    assert res["score"] >= res["threshold"]

    # Check audit log for success
    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "biometric_verify_success")
        .first()
    )
    assert audit is not None
    assert audit.details["score"] >= audit.details["threshold"]


def test_cp_s08_impostor_pattern_rejected(client: TestClient, db_session: Session):
    """
    CP-S08: Impostor pattern rejection.
    Simulates an attacker attempting to access a legitimate user account by submitting
    an impostor keystroke pattern with significantly distorted rhythms (2.5x slower / erratic).
    Expects match == False, score < threshold, and 'biometric_verify_failed' logged in audit_log.
    """
    auth = register_and_login_user(client, "victim_user", "victim@example.com")
    cookies = auth["cookies"]
    user_id = auth["user"]["id"]

    # Victim enrolls their normal keystroke profile
    client.post(
        "/api/biometric/enroll",
        json={"vector": SAMPLE_31_VECTOR},
        cookies=cookies,
    )

    # Impostor attempt: 2.5x slower timing cadence with irregular rhythm
    impostor_sample = [round(x * 2.5 + 0.15, 6) for x in SAMPLE_31_VECTOR]

    verify_resp = client.post(
        "/api/biometric/verify",
        json={"vector": impostor_sample},
        cookies=cookies,
    )
    assert verify_resp.status_code == 200
    res = verify_resp.json()
    assert res["match"] is False
    assert res["score"] < res["threshold"]

    # Audit log verification: must record biometric_verify_failed
    audit = (
        db_session.query(AuditLog)
        .filter(AuditLog.user_id == user_id, AuditLog.event_type == "biometric_verify_failed")
        .first()
    )
    assert audit is not None
    assert audit.details["score"] < audit.details["threshold"]


def test_biometric_verification_unregistered_profile(client: TestClient):
    """
    Verifies that calling verify on an account without an enrolled profile returns HTTP 404.
    """
    auth = register_and_login_user(client, "no_profile_user", "noprofile@example.com")
    cookies = auth["cookies"]

    verify_resp = client.post(
        "/api/biometric/verify",
        json={"vector": SAMPLE_31_VECTOR},
        cookies=cookies,
    )
    assert verify_resp.status_code == 404
    assert "enrolled" in verify_resp.json()["detail"].lower()


def test_biometric_dimension_mismatch_fails_verification(client: TestClient):
    """
    Verifies that submitting a vector of different dimension than the enrolled template fails verification.
    """
    auth = register_and_login_user(client, "dim_user", "dim@example.com")
    cookies = auth["cookies"]

    client.post(
        "/api/biometric/enroll",
        json={"vector": SAMPLE_31_VECTOR},
        cookies=cookies,
    )

    # Send only 15 features instead of 31
    verify_resp = client.post(
        "/api/biometric/verify",
        json={"vector": SAMPLE_31_VECTOR[:15]},
        cookies=cookies,
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["match"] is False
    assert verify_resp.json()["score"] == 0.0


def test_biometric_raw_events_pipeline(client: TestClient):
    """
    Verifies feature extraction from raw keypress events without letters (RNF-08).
    """
    auth = register_and_login_user(client, "raw_events_user", "rawevents@example.com")
    cookies = auth["cookies"]

    # 4 synthetic press/release events with performance.now() millisecond timestamps
    raw_events = [
        {"down": 100.0, "up": 190.0},
        {"down": 300.0, "up": 405.0},
        {"down": 520.0, "up": 615.0},
        {"down": 740.0, "up": 830.0},
    ]

    enroll_resp = client.post(
        "/api/biometric/enroll",
        json={"raw_events": raw_events},
        cookies=cookies,
    )
    assert enroll_resp.status_code == 200
    # 4 events -> 4 holds + 3 DD flights + 3 UD flights = 10 features
    assert enroll_resp.json()["vector_length"] == 10

    # Verify with identical raw events
    verify_resp = client.post(
        "/api/biometric/verify",
        json={"raw_events": raw_events},
        cookies=cookies,
    )
    assert verify_resp.status_code == 200
    assert verify_resp.json()["match"] is True
