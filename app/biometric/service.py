"""
Biometric Service Implementation
Zero Trust Continuous Keystroke Dynamics Authentication (RF-03, RF-05, RNF-01, RNF-08, CP-S08)
"""

import os
import logging
from typing import Any, Dict, List, Optional
import numpy as np
import joblib
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models import User, KeystrokeProfile
from app.core.crypto import encrypt_vector, decrypt_vector
from app.biometric.features import (
    extract_features_from_events,
    validate_and_normalize_vector,
    compute_template_from_samples,
    calculate_statistical_similarity,
)

logger = logging.getLogger("zero_trust_biometric")

DEFAULT_MODEL_PATH = os.path.join("ml_models", "keystroke_gb_model.pkl")


class BiometricService:
    """
    Manages keystroke profile enrollment (AES-256-GCM encryption in DB)
    and live identity verification via Gradient Boosting and statistical hybrid scoring.
    """

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        self.model_path = model_path
        self.model = None
        self.optimal_threshold: float = 0.50
        self.eer: float = 0.10
        self.auc: float = 0.90
        self.feature_names: List[str] = []
        self._load_model()

    def _load_model(self) -> None:
        """Loads trained Gradient Boosting model bundle from disk if present."""
        if os.path.exists(self.model_path):
            try:
                bundle = joblib.load(self.model_path)
                self.model = bundle.get("model")
                self.optimal_threshold = float(bundle.get("optimal_threshold", 0.50))
                self.eer = float(bundle.get("eer", 0.10))
                self.auc = float(bundle.get("auc", 0.90))
                self.feature_names = bundle.get("feature_names", [])
                logger.info(
                    f"Biometric GradientBoosting model loaded from {self.model_path} "
                    f"(Threshold={self.optimal_threshold:.4f}, EER={self.eer:.4f}, AUC={self.auc:.4f})"
                )
            except Exception as e:
                logger.warning(f"Could not load biometric model from {self.model_path}: {e}")
        else:
            logger.info(f"Model file not found at {self.model_path}; using statistical scoring engine.")

    def enroll_keystroke_profile(
        self,
        db: Session,
        user: User,
        vector: Optional[List[float]] = None,
        samples: Optional[List[List[float]]] = None,
        raw_events: Optional[List[Dict[str, float]]] = None,
    ) -> KeystrokeProfile:
        """
        Enrolls or updates a user's biometric keystroke template.
        The template is encrypted at rest using AES-256-GCM (RF-03, RNF-01).

        Args:
            db: Database session
            user: Authenticated user
            vector: Optional single feature vector
            samples: Optional multiple repetition vectors (calculates mean template)
            raw_events: Optional raw press/release timing events

        Returns:
            KeystrokeProfile: The persisted encrypted profile record.
        """
        if samples is not None and len(samples) > 0:
            template = compute_template_from_samples(samples)
        elif vector is not None and len(vector) > 0:
            template = validate_and_normalize_vector(vector)
        elif raw_events is not None and len(raw_events) > 0:
            template = extract_features_from_events(raw_events)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Must provide either 'vector', 'samples', or 'raw_events' for enrollment.",
            )

        # Encrypt the template in memory with AES-256-GCM before writing to DB (RNF-01)
        encrypted_data = encrypt_vector(template)

        # Check for existing profile
        existing_profile = (
            db.query(KeystrokeProfile)
            .filter(KeystrokeProfile.user_id == user.id)
            .first()
        )

        if existing_profile:
            existing_profile.vector_encrypted = encrypted_data
            profile = existing_profile
        else:
            profile = KeystrokeProfile(
                user_id=user.id,
                vector_encrypted=encrypted_data,
            )
            db.add(profile)

        db.commit()
        db.refresh(profile)
        return profile

    def verify_keystroke_pattern(
        self,
        db: Session,
        user: User,
        vector: Optional[List[float]] = None,
        raw_events: Optional[List[Dict[str, float]]] = None,
        custom_threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Verifies a keystroke timing sample against the user's stored encrypted template (RF-05).
        Decrypts template in memory and scores similarity via Gradient Boosting + statistical metrics.

        Args:
            db: Database session
            user: Authenticated user attempting verification
            vector: Timing feature vector from client
            raw_events: Raw press/release timing events
            custom_threshold: Optional override for risk-adaptive thresholding

        Returns:
            Dict[str, Any]: {"match": bool, "score": float, "threshold": float}
        """
        profile = (
            db.query(KeystrokeProfile)
            .filter(KeystrokeProfile.user_id == user.id)
            .first()
        )

        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No biometric keystroke profile enrolled for this user.",
            )

        # Process input sample
        if vector is not None and len(vector) > 0:
            sample = validate_and_normalize_vector(vector)
        elif raw_events is not None and len(raw_events) > 0:
            sample = extract_features_from_events(raw_events)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Must provide either 'vector' or 'raw_events' for verification.",
            )

        # Decrypt stored template in memory (AES-256-GCM)
        try:
            template = decrypt_vector(profile.vector_encrypted)
        except Exception as e:
            logger.error(f"Failed to decrypt biometric profile for user {user.id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not decrypt biometric profile.",
            )

        threshold = custom_threshold if custom_threshold is not None else self.optimal_threshold

        # If dimension mismatch, fail verification immediately
        if len(sample) != len(template):
            logger.warning(
                f"Biometric dimension mismatch: template={len(template)}, sample={len(sample)}"
            )
            return {
                "match": False,
                "score": 0.0,
                "threshold": round(threshold, 4),
            }

        # If 31 dimensions and model is loaded, evaluate hybrid score (GB + Statistical)
        if len(sample) == 31 and self.model is not None:
            diff = np.abs(np.array(sample) - np.array(template)).reshape(1, -1)
            gb_prob = float(self.model.predict_proba(diff)[0, 1])
            stat_prob = calculate_statistical_similarity(template, sample)
            # Hybrid weighted score: 70% ML Classifier, 30% Statistical normalized distance
            score = 0.70 * gb_prob + 0.30 * stat_prob
        else:
            # General phrase length or fallback: statistical normalized similarity
            score = calculate_statistical_similarity(template, sample)

        match = bool(score >= threshold)
        return {
            "match": match,
            "score": round(float(score), 4),
            "threshold": round(float(threshold), 4),
        }


# Singleton service instance
biometric_service = BiometricService()
