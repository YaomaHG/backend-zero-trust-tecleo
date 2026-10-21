"""
Servicio Biométrico de Dinámica de Tecleo (app/biometric/service.py).
Implementa el enrolamiento cifrado en reposo (AES-256-GCM) y la verificación
de identidad biomecánica en tiempo real mediante un clasificador Gradient Boosting
entrenado con el Benchmark de Carnegie Mellon (CMU) combinado con scoring híbrido.

Requerimientos y Casos de Prueba asociados:
- RF-03 / RNF-01: Enrolamiento de perfiles y almacenamiento cifrado en PostgreSQL.
- RF-05 / CP-S08: Verificación biométrica continua, tolerancia a la varianza humana
  en vivo y detección de ataques de impostores.
- RNF-08: Procesamiento seguro sin exposición de teclas en texto plano.
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
    Servicio central de biometría conductual de tecleo (Keystroke Dynamics).

    Responsabilidades:
    1. Enrolamiento seguro: Cifra la plantilla de referencia con AES-256-GCM antes de persistir.
    2. Descifrado en memoria RAM volátil para evitar fugas de datos en disco.
    3. Inferencia probabilística con ensemble Gradient Boosting de scikit-learn.
    4. Scoring Híbrido Multicriterio con tolerancia humana a la fatiga y velocidad de tecleo.
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
        """
        Carga el artefacto serializado del modelo Gradient Boosting entrenado.
        Extrae el clasificador, el umbral óptimo calibrado en el EER (theta* = 0.4024),
        el EER alcanzado (15.45%) y el AUC-ROC (0.9255).
        """
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
        Enrola o actualiza la plantilla biométrica del usuario (RF-03).

        Seguridad (RNF-01):
        La plantilla calculada (vector de 31 floats) se cifra en memoria con AES-256-GCM
        mediante `encrypt_vector(template)` y se almacena en formato BYTEA en la tabla
        `keystroke_profiles.vector_encrypted`. Nunca se escribe en texto plano.

        Args:
            db: Sesión activa de base de datos.
            user: Usuario autenticado.
            vector: Vector único opcional.
            samples: Múltiples repeticiones (se promedian con compute_template_from_samples).
            raw_events: Eventos down/up de teclado sin procesar.

        Returns:
            KeystrokeProfile: Registro de base de datos con el criptograma binario.
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

        # Cifrado en reposo con AES-256-GCM (RNF-01)
        encrypted_data = encrypt_vector(template)

        # Buscar si ya existe un perfil para actualizarlo o crear uno nuevo
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
        Verifica una muestra biomecánica contra la plantilla cifrada del usuario (RF-05, CP-S08).

        ¿Cómo opera la Inferencia y la Fórmula Híbrida en CP-S08?
        ---------------------------------------------------------
        1. Descifrado en Memoria (AES-256-GCM):
           Recupera `vector_encrypted` de la BD y lo descifra en RAM con `decrypt_vector`.
           Si el tag GCM fue manipulado, se rechaza la operación (CP-S10).

        2. Vector de Diferencias Absolutas (Insumo de Gradient Boosting):
           El clasificador fue entrenado para recibir la distancia absoluta componente a
           componente entre la muestra candidata y la plantilla de referencia:
           Delta = |X_muestra - X_plantilla|

        3. Tolerancia a la Varianza Humana en Vivo (Live Human Tempo Tolerance):
           Un usuario legítimo puede escribir más rápido o más lento según la hora del día,
           el cansancio o el café (ratio de velocidad entre 0.70x y 1.38x).
           - Se calcula el ratio de velocidad: `speed_ratio = mean(muestra) / mean(plantilla)`.
           - Se evalúa la correlación de ritmo de Pearson (`corr = np.corrcoef(...)`).
           - Si la cadencia relativa es humana (0.70 <= speed_ratio <= 1.38), se escala
             temporalmente la muestra (`aligned_sample = sample * (mean_t / mean_s)`)
             para alinear el compás musical de los dedos y evitar falsos rechazos injustos.

        4. Fórmula Híbrida de Decisión:
           - En usuarios genuinos con correlación rítmica (corr > 0.50):
             Score = 0.50 * Clasificador_GB + 0.35 * Similitud_Estadística + 0.15 * Correlación
           - En impostores o cadencias no humanas (ataques de replay o mecanografía desfasada):
             Score = (0.70 * Clasificador_GB + 0.30 * Similitud_Estadística) * Penalización
             (Donde la penalización es 0.50 si la velocidad diverge más del doble o la mitad).

        5. Umbral de Decisión:
           El puntaje final se compara con el umbral calibrado (theta* = 0.4024).
           Si Score >= 0.4024 -> match = True (Usuario legítimo reconocido).
           Si Score < 0.4024 -> match = False (Impostor o usuario no verificado).

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

        # Procesar vector o eventos de entrada
        if vector is not None and len(vector) > 0:
            sample = validate_and_normalize_vector(vector)
        elif raw_events is not None and len(raw_events) > 0:
            sample = extract_features_from_events(raw_events)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Must provide either 'vector' or 'raw_events' for verification.",
            )

        # Descifrado seguro en memoria RAM volátil mediante AES-256-GCM (RNF-01, CP-S10)
        try:
            template = decrypt_vector(profile.vector_encrypted)
        except Exception as e:
            logger.error(f"Failed to decrypt biometric profile for user {user.id}: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Could not decrypt biometric profile.",
            )

        threshold = custom_threshold if custom_threshold is not None else self.optimal_threshold

        # Validación de dimensionalidad: Si difiere, rechazar de inmediato
        if len(sample) != len(template):
            logger.warning(
                f"Biometric dimension mismatch: template={len(template)}, sample={len(sample)}"
            )
            return {
                "match": False,
                "score": 0.0,
                "threshold": round(threshold, 4),
            }

        # Inferencia con Gradient Boosting y scoring híbrido si es el vector estándar de 31-D
        if len(sample) == 31 and self.model is not None:
            sample_arr = np.array(sample, dtype=float)
            template_arr = np.array(template, dtype=float)

            # Cálculo de velocidad de tecleo relativa y correlación de perfil rítmico
            mean_t = float(np.mean(template_arr))
            mean_s = float(np.mean(sample_arr))
            speed_ratio = mean_s / (mean_t + 1e-6)

            std_s = float(np.std(sample_arr))
            std_t = float(np.std(template_arr))
            if std_s > 1e-6 and std_t > 1e-6:
                corr = float(np.corrcoef(template_arr, sample_arr)[0, 1])
            else:
                corr = 0.0

            # Tolerancia biológica humana: Variación natural de velocidad (0.70x a 1.38x)
            if 0.70 <= speed_ratio <= 1.38:
                tempo_scale = mean_t / mean_s
                aligned_sample = list(sample_arr * tempo_scale)
            else:
                aligned_sample = sample

            # Vector de diferencias absolutas Delta = |X_candidato - X_plantilla|
            diff_raw = np.abs(sample_arr - template_arr).reshape(1, -1)
            diff_aligned = np.abs(np.array(aligned_sample) - template_arr).reshape(1, -1)

            # Inferencia de probabilidades con el clasificador Gradient Boosting
            gb_raw = float(self.model.predict_proba(diff_raw)[0, 1])
            gb_aligned = float(self.model.predict_proba(diff_aligned)[0, 1])

            # Similitud estadística por distancia Manhattan normalizada
            stat_raw = calculate_statistical_similarity(template, sample)
            stat_aligned = calculate_statistical_similarity(template, aligned_sample)

            if 0.70 <= speed_ratio <= 1.38 and corr > 0.50:
                # Caso genuino en vivo: Fusión adaptativa compensando variabilidad humana
                gb_score = max(gb_raw, gb_aligned * 0.90)
                stat_score = max(stat_raw, stat_aligned * 0.90)
                score = 0.50 * gb_score + 0.35 * stat_score + 0.15 * max(0.0, corr)
            else:
                # Caso impostor o divergencia extrema de velocidad (>= 1.9x o <= 0.5x)
                penalty = 1.0
                if speed_ratio >= 1.90 or speed_ratio <= 0.50:
                    penalty = 0.50
                # Fórmula estándar híbrida: 70% Clasificador Gradient Boosting + 30% Estadística
                score = (0.70 * gb_raw + 0.30 * stat_raw) * penalty
        else:
            # Fallback o frases de longitud arbitraria: similitud estadística normalizada
            score = calculate_statistical_similarity(template, sample)

        match = bool(score >= threshold)
        return {
            "match": match,
            "score": round(float(score), 4),
            "threshold": round(float(threshold), 4),
        }


# Instancia singleton del servicio biométrico
biometric_service = BiometricService()

