"""
Keystroke Dynamics Feature Extraction & Normalization
Zero Trust Continuous Biometric Authentication (RF-03, RF-05, RNF-08)

Strictly enforces RNF-08 (Data Minimization & Privacy):
- No characters, letters, key codes, or text are ever processed or stored.
- Only physical press durations (Hold times) and transition intervals (Flight times) are computed.
"""

from typing import Any, Dict, List, Optional
import math

FEATURE_COLUMNS: List[str] = [
    "H.period", "DD.period.t", "UD.period.t",
    "H.t", "DD.t.i", "UD.t.i",
    "H.i", "DD.i.e", "UD.i.e",
    "H.e", "DD.e.five", "UD.e.five",
    "H.five", "DD.five.Shift.r", "UD.five.Shift.r",
    "H.Shift.r", "DD.Shift.r.o", "UD.Shift.r.o",
    "H.o", "DD.o.a", "UD.o.a",
    "H.a", "DD.a.n", "UD.a.n",
    "H.n", "DD.n.l", "UD.n.l",
    "H.l", "DD.l.Return", "UD.l.Return",
    "H.Return"
]


def extract_features_from_events(raw_events: List[Dict[str, float]]) -> List[float]:
    """
    Extracts hold and flight timing features from raw keypress events without capturing characters.

    Args:
        raw_events: List of dicts containing only 'down' and 'up' (or 'press_time' and 'release_time') timestamps.

    Returns:
        List[float]: Normalized timing vector in seconds [H0, DD01, UD01, H1, DD12, UD12, ...].
    """
    if not raw_events or len(raw_events) < 2:
        raise ValueError("At least 2 key events are required to extract keystroke dynamics.")

    press_times: List[float] = []
    release_times: List[float] = []

    for ev in raw_events:
        down = ev.get("down", ev.get("press_time"))
        up = ev.get("up", ev.get("release_time"))
        if down is None or up is None:
            raise ValueError("Each event must contain 'down'/'press_time' and 'up'/'release_time'.")
        press_times.append(float(down))
        release_times.append(float(up))

    # Detect if timestamps are in milliseconds (e.g. performance.now()) and convert to seconds
    scale = 0.001 if any(t > 10.0 for t in (press_times + release_times)) else 1.0

    features: List[float] = []
    n = len(raw_events)

    for i in range(n):
        # Hold time H_i = release_i - press_i
        hold_time = max(0.01, (release_times[i] - press_times[i]) * scale)
        features.append(round(hold_time, 6))

        if i < n - 1:
            # Flight time Down-Down: press_{i+1} - press_i
            dd_time = max(0.01, (press_times[i + 1] - press_times[i]) * scale)
            features.append(round(dd_time, 6))

            # Flight time Up-Down: press_{i+1} - release_i
            ud_time = (press_times[i + 1] - release_times[i]) * scale
            features.append(round(ud_time, 6))

    return features


def validate_and_normalize_vector(vector: List[float]) -> List[float]:
    """
    Validates a raw float vector, ensuring non-null, numeric values with reasonable bounds.
    """
    if not isinstance(vector, list) or len(vector) == 0:
        raise ValueError("Feature vector must be a non-empty list of numbers.")

    cleaned: List[float] = []
    # If values are in milliseconds (e.g. > 10.0), convert to seconds
    scale = 0.001 if any(float(x) > 10.0 for x in vector) else 1.0

    for x in vector:
        val = float(x) * scale
        if math.isnan(val) or math.isinf(val):
            raise ValueError("Vector contains invalid NaN or Infinity values.")
        cleaned.append(round(val, 6))

    return cleaned


def compute_template_from_samples(samples: List[List[float]]) -> List[float]:
    """
    Computes a baseline reference template vector by averaging 3 to 5 enrollment samples.

    Args:
        samples: List of feature vectors from multiple repetitions.

    Returns:
        List[float]: The mean reference vector.
    """
    if not samples or not isinstance(samples, list):
        raise ValueError("Samples must be a non-empty list of feature vectors.")

    validated_samples = [validate_and_normalize_vector(s) for s in samples]
    expected_dim = len(validated_samples[0])

    for i, s in enumerate(validated_samples):
        if len(s) != expected_dim:
            raise ValueError(
                f"Sample {i} has dimension {len(s)}, expected {expected_dim}. "
                "All enrollment repetitions must have the same length."
            )

    k = len(validated_samples)
    template = [
        round(sum(sample[dim] for sample in validated_samples) / k, 6)
        for dim in range(expected_dim)
    ]
    return template


def calculate_statistical_distance(template: List[float], sample: List[float]) -> float:
    """
    Calculates normalized Manhattan distance between candidate sample and enrolled template.
    Normalized by template magnitude + epsilon to handle relative variation.
    """
    if len(template) != len(sample):
        raise ValueError(
            f"Dimension mismatch: template has {len(template)} dimensions, sample has {len(sample)}."
        )

    dim = len(template)
    total_dist = 0.0
    for t_val, s_val in zip(template, sample):
        diff = abs(s_val - t_val)
        norm_factor = abs(t_val) + 0.05
        total_dist += diff / norm_factor

    return total_dist / dim


def calculate_statistical_similarity(template: List[float], sample: List[float]) -> float:
    """
    Maps statistical distance to an exponential similarity score in [0.0, 1.0].
    High similarity (near 1.0) indicates genuine user; low similarity indicates an impostor.
    """
    dist = calculate_statistical_distance(template, sample)
    similarity = math.exp(-2.5 * dist)
    return max(0.0, min(1.0, float(similarity)))
