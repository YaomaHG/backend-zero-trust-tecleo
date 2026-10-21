"""
Módulo de Extracción y Normalización de Características Biomecánicas (app/biometric/features.py).
Convierte eventos temporales de pulsación de teclado en vectores numéricos continuos.

Requerimientos y Casos de Prueba asociados:
- RNF-08 (Minimización de Datos y Privacidad):
  NUNCA se captura, procesa ni almacena el texto, caracteres o letras escritas.
  Solo se extraen marcas de tiempo relativas (segundos) entre eventos físicos.
- RF-03: Extracción de vectores biométricos y cálculo de plantillas promedio de enrolamiento.
- RF-05 / CP-S08: Normalización de características para verificación y tolerancia biomecánica.
"""

from typing import Any, Dict, List, Optional
import math

# =============================================================================
# DEFINICIÓN DEL VECTOR DE 31 DIMENSIONES (BENCHMARK INTERNACIONAL CMU)
# Para la frase fija obligatoria ".tie5Roanl" (10 caracteres + tecla Enter = 11 teclas):
# - 11 Tiempos de Retención (Hold time 'H'): H.period, H.t, H.i, ..., H.Return
# - 10 Tiempos de Vuelo Tecla a Tecla (Down-Down 'DD'): DD.period.t, DD.t.i, ..., DD.l.Return
# - 10 Tiempos de Transición (Up-Down 'UD'): UD.period.t, UD.t.i, ..., UD.l.Return
# Total exacto: 11 + 10 + 10 = 31 dimensiones flotantes.
# =============================================================================
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
    Extrae los tiempos biométricos a partir de marcas temporales de pulsación (down) y liberación (up).

    Fórmulas Biomecánicas Implementadas de forma muy sencilla:
    ---------------------------------------------------------
    1. Tiempo de Retención / Presión (Hold Time - H):
       Mide cuánto tiempo permanece aplastada físicamente una tecla.
       Fórmula: H_i = t_release(i) - t_press(i)

    2. Tiempo de Vuelo Tecla a Tecla (Down-Down - DD):
       Intervalo entre el momento en que se presiona una tecla y se presiona la siguiente.
       Fórmula: DD_i = t_press(i+1) - t_press(i)

    3. Tiempo de Transición / Despegue (Up-Down - UD):
       Tiempo transcurrido desde que se suelta una tecla hasta que se presiona la siguiente.
       Fórmula: UD_i = t_press(i+1) - t_release(i)
       (Nota: Puede ser negativo si el usuario escribe muy rápido con solapamiento de dedos).

    Minimización de Datos (RNF-08):
    El diccionario de entrada sólo contiene claves numéricas temporales {'down', 'up'}.
    No existen variables ni metadatos con el valor textual de las teclas.

    Args:
        raw_events: Lista de diccionarios con marcas 'down' y 'up' (en ms o segundos).

    Returns:
        List[float]: Vector numérico normalizado en segundos [H0, DD01, UD01, H1, DD12, ...].
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

    # Detectar si vienen en milisegundos (ej. performance.now() > 10.0) y convertir a segundos
    scale = 0.001 if any(t > 10.0 for t in (press_times + release_times)) else 1.0

    features: List[float] = []
    n = len(raw_events)

    for i in range(n):
        # Fórmula Hold (H): liberación - presión
        hold_time = max(0.01, (release_times[i] - press_times[i]) * scale)
        features.append(round(hold_time, 6))

        if i < n - 1:
            # Fórmula Down-Down (DD): presión siguiente - presión actual
            dd_time = max(0.01, (press_times[i + 1] - press_times[i]) * scale)
            features.append(round(dd_time, 6))

            # Fórmula Up-Down (UD): presión siguiente - liberación actual
            ud_time = (press_times[i + 1] - release_times[i]) * scale
            features.append(round(ud_time, 6))

    return features


def validate_and_normalize_vector(vector: List[float]) -> List[float]:
    """
    Valida y sanitiza un vector numérico asegurando que todos los valores sean flotantes
    reales finitos (sin NaN ni Inf) y normalizados en la unidad estándar de segundos.
    """
    if not isinstance(vector, list) or len(vector) == 0:
        raise ValueError("Feature vector must be a non-empty list of numbers.")

    cleaned: List[float] = []
    # Si los valores están en milisegundos (> 10.0), convertir a segundos
    scale = 0.001 if any(float(x) > 10.0 for x in vector) else 1.0

    for x in vector:
        val = float(x) * scale
        if math.isnan(val) or math.isinf(val):
            raise ValueError("Vector contains invalid NaN or Infinity values.")
        cleaned.append(round(val, 6))

    return cleaned


def compute_template_from_samples(samples: List[List[float]]) -> List[float]:
    """
    Calcula la plantilla biométrica de referencia promedio del usuario durante el enrolamiento (RF-03).

    Se solicitan entre 3 y 5 repeticiones de la frase para capturar la varianza natural del usuario.
    Se calcula la media aritmética componente a componente:
    T_j = (1 / K) * sum_{k=1}^K S_{k, j}

    Args:
        samples: Lista de vectores de características de las distintas repeticiones.

    Returns:
        List[float]: Vector plantilla promedio de referencia.
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
    Calcula la Distancia Manhattan Relativa Normalizada entre una muestra y la plantilla.

    d = (1 / D) * sum_{i=1}^D ( |sample_i - template_i| / (|template_i| + 0.08) )
    El término 0.08 actúa como factor de suavizado numérico contra divisiones por cero.
    """
    if len(template) != len(sample):
        raise ValueError(
            f"Dimension mismatch: template has {len(template)} dimensions, sample has {len(sample)}."
        )

    dim = len(template)
    total_dist = 0.0
    for t_val, s_val in zip(template, sample):
        diff = abs(s_val - t_val)
        norm_factor = abs(t_val) + 0.08
        total_dist += diff / norm_factor

    return total_dist / dim


def calculate_statistical_similarity(template: List[float], sample: List[float]) -> float:
    """
    Mapea la distancia estadística a un índice de similitud acotado en el intervalo [0.0, 1.0].

    Utiliza decaimiento exponencial: Sim = exp(-2.2 * distancia)
    - Distancia cercana a 0.0 produce similitud cercana a 1.0 (patrón idéntico o muy afín).
    - Distancias grandes producen similitud tendiente a 0.0 (impostor o tecleo errático).
    """
    dist = calculate_statistical_distance(template, sample)
    similarity = math.exp(-2.2 * dist)
    return max(0.0, min(1.0, float(similarity)))

