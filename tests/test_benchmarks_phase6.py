"""
Pruebas Automatizadas de Fase 6 y Fase 7 (tests/test_benchmarks_phase6.py).
Valida formalmente los resultados empíricos del benchmarking de tesis:
1. Cumplimiento de latencias operativas frente a RNF-06 (< 2,000 ms).
2. Eficacia comparativa frente a amenazas: Baseline Tradicional vs. Back-end Zero Trust (Objetivo Específico 6).
3. Protocolo experimental con 10 voluntarios y evaluación de usabilidad SUS (Brooke / Bangor).
4. Generación íntegra de artefactos científicos (PNG a 300 DPI, JSON estructurado y Capítulos IV y V de Tesis).
"""

import json
import os
import pytest


METRICS_DIR = os.path.join("docs", "metrics")
BENCHMARK_JSON_PATH = os.path.join(METRICS_DIR, "benchmark_results.json")
FIG_BASELINE_PATH = os.path.join(METRICS_DIR, "baseline_vs_zerotrust_comparison.png")
FIG_VOLUNTEERS_PATH = os.path.join(METRICS_DIR, "volunteers_evaluation_sus.png")
THESIS_DOC_PATH = os.path.join("docs", "CAPITULO_IV_Y_V_TESIS.md")


@pytest.fixture(scope="module")
def benchmark_data():
    """Carga los resultados consolidados de la suite de benchmarking experimental."""
    assert os.path.exists(BENCHMARK_JSON_PATH), f"No se encontró el archivo {BENCHMARK_JSON_PATH}"
    with open(BENCHMARK_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data


# =============================================================================
# 1. PRUEBAS DE RENDIMIENTO Y LATENCIA OPERATIVA (RNF-06 < 2,000 ms)
# =============================================================================
def test_operational_latencies_rnf06_compliance(benchmark_data):
    """
    Verifica que todos los endpoints evaluados cumplen holgadamente con RNF-06 (< 2,000 ms).
    Evalúa promedio, mediana, percentil 95 y máximo sobre 30 repeticiones.
    """
    latencies = benchmark_data["operational_latency"]
    assert latencies["all_compliant"] is True
    assert latencies["rnf06_threshold_ms"] == 2000.0

    endpoints_to_check = ["login", "biometric_enroll", "risk_evaluate", "reauth_verify"]
    for ep in endpoints_to_check:
        ep_data = latencies[ep]
        assert ep_data["rnf06_compliant"] is True
        assert ep_data["samples"] == 30
        assert ep_data["mean_ms"] < 2000.0, f"Media de {ep} supera 2000 ms: {ep_data['mean_ms']} ms"
        assert ep_data["p95_ms"] < 2000.0, f"P95 de {ep} supera 2000 ms: {ep_data['p95_ms']} ms"
        assert ep_data["max_ms"] < 2000.0, f"Máximo de {ep} supera 2000 ms: {ep_data['max_ms']} ms"

    # Verificación específica del endpoint biométrico con ML
    reauth_data = latencies["reauth_verify"]
    assert reauth_data["mean_ms"] < 50.0, f"Inferencia biométrica demasiado lenta: {reauth_data['mean_ms']} ms"
    assert reauth_data["p95_ms"] < 100.0


# =============================================================================
# 2. PRUEBAS DE COMPARATIVA BASELINE VS. ZERO TRUST (OBJETIVO ESPECÍFICO 6)
# =============================================================================
def test_threat_scenarios_comparison_objective6(benchmark_data):
    """
    Verifica que la tasa de bloqueo del Back-end Zero Trust propuesto supera
    significativamente al esquema tradicional (Baseline) en los 5 escenarios evaluados.
    """
    threats = benchmark_data["threat_scenarios_comparison"]
    scenarios = threats["scenarios"]
    summary = threats["summary"]

    assert len(scenarios) == 5

    # El esquema tradicional sucumbe ante todos los vectores posteriores al login
    assert summary["baseline_global_blocked_pct"] == 0.0

    # El back-end propuesto alcanza una tasa global de bloqueo superior al 90%
    assert summary["zerotrust_global_blocked_pct"] >= 90.0, (
        f"Bloqueo global inferior al 90%: {summary['zerotrust_global_blocked_pct']}%"
    )

    # Validar escenarios específicos
    sc_map = {s["id"]: s for s in scenarios}

    # 1. Phishing / Credential Stuffing mitigado por dinámica de tecleo (> 70%)
    assert sc_map["credential_stuffing_phishing"]["zerotrust_blocked_pct"] >= 70.0
    assert sc_map["credential_stuffing_phishing"]["baseline_blocked_pct"] == 0.0

    # 2. Robo de token / IP Change mitigado al 100% (CP-S07)
    assert sc_map["session_hijacking_ip_change"]["zerotrust_blocked_pct"] == 100.0

    # 3. Operación sensible en sesión desatendida mitigada al 100% (RF-04)
    assert sc_map["unattended_sensitive_operation"]["zerotrust_blocked_pct"] == 100.0

    # 4. Ataque de Replay mitigado al 100% (CP-S04)
    assert sc_map["replay_attack"]["zerotrust_blocked_pct"] == 100.0

    # 5. Fuerza bruta mitigada al 100% por bloqueo temporal en BD (CP-S06)
    assert sc_map["brute_force_attack"]["zerotrust_blocked_pct"] == 100.0


# =============================================================================
# 3. PRUEBAS DEL PROTOCOLO DE 10 VOLUNTARIOS Y USABILIDAD SUS
# =============================================================================
def test_volunteers_protocol_and_sus_score(benchmark_data):
    """
    Verifica que el protocolo experimental de 10 participantes voluntarios y
    la evaluación System Usability Scale (SUS) cumplan los estándares de la tesis.
    """
    protocol = benchmark_data["volunteers_protocol"]
    volunteers = protocol["volunteers"]
    global_metrics = protocol["global_metrics"]
    sus = protocol["sus_evaluation"]

    # 10 voluntarios evaluados
    assert len(volunteers) == 10
    assert global_metrics["total_volunteers"] == 10
    assert global_metrics["total_legitimate_attempts"] == 100
    assert global_metrics["total_impostor_attempts"] == 50

    # Métricas globales de biometría conductual
    assert global_metrics["tar_pct"] >= 80.0, f"TAR insuficiente: {global_metrics['tar_pct']}%"
    assert global_metrics["frr_pct"] <= 20.0, f"FRR excesivo: {global_metrics['frr_pct']}%"
    assert global_metrics["trr_pct"] >= 60.0, f"TRR insuficiente: {global_metrics['trr_pct']}%"
    assert global_metrics["mean_verify_latency_ms"] < 40.0

    # Verificación de la evaluación psicométrica SUS
    assert sus["baseline_threshold"] == 68.0
    assert sus["mean_score"] >= 68.0, f"Puntuación SUS inferior a la línea base: {sus['mean_score']}"
    assert sus["mean_score"] >= 80.0, f"Puntuación SUS no alcanza Grado A: {sus['mean_score']}"
    assert sus["grade"] == "A"
    assert sus["adjective"] == "Excelente"
    assert len(sus["individual_scores"]) == 10


# =============================================================================
# 4. PRUEBAS DE EXISTENCIA E INTEGRIDAD DE ARTEFACTOS GENERADOS
# =============================================================================
def test_generated_artifacts_existence_and_integrity():
    """
    Verifica que los archivos de métricas, gráficas científicas a 300 DPI y
    el documento maestro de tesis hayan sido generados con tamaño y estructura válidos.
    """
    # 1. Gráfica 1: Comparativa Baseline vs. Zero Trust
    assert os.path.exists(FIG_BASELINE_PATH), f"No existe {FIG_BASELINE_PATH}"
    size_fig1 = os.path.getsize(FIG_BASELINE_PATH)
    assert size_fig1 > 50000, f"Gráfica {FIG_BASELINE_PATH} parece corrupta o vacía ({size_fig1} bytes)"

    # 2. Gráfica 2: Evaluación Voluntarios y SUS
    assert os.path.exists(FIG_VOLUNTEERS_PATH), f"No existe {FIG_VOLUNTEERS_PATH}"
    size_fig2 = os.path.getsize(FIG_VOLUNTEERS_PATH)
    assert size_fig2 > 50000, f"Gráfica {FIG_VOLUNTEERS_PATH} parece corrupta o vacía ({size_fig2} bytes)"

    # 3. Documento maestro de tesis: docs/CAPITULO_IV_Y_V_TESIS.md
    assert os.path.exists(THESIS_DOC_PATH), f"No existe {THESIS_DOC_PATH}"
    size_doc = os.path.getsize(THESIS_DOC_PATH)
    assert size_doc > 15000, f"Documento de tesis incompleto ({size_doc} bytes)"

    with open(THESIS_DOC_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # Validar que contiene todas las secciones obligatorias solicitadas
    required_headings = [
        "4.3. Evaluación de Rendimiento Operativo (RNF-06)",
        "4.4. Análisis Comparativo: Esquema Tradicional (Baseline) vs. Back-end Zero Trust Propuesto",
        "4.5. Discusión de Resultados y Respuesta a las Preguntas de Investigación",
        "CAPÍTULO V. CONCLUSIONES Y TRABAJOS FUTUROS",
        "5.1. Conclusiones Generales",
        "5.2. Contribuciones de la Investigación",
        "5.3. Limitaciones y Trabajos Futuros",
    ]
    for heading in required_headings:
        assert heading in content, f"Falta el encabezado obligatorio: '{heading}' en {THESIS_DOC_PATH}"
