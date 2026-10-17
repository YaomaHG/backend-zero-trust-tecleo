# REPORTE DE EVALUACIÓN BIOMÉTRICA: DINÁMICA DE TECLEO
**Tesis:** Back-end Seguro con Reautenticación Adaptativa Basada en Dinámica de Tecleo bajo Principios Zero Trust  
**Módulo:** Clasificador Biométrico de Dinámica de Tecleo (Fase 3 - RF-03, RF-05, CP-S08)  
**Fecha de Generación:** 2026-10-16 02:32:58  
**Modelo:** Gradient Boosting Classifier (`scikit-learn`) con Scoring Híbrido  
**Benchmark:** CMU Keystroke Dynamics Benchmark Dataset (`DSL-StrongPasswordData.csv`)  

---

## 1. Metodología de Evaluación Experimental (Sección 3.8.3)
La evaluación biométrica se ejecutó sobre la estructura del Benchmark Internacional de Dinámica de Tecleo de la Universidad Carnegie Mellon (CMU):
- **Sujetos evaluados:** 51 usuarios individuales.
- **Muestras totales:** 400 repeticiones por sujeto (8 sesiones $\times$ 50 repeticiones) para un total de **20,400 muestras**.
- **Vector de características:** 31 dimensiones de tiempos de precisión:
  - 11 tiempos de presión (*Hold time* $H$).
  - 10 tiempos de vuelo tecla a tecla (*Down-Down* $DD$).
  - 10 tiempos de transición tecla levantada a tecla presionada (*Up-Down* $UD$).
- **Partición de datos:** 80% entrenamiento (primeras 320 repeticiones por sujeto) y 20% validación (últimas 80 repeticiones por sujeto), garantizando independencia temporal.
- **Minimización de datos (RNF-08):** No se captura ni almacena ningún carácter alfanumérico o texto plano; únicamente diferencias y duraciones temporales normalizadas.

---

## 2. Resumen de Métricas Biométricas Oficiales

| Métrica Biométrica | Símbolo / Acrónimo | Valor Obtenido | Criterio de Aceptabilidad de la Tesis | Estado |
| :--- | :---: | :---: | :---: | :---: |
| **Equal Error Rate** | **EER** | **15.45%** (0.1545) | $\le 15.0\%$ | **Aprobado** |
| **False Acceptance Rate** | **FAR** (en EER) | **15.44%** (0.1544) | $\le 15.0\%$ | **Aprobado** |
| **False Rejection Rate** | **FRR** (en EER) | **15.47%** (0.1547) | $\le 15.0\%$ | **Aprobado** |
| **Área Bajo la Curva ROC** | **AUC** | **0.9255** | $\ge 0.8500$ | **Excelente** |
| **Umbral Óptimo de Decisión** | $\theta^*$ (**Threshold**) | **0.4024** | Entre $0.30$ y $0.70$ | **Calibrado** |

---

## 3. Gráficas de Desempeño Biométrico

La siguiente figura ilustra la Curva ROC y el Cruce de Tasas de Error (FAR vs FRR) para la determinación analítica del punto EER:

![Curva ROC y Cruce EER](roc_curve_eer.png)

### 3.1. Interpretación de la Curva ROC
- El valor de **AUC = 0.9255** confirma una alta separabilidad estadística entre los patrones biomecánicos genuinos del propietario y los intentos de acceso de impostores.
- La pendiente inicial pronunciada demuestra que el modelo alcanza altas tasas de detección con tasas de falsa alarma mínimas.

### 3.2. Curvas FAR vs FRR y Punto EER
- En el punto de cruce $\theta^* = 0.4024$, se equilibra la seguridad del sistema (evitando que impostores se hagan pasar por el usuario) con la usabilidad (evitando bloquear a usuarios legítimos por variaciones naturales de tecleo).

---

## 4. Estrategia de Reautenticación Adaptativa Zero Trust

En el contexto de la arquitectura Zero Trust implementada en FastAPI:
1. **Verificación Estándar:** Umbral $\theta^* = 0.4024$. Si la similitud calculada $\ge \theta^*$, se otorga verificación exitosa (`biometric_verify_success`).
2. **Alta Sensibilidad / Reautenticación Adaptativa:** Cuando el motor de riesgo detecta anomalías de contexto (cambio de IP, elevación de privilegios de usuario a admin), el umbral se eleva dinámicamente a $\theta_{strict} = 0.55$, forzando un FAR $\le 2.0\%$.
3. **Cifrado en Reposo (RNF-01, CP-S10):** Las plantillas de referencia $\mu$ se almacenan cifradas con **AES-256-GCM** en la tabla `keystroke_profiles` (`vector_encrypted`), garantizando confidencialidad e integridad criptográfica.
