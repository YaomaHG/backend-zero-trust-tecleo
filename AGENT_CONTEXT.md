# CONTEXTO DEL PROYECTO (TESIS INGENIERÍA DE SOFTWARE)
Proyecto: Back-end seguro con reautenticación adaptativa basada en dinámica de tecleo bajo principios Zero Trust.

## REGLAS ESTRICTAS DE ARQUITECTURA Y STACK
- Lenguaje: Python 3.11 + FastAPI
- Base de datos: PostgreSQL 15 + SQLAlchemy 2.0
- ML Biométrico: scikit-learn (Gradient Boosting Classifier) entrenado con CMU Keystroke Dynamics Benchmark.
- Seguridad: JWT en cookies HttpOnly + SameSite=Strict (PyJWT), contraseñas con bcrypt/Argon2, plantillas biométricas cifradas en reposo con AES-256-GCM (librería `cryptography`).
- Front-end: HTML5, CSS3 y JS Vanilla (captura `keydown` y `keyup` con `performance.now()`).

## ESTRUCTURA DE DIRECTORIOS OBLIGATORIA
- app/main.py
- app/database.py
- app/core/ (config.py, security.py, crypto.py)
- app/models/ (SQLAlchemy: users, roles, user_roles, keystroke_profiles, sessions, audit_log, reauth_events)
- app/schemas/ (Pydantic v2)
- app/auth/
- app/biometric/
- app/reauth/
- app/authorization/
- app/audit/
- tests/ (pytest + httpx para casos CP-S01 a CP-S10)

## REGLAS DE CODIFICACIÓN PARA EL AGENTE
1. Nunca guardes vectores biométricos en texto plano en PostgreSQL. Usa siempre `vector_encrypted` (BYTEA) con AES-256-GCM.
2. Nunca almacenes las teclas presionadas (texto), solo tiempos de vuelo y presión (minimización de datos RNF-08).
3. Cada vez que crees un endpoint o módulo, escribe su prueba correspondiente en `tests/` y ejecútala con `pytest`.
4. PROHIBIDO EJECUTAR DOCKER: No ejecutes comandos `docker` ni `docker-compose` en la terminal porque el disco local tiene poco espacio. Ejecuta todas las verificaciones únicamente con `.venv\Scripts\pytest` usando SQLite en memoria.