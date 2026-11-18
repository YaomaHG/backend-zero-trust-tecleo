# Back-end Seguro con Reautenticación Adaptativa Basada en Dinámica de Tecleo bajo Principios Zero Trust

[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com/)
[![Zero Trust](https://img.shields.io/badge/Security-Zero%20Trust%20Architecture-red.svg)](#)
[![Tests Passing](https://img.shields.io/badge/pytest-33%20passed-brightgreen.svg)](#)
[![Biometrics](https://img.shields.io/badge/ML-Gradient%20Boosting%20(CMU)-orange.svg)](#)

Proyecto de Titulación de Ingeniería de Software con el asesor de tesis **D.Ed. Armando Román**. Desarrollado por **Omar Hernández** y **Salvador Garibay**.

---

## 🎯 Objetivo del Sistema

Implementar un back-end con arquitectura **Zero Trust** ("Nunca confiar, siempre verificar") que evalúa de forma continua el riesgo de la sesión y exige **reautenticación biométrica pasiva/activa basada en la cadencia de tecleo (Keystroke Dynamics)** ante anomalías contextuales (como cambios repentinos de dirección IP o ejecución de operaciones corporativas sensibles).

---

## 🚀 Guía Rápida de Instalación y Ejecución en Windows

Sigue estos pasos en **PowerShell** o **Símbolo del sistema (CMD)** para levantar el proyecto en tu entorno local.

### 1. Clonar el Repositorio y Acceder a la Carpeta

```powershell
git clone https://github.com/YaomaHG/backend-zero-trust-tecleo.git
cd backend-zero-trust-tecleo
```

---

### 2. Crear y Activar el Entorno Virtual de Python (3.11)

```powershell
# Crear el entorno virtual en la carpeta .venv
python -m venv .venv

# Activar en PowerShell:
.\.venv\Scripts\Activate.ps1

# (Si PowerShell muestra error de permisos de ejecución de scripts, ejecuta una sola vez):
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```

*Si usas CMD clásico en lugar de PowerShell:*
```cmd
.\.venv\Scripts\activate.bat
```

---

### 3. Instalar Dependencias del Proyecto

```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

---

### 4. Configurar las Variables de Entorno (`.env`)

Copia la plantilla preconfigurada `.env.example` hacia `.env`:

```powershell
# En PowerShell:
Copy-Item .env.example .env

# O en CMD:
copy .env.example .env
```

#### Modo Base de Datos:
El archivo `.env` ya viene configurado con llaves maestras seguras para pruebas. Puedes elegir entre dos modos:

* **Modo A: SQLite Local Ligero (Recomendado para pruebas rápidas sin instalar Postgres)**:  
  En tu `.env`, asegura que `DATABASE_URL` apunte a SQLite:
  ```env
  DATABASE_URL=sqlite:///./zerotrust_local.db
  ```

* **Modo B: PostgreSQL (Producción / Docker Compose)**:  
  ```env
  POSTGRES_USER=postgres
  POSTGRES_PASSWORD=postgres
  POSTGRES_HOST=localhost
  POSTGRES_PORT=5432
  POSTGRES_DB=zero_trust_db
  DATABASE_URL=postgresql://postgres:postgres@localhost:5432/zero_trust_db
  ```

> **Llaves Criptográficas incluidas en `.env`:**
> - `JWT_SECRET_KEY`: Llave de 256 bits para firma y verificación de tokens JWT.
> - `AES_MASTER_KEY`: Llave hexadecimal de 64 caracteres (32 bytes) para cifrado AES-256-GCM de plantillas biométricas en reposo.

---

### 5. Ejecutar la Batería de Pruebas Automatizadas (33 Tests)

El conjunto de pruebas utiliza SQLite en memoria (`sqlite:///:memory:`), por lo que **no requiere tener levantado Docker ni PostgreSQL**. Ejecuta:

```powershell
pytest -v
```

**Resultado esperado:**
```text
tests/test_db_models.py ........ [ 21%]
tests/test_security_phase2.py ........ [ 45%]
tests/test_biometric_phase3.py ........ [ 69%]
tests/test_reauth_phase4.py ...... [ 87%]
tests/test_frontend_phase5.py .... [100%]
============================== 33 passed in ~2.8s ==============================
```

Los 33 tests validan integralmente:
- Modelos relacionales e integridad referencial.
- Seguridad de sesiones y cookies HttpOnly.
- Casos de prueba de seguridad **CP-S01 a CP-S10** (anti-replay, inyecciones SQL, fuerza bruta, bloqueo de cuentas, cifrado de plantillas).
- Clasificador biométrico entrenado con el Benchmark CMU.
- Flujo SPA extremo a extremo (E2E).

---

### 6. Iniciar el Servidor de Desarrollo

#### Opción A: Modo Local Ligero con SQLite (Recomendado)

Una vez configurado `DATABASE_URL=sqlite:///./zerotrust_local.db` en tu `.env`, ejecuta:

```powershell
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Al iniciar por primera vez, el sistema creará automáticamente las tablas y sembrará el usuario administrador por defecto.

Abre tu navegador en:
- **Aplicación Web (SPA Zero Trust):** [http://localhost:8000](http://localhost:8000)
- **Documentación Interactiva Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **Documentación ReDoc:** [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Verificación de Salud (Healthcheck):** [http://localhost:8000/health](http://localhost:8000/health)

---

#### Opción B: Ejecución con Docker Compose (PostgreSQL + FastAPI)

Si cuentas con Docker Desktop instalado y deseas levantar el entorno de contenedores:

```powershell
docker-compose up --build -d
```

Para consultar los logs del contenedor:
```powershell
docker-compose logs -f backend
```

Para detener los contenedores:
```powershell
docker-compose down
```

---

## 🔑 Credenciales de Demostración

El sistema se inicializa con una cuenta de Administrador lista para pruebas de defensa y demostraciones en vivo:

| Campo | Valor |
| :--- | :--- |
| **Usuario** | `admin` |
| **Contraseña** | `AdminZeroTrust2026!` |
| **Rol asignado** | `admin`, `user` |
| **Privilegios** | Registro de auditoría inmutable, gestión de usuarios, asignación de roles y ejecución de operaciones corporativas sensibles. |

> 💡 **Nota para la demo:** También puedes usar el botón *"Registrar Usuario"* en la interfaz web para crear un usuario de prueba (ej. `salvador`), enrolar tu propia dinámica de tecleo tecleando la frase objetivo obligatoria `.tie5Roanl` 3 veces, y verificar en vivo cómo reacciona el escudo ante un intento de acceso con ritmo simulado de impostor.

---

## 🏛️ Estructura del Proyecto

```text
backend-zero-trust-tecleo/
├── app/
│   ├── main.py                     # Punto de entrada FastAPI, montaje de routers y SPA
│   ├── database.py                 # Conexión SQLAlchemy y generador de sesiones
│   ├── core/                       # Núcleo de seguridad criptográfica y configuración
│   │   ├── config.py               # Settings de Pydantic validados desde .env
│   │   ├── crypto.py               # Cifrado/Descifrado AES-256-GCM para vectores biométricos
│   │   ├── security.py             # Hashing bcrypt y generación/validación de tokens JWT
│   │   └── rate_limiter.py         # Limitador de tasa por IP (5 req/min, RNF-03)
│   ├── models/                     # 7 Tablas relacionales SQLAlchemy
│   ├── schemas/                    # Contratos de datos y validaciones con Pydantic v2
│   ├── auth/                       # Registro, Login (Cookies HttpOnly), Logout y /me
│   ├── biometric/                  # Extracción de características (31-D) y clasificador ML
│   ├── reauth/                     # Motor de riesgo Zero Trust y Anti-Replay con nonces
│   ├── authorization/              # Control de acceso basado en roles (RBAC) y panel admin
│   ├── audit/                      # Trazabilidad y bitácora de auditoría inmutable
│   └── static/                     # Front-end SPA Vanilla (HTML5, CSS3 neon, JS)
│       ├── css/styles.css          # Estilos Cyber-Shield en modo oscuro
│       ├── js/keystroke.js         # Captura de timing con window.performance.now()
│       └── js/app.js               # Controlador SPA y modal de reautenticación
├── data/                           # Dataset CMU Benchmark (20,400 muestras)
├── docs/                           # Reporte biométrico oficial y Guía de Defensa
│   ├── BIOMETRIC_EVALUATION_REPORT.md  # Reporte de métricas biométricas
│   ├── GUIA_DEFENSA_ASESOR.md          # Manual de defensa para el Dr. Román
│   └── roc_curve_eer.png               # Curva ROC y cruce FAR vs FRR
├── ml_models/
│   └── keystroke_gb_model.pkl      # Modelo entrenado Gradient Boosting exportado
├── scripts/
│   └── train_cmu_model.py          # Script de entrenamiento y evaluación experimental
├── tests/                          # Suite de 33 pruebas unitarias y de integración
├── .env.example                    # Plantilla de variables de entorno
├── docker-compose.yml              # Orquestación de contenedores (Postgres + Backend)
├── Dockerfile                      # Imagen Docker optimizada en Python 3.11-slim
└── requirements.txt                # Dependencias fijadas del proyecto
```

---

## 🛡️ Matriz de Casos de Prueba de Seguridad (CP-S01 a CP-S10)

| Código | Descripción del Caso de Prueba | Resultado Obtenido | Archivo de Prueba |
| :---: | :--- | :---: | :--- |
| **CP-S01** | Petición a endpoint protegido sin token | `401 Unauthorized` | `tests/test_security_phase2.py` |
| **CP-S02** | Acceso con token JWT expirado | `401 Unauthorized` | `tests/test_security_phase2.py` |
| **CP-S03** | Token con firma criptográfica alterada | `401 Unauthorized` | `tests/test_security_phase2.py` |
| **CP-S04** | Ataque de repetición (Replay) con Nonce duplicado | `400 Bad Request` + Log Auditoría | `tests/test_reauth_phase4.py` |
| **CP-S05** | Escalación de privilegios RBAC (Usuario accede a Admin) | `403 Forbidden` + Evento `access_denied` | `tests/test_security_phase2.py` |
| **CP-S06** | Bloqueo por fuerza bruta tras 10 fallos (15 minutos) | `403 Forbidden` + Bloqueo de cuenta | `tests/test_security_phase2.py` |
| **CP-S07** | Detección de cambio súbito de dirección IP | `403 Forbidden` (`reauth_required=True`) | `tests/test_reauth_phase4.py` |
| **CP-S08** | Rechazo de patrón impostor de tecleo y revocación de sesión | `403 Forbidden` + Revocación DB | `tests/test_reauth_phase4.py` |
| **CP-S09** | Inyección SQL en login y registro neutralizada por ORM | `401/400` Seguro (Sin fugas ni alteración) | `tests/test_reauth_phase4.py` |
| **CP-S10** | Cifrado en reposo AES-256-GCM y detección de alteración de 1 bit | `InvalidTag` detectado en descifrado | `tests/test_security_phase2.py` |

---

## 📈 Métricas Biométricas del Modelo

Evaluado sobre el Benchmark Internacional de Dinámica de Tecleo de la **Carnegie Mellon University (CMU)** con 51 sujetos y 20,400 muestras:

- **Área Bajo la Curva (AUC-ROC):** `0.9255` (Excelente separabilidad estadística)
- **Tasa de Error Equitativo (EER):** `15.45%` ($\le 15.0\%$ objetivo)
- **Umbral Óptimo de Decisión ($\theta^*$):** `0.4024`
- **Tasa de Falsa Aceptación (FAR):** `15.44%`
- **Tasa de Falso Rechazo (FRR):** `15.47%`

Para más detalles, consulta [docs/BIOMETRIC_EVALUATION_REPORT.md](docs/BIOMETRIC_EVALUATION_REPORT.md).
