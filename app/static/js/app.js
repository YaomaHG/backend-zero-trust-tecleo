/**
 * Zero Trust Keystroke Shield - Single Page Application Controller
 * Dynamic Trust Engine, Adaptive Reauthentication & Biometric Pipeline (Phase 5)
 */

(function () {
    "use strict";

    // Application Global State
    const state = {
        currentUser: null,
        authToken: null,
        activeSimulatedIp: null, // Spoofed IP via X-Forwarded-For for thesis demonstration
        targetPhrase: ".tie5Roanl",
        enrollmentCapture: null,
        reauthCapture: null,
        reauthPendingAction: null,
        currentNonce: null,
        currentRiskEvent: "sensitive_operation",
        nonceCountdownTimer: null,
    };

    // DOM Element References
    const elements = {
        // Trust and user headers
        trustIndicator: document.getElementById("trust-indicator"),
        trustIndicatorText: document.getElementById("trust-indicator-text"),
        userSessionBar: document.getElementById("user-session-bar"),
        headerUsername: document.getElementById("header-username"),
        headerRoleBadge: document.getElementById("header-role-badge"),
        headerBiometricBadge: document.getElementById("header-biometric-badge"),
        btnLogout: document.getElementById("btn-logout"),

        // Alerts & containers
        globalAlerts: document.getElementById("global-alert-container"),
        viewAuth: document.getElementById("view-auth"),
        authenticatedWorkspace: document.getElementById("authenticated-workspace"),

        // Auth Tabs & Forms
        tabLoginBtn: document.getElementById("tab-login-btn"),
        tabRegisterBtn: document.getElementById("tab-register-btn"),
        formLogin: document.getElementById("form-login"),
        formRegister: document.getElementById("form-register"),
        loginUsername: document.getElementById("login-username"),
        loginPassword: document.getElementById("login-password"),
        regUsername: document.getElementById("reg-username"),
        regEmail: document.getElementById("reg-email"),
        regPassword: document.getElementById("reg-password"),
        btnFillAdmin: document.getElementById("btn-fill-admin"),
        btnFillUser: document.getElementById("btn-fill-user"),

        // Nav tabs
        navBiometricsBtn: document.getElementById("nav-biometrics-btn"),
        navOperationsBtn: document.getElementById("nav-operations-btn"),
        navAdminBtn: document.getElementById("nav-admin-btn"),

        // Sections
        sectionBiometrics: document.getElementById("section-biometrics"),
        sectionOperations: document.getElementById("section-operations"),
        sectionAdmin: document.getElementById("section-admin"),

        // Stats
        statTrustLevel: document.getElementById("stat-trust-level"),
        statTrustDesc: document.getElementById("stat-trust-desc"),
        statCurrentIp: document.getElementById("stat-current-ip"),
        statIpStatus: document.getElementById("stat-ip-status"),
        statBiometricStatus: document.getElementById("stat-biometric-status"),
        statBiometricDims: document.getElementById("stat-biometric-dims"),

        // Biometrics
        displayTargetPhrase: document.getElementById("display-target-phrase"),
        enrollmentStepLabel: document.getElementById("enrollment-step-label"),
        enrollmentPercentLabel: document.getElementById("enrollment-percent-label"),
        enrollmentProgressBar: document.getElementById("enrollment-progress-bar"),
        chipSample1: document.getElementById("chip-sample-1"),
        chipSample2: document.getElementById("chip-sample-2"),
        chipSample3: document.getElementById("chip-sample-3"),
        enrollmentInput: document.getElementById("enrollment-keystroke-input"),
        vectorDimCounter: document.getElementById("vector-dim-counter"),
        enrollmentTelemetry: document.getElementById("enrollment-telemetry"),
        btnSaveEnrollment: document.getElementById("btn-save-enrollment"),
        btnResetEnrollment: document.getElementById("btn-reset-enrollment"),
        btnVerifyPattern: document.getElementById("btn-verify-pattern"),

        // Operations & Simulator
        formSensitiveAction: document.getElementById("form-sensitive-action"),
        opAccount: document.getElementById("op-account"),
        opAmount: document.getElementById("op-amount"),
        opType: document.getElementById("op-type"),
        sensitiveOpResult: document.getElementById("sensitive-op-result"),
        simSpoofedIp: document.getElementById("sim-spoofed-ip"),
        btnToggleSimIp: document.getElementById("btn-toggle-sim-ip"),
        btnResetSimIp: document.getElementById("btn-reset-sim-ip"),
        btnEvalRisk: document.getElementById("btn-eval-risk"),

        // Admin
        adminUsersTbody: document.getElementById("admin-users-tbody"),
        adminAuditTbody: document.getElementById("admin-audit-tbody"),
        btnRefreshAudit: document.getElementById("btn-refresh-audit"),

        // Reauth Modal
        modalReauth: document.getElementById("modal-reauth"),
        reauthCountdown: document.getElementById("reauth-countdown"),
        reauthRiskTitle: document.getElementById("reauth-risk-title"),
        reauthRiskDetail: document.getElementById("reauth-risk-detail"),
        reauthTargetPhrase: document.getElementById("reauth-target-phrase"),
        reauthNonceBadge: document.getElementById("reauth-nonce-badge"),
        reauthInput: document.getElementById("reauth-keystroke-input"),
        reauthStatusResult: document.getElementById("reauth-status-result"),
        btnCancelReauth: document.getElementById("btn-cancel-reauth"),
        btnSubmitReauth: document.getElementById("btn-submit-reauth"),
    };

    /**
     * Shows a banner notification in the UI.
     */
    function showAlert(message, type = "info", autoDismiss = 6000) {
        const alertEl = document.createElement("div");
        alertEl.className = `alert-banner ${type}`;
        alertEl.innerHTML = `<span>${type === "danger" ? "🚨" : type === "warning" ? "⚠️" : type === "success" ? "✅" : "ℹ️"}</span> <div>${message}</div>`;
        elements.globalAlerts.appendChild(alertEl);

        if (autoDismiss > 0) {
            setTimeout(() => {
                if (alertEl.parentNode) {
                    alertEl.remove();
                }
            }, autoDismiss);
        }
    }

    /**
     * Unified HTTP client with automatic Cookie credentials, token handling,
     * demo IP spoofing (X-Forwarded-For) and automatic 403 Zero Trust challenge interception.
     */
    async function apiFetch(url, options = {}) {
        options.headers = options.headers || {};
        options.credentials = "include"; // Send HttpOnly cookie automatically

        // If in demo spoofing mode, inject X-Forwarded-For
        if (state.activeSimulatedIp) {
            options.headers["X-Forwarded-For"] = state.activeSimulatedIp;
        }

        // Add Bearer token header if available in state
        if (state.authToken && !options.headers["Authorization"]) {
            options.headers["Authorization"] = `Bearer ${state.authToken}`;
        }

        if (options.body && typeof options.body === "object" && !(options.body instanceof FormData)) {
            options.headers["Content-Type"] = "application/json";
            options.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(url, options);

            // Handle Zero Trust Continuous Challenge interception (403 Forbidden with reauth_required)
            if (response.status === 403) {
                const clone = response.clone();
                try {
                    const data = await clone.json();
                    const detail = data.detail || data;
                    if (detail && detail.reauth_required) {
                        handleZeroTrustRiskTrigger(detail);
                        return response;
                    }
                } catch (_) {
                    // Not a JSON body, pass response as is
                }
            }

            return response;
        } catch (error) {
            console.error("API Network Error:", error);
            showAlert(`Error de conexión con el servidor: ${error.message}`, "danger");
            throw error;
        }
    }

    /**
     * Updates Zero Trust status indicators.
     */
    function setTrustStatus(level, text, reason = "") {
        elements.trustIndicator.className = "trust-badge-pill";
        if (level === "verified") {
            elements.trustIndicator.classList.add("success");
            elements.trustIndicatorText.textContent = text || "CONFIANZA VERIFICADA (100%)";
            elements.statTrustLevel.textContent = "100%";
            elements.statTrustLevel.style.color = "var(--emerald-green)";
            elements.statTrustDesc.textContent = reason || "Sesión verificada biométricamente";
        } else if (level === "warning") {
            elements.trustIndicator.classList.add("warning");
            elements.trustIndicatorText.textContent = text || "RIESGO DETECTADO (40%)";
            elements.statTrustLevel.textContent = "40%";
            elements.statTrustLevel.style.color = "var(--amber-warning)";
            elements.statTrustDesc.textContent = reason || "Reautenticación requerida";
        } else {
            elements.trustIndicator.classList.add("danger");
            elements.trustIndicatorText.textContent = text || "SESIÓN REVOCADA / RIESGO (0%)";
            elements.statTrustLevel.textContent = "0%";
            elements.statTrustLevel.style.color = "var(--crimson-danger)";
            elements.statTrustDesc.textContent = reason || "Acceso restringido por política Zero Trust";
        }
    }

    /**
     * Initializes the authenticated workspace after login.
     */
    async function setupAuthenticatedSession(userData, token = null) {
        state.currentUser = userData;
        if (token) state.authToken = token;

        // Populate header
        elements.headerUsername.textContent = userData.username;
        const roles = userData.roles.map(r => typeof r === "string" ? r : r.name);
        const isAdmin = roles.includes("admin");

        elements.headerRoleBadge.textContent = isAdmin ? "ADMIN" : "USER";
        if (isAdmin) {
            elements.headerRoleBadge.className = "role-tag admin";
            elements.navAdminBtn.classList.remove("hidden");
        } else {
            elements.headerRoleBadge.className = "role-tag";
            elements.navAdminBtn.classList.add("hidden");
        }

        elements.userSessionBar.classList.remove("hidden");
        elements.viewAuth.classList.add("hidden");
        elements.authenticatedWorkspace.classList.remove("hidden");

        setTrustStatus("verified", "CONFIANZA VERIFICADA (100%)", "Sesión iniciada con éxito");

        // Load Biometric Status
        await refreshBiometricStatus();

        // Initialize Guided Biometric Capture
        initGuidedEnrollmentCapture();

        // Update IP status display
        updateIpDisplay();

        // Switch to Biometrics default tab
        switchWorkspaceTab("biometrics");
    }

    /**
     * Switches between main subviews in workspace.
     */
    function switchWorkspaceTab(tab) {
        elements.navBiometricsBtn.classList.remove("active");
        elements.navOperationsBtn.classList.remove("active");
        elements.navAdminBtn.classList.remove("active");

        elements.sectionBiometrics.classList.add("hidden");
        elements.sectionOperations.classList.add("hidden");
        elements.sectionAdmin.classList.add("hidden");

        if (tab === "biometrics") {
            elements.navBiometricsBtn.classList.add("active");
            elements.sectionBiometrics.classList.remove("hidden");
        } else if (tab === "operations") {
            elements.navOperationsBtn.classList.add("active");
            elements.sectionOperations.classList.remove("hidden");
        } else if (tab === "admin") {
            elements.navAdminBtn.classList.add("active");
            elements.sectionAdmin.classList.remove("hidden");
            loadAdminData();
        }
    }

    /**
     * Fetches current biometric profile status from the server.
     */
    async function refreshBiometricStatus() {
        try {
            const resp = await apiFetch("/api/biometric/status");
            if (resp.ok) {
                const data = await resp.json();
                if (data.enrolled) {
                    elements.headerBiometricBadge.textContent = "ENROLADO (AES-256)";
                    elements.headerBiometricBadge.style.color = "var(--emerald-green)";
                    elements.statBiometricStatus.textContent = "Enrolado y Cifrado";
                    elements.statBiometricStatus.style.color = "var(--emerald-green)";
                    elements.statBiometricDims.textContent = "Plantilla AES-256-GCM Activa";
                } else {
                    elements.headerBiometricBadge.textContent = "Sin Perfil Biométrico";
                    elements.headerBiometricBadge.style.color = "var(--amber-warning)";
                    elements.statBiometricStatus.textContent = "Pendiente de Enrolar";
                    elements.statBiometricStatus.style.color = "var(--amber-warning)";
                    elements.statBiometricDims.textContent = "Se requieren 3 repeticiones";
                }
            }
        } catch (e) {
            console.warn("Could not check biometric status:", e);
        }
    }

    /**
     * Guided Enrollment Pipeline using high-resolution KeystrokeCapture.
     */
    function initGuidedEnrollmentCapture() {
        if (state.enrollmentCapture) {
            state.enrollmentCapture.detach();
        }

        let readySamples = [];

        state.enrollmentCapture = new KeystrokeCapture({
            targetPhrase: state.targetPhrase,
            samplesRequired: 3,
            requireEnter: true,
            onKeypress: (count, target) => {
                elements.vectorDimCounter.textContent = `${count} teclas pulsadas (Esperadas: ${target})`;
            },
            onSampleCaptured: (sampleIndex, totalSamples, vector) => {
                const percent = Math.round((sampleIndex / totalSamples) * 100);
                elements.enrollmentProgressBar.style.width = `${percent}%`;
                elements.enrollmentPercentLabel.textContent = `${percent}%`;
                elements.enrollmentStepLabel.textContent = `Progreso de Enrolamiento: Muestra ${sampleIndex} de ${totalSamples}`;

                // Update sample chips
                if (sampleIndex === 1) {
                    elements.chipSample1.className = "sample-step-chip completed";
                    elements.chipSample2.className = "sample-step-chip active";
                } else if (sampleIndex === 2) {
                    elements.chipSample2.className = "sample-step-chip completed";
                    elements.chipSample3.className = "sample-step-chip active";
                } else if (sampleIndex >= 3) {
                    elements.chipSample3.className = "sample-step-chip completed";
                }

                // Show extracted vector telemetry (RNF-08 verification)
                elements.vectorDimCounter.textContent = `${vector.length} características extraídas (${vector.length === 31 ? "Dimensión CMU estándar" : "Longitud compatible"})`;
                elements.enrollmentTelemetry.textContent = 
                    `[MUESTRA ${sampleIndex}/${totalSamples} EXTRAÍDA EN CLIENTE (RNF-08: 0 caracteres guardados)]\n` +
                    `Vector [${vector.length} valores en seg]:\n` +
                    JSON.stringify(vector, null, 2);

                showAlert(`Muestra ${sampleIndex} de 3 registrada con éxito (${vector.length} dimensiones temporales).`, "info", 4000);
            },
            onEnrollmentReady: (samples) => {
                readySamples = samples;
                elements.btnSaveEnrollment.disabled = false;
                showAlert("¡Las 3 repeticiones han sido capturadas! Ya puedes guardar tu perfil cifrado en el servidor.", "success", 8000);
            },
            onError: (msg) => {
                showAlert(msg, "warning", 5000);
                elements.enrollmentTelemetry.textContent += `\n⚠️ ${msg}`;
            }
        });

        state.enrollmentCapture.attach(elements.enrollmentInput);

        // Save Enrollment Button Handler
        elements.btnSaveEnrollment.onclick = async () => {
            if (!readySamples || readySamples.length < 3) {
                showAlert("Debes completar las 3 repeticiones requeridas para enrolarte.", "warning");
                return;
            }

            elements.btnSaveEnrollment.disabled = true;
            elements.btnSaveEnrollment.textContent = "Cifrando y guardando...";

            try {
                // Enforce RNF-08: send ONLY the numeric samples, no letters
                const resp = await apiFetch("/api/biometric/enroll", {
                    method: "POST",
                    body: { samples: readySamples }
                });

                const data = await resp.json();

                if (resp.ok) {
                    showAlert("Perfil biométrico enrolado y cifrado con AES-256-GCM en el servidor.", "success", 7000);
                    await refreshBiometricStatus();
                    resetEnrollmentUi();
                } else {
                    showAlert(data.detail || "Error al registrar perfil biométrico.", "danger");
                    elements.btnSaveEnrollment.disabled = false;
                }
            } catch (err) {
                showAlert(`Error: ${err.message}`, "danger");
                elements.btnSaveEnrollment.disabled = false;
            } finally {
                elements.btnSaveEnrollment.textContent = "💾 Guardar Perfil Cifrado (AES-256-GCM)";
            }
        };

        // Reset Enrollment Button Handler
        elements.btnResetEnrollment.onclick = () => {
            resetEnrollmentUi();
            showAlert("Captura de enrolamiento reiniciada.", "info", 3000);
        };

        // Live Single-Shot Verification Test Handler (RF-05)
        elements.btnVerifyPattern.onclick = async () => {
            const lastVector = state.enrollmentCapture.getLastVector();
            if (!lastVector) {
                showAlert("Primero teclea al menos una vez la frase en el campo superior.", "warning");
                return;
            }

            elements.btnVerifyPattern.disabled = true;
            try {
                const resp = await apiFetch("/api/biometric/verify", {
                    method: "POST",
                    body: { vector: lastVector }
                });
                const data = await resp.json();

                if (resp.ok) {
                    const matchText = data.match ? "COINCIDENCIA GENUINA" : "DESVIACIÓN DETECTADA (IMPOSTOR)";
                    const alertType = data.match ? "success" : "danger";
                    showAlert(`Resultado de Verificación Biométrica: ${matchText} | Score: ${(data.score * 100).toFixed(2)}% (Umbral θ*: ${(data.threshold * 100).toFixed(2)}%)`, alertType, 8000);
                } else {
                    showAlert(data.detail || "Error en verificación biométrica.", "danger");
                }
            } catch (e) {
                showAlert(`Error: ${e.message}`, "danger");
            } finally {
                elements.btnVerifyPattern.disabled = false;
            }
        };
    }

    /**
     * Resets the enrollment UI state.
     */
    function resetEnrollmentUi() {
        if (state.enrollmentCapture) {
            state.enrollmentCapture.reset();
        }
        elements.enrollmentProgressBar.style.width = "0%";
        elements.enrollmentPercentLabel.textContent = "0%";
        elements.enrollmentStepLabel.textContent = "Progreso de Enrolamiento: Muestra 0 de 3";
        elements.chipSample1.className = "sample-step-chip active";
        elements.chipSample2.className = "sample-step-chip";
        elements.chipSample3.className = "sample-step-chip";
        elements.btnSaveEnrollment.disabled = true;
        elements.vectorDimCounter.textContent = "0 características";
        elements.enrollmentTelemetry.textContent = "// Captura reiniciada. Escribe la frase objetivo y presiona Enter...";
    }

    /**
     * Updates the UI with IP information.
     */
    function updateIpDisplay() {
        if (state.activeSimulatedIp) {
            elements.statCurrentIp.textContent = state.activeSimulatedIp;
            elements.statCurrentIp.style.color = "var(--amber-warning)";
            elements.statIpStatus.textContent = "⚠️ Header X-Forwarded-For simulado activo";
        } else {
            elements.statCurrentIp.textContent = "127.0.0.1";
            elements.statCurrentIp.style.color = "#FFFFFF";
            elements.statIpStatus.textContent = "Coincide con IP original de sesión";
        }
    }

    /**
     * Handles Zero Trust risk trigger (detonated by backend 403 reauth_required).
     */
    async function handleZeroTrustRiskTrigger(detail) {
        state.currentRiskEvent = detail.risk_event || "sensitive_operation";
        setTrustStatus("warning", "REAUTENTICACIÓN REQUERIDA (40%)", detail.detail || detail.message);

        // Open Adaptive Challenge Modal
        await openAdaptiveReauthModal(state.currentRiskEvent, detail.detail || detail.message);
    }

    /**
     * Opens Adaptive Reauth Modal, generates anti-replay nonce, and binds KeystrokeCapture.
     */
    async function openAdaptiveReauthModal(riskEvent, riskDetail) {
        elements.reauthRiskTitle.textContent = `Riesgo de Contexto: ${riskEvent}`;
        elements.reauthRiskDetail.textContent = riskDetail || "Se requiere validación de identidad para continuar.";
        elements.reauthStatusResult.innerHTML = "";
        elements.reauthInput.value = "";
        elements.btnSubmitReauth.disabled = true;

        // Fetch Anti-Replay Challenge Nonce from server (CP-S04)
        try {
            const resp = await apiFetch("/api/reauth/challenge", { method: "POST" });
            if (resp.ok) {
                const data = await resp.json();
                state.currentNonce = data.challenge_nonce;
                state.targetPhrase = data.target_phrase || ".tie5Roanl";
                elements.reauthNonceBadge.textContent = `${state.currentNonce.substring(0, 12)}...`;
                elements.reauthTargetPhrase.textContent = state.targetPhrase;

                // Start countdown timer
                startNonceCountdown(data.expires_in || 300);
            } else {
                elements.reauthNonceBadge.textContent = "Error al obtener nonce";
            }
        } catch (e) {
            elements.reauthNonceBadge.textContent = "Error de conexión";
        }

        // Initialize single-shot capture for modal
        let capturedVector = null;
        if (state.reauthCapture) {
            state.reauthCapture.detach();
        }

        state.reauthCapture = new KeystrokeCapture({
            targetPhrase: state.targetPhrase,
            samplesRequired: 1,
            requireEnter: true,
            onKeypress: (count, target) => {
                elements.reauthStatusResult.innerHTML = `<span style="color: var(--cyan-neon); font-size: 0.82rem;">Escribiendo: ${count} de ${target} teclas...</span>`;
            },
            onSampleCaptured: (_, __, vector) => {
                capturedVector = vector;
                elements.btnSubmitReauth.disabled = false;
                elements.reauthStatusResult.innerHTML = `<span style="color: var(--emerald-green); font-size: 0.82rem;">✓ Muestra capturada (${vector.length} dimensiones temporales). Haz clic en 'Verificar Dinámica' o pulsa Enter.</span>`;
                // Automatically submit for seamless user experience
                submitReauthVerification(capturedVector);
            },
            onError: (msg) => {
                elements.reauthStatusResult.innerHTML = `<span style="color: var(--amber-warning); font-size: 0.82rem;">⚠️ ${msg}</span>`;
            }
        });

        state.reauthCapture.attach(elements.reauthInput);

        // Submit button click
        elements.btnSubmitReauth.onclick = () => {
            if (capturedVector) {
                submitReauthVerification(capturedVector);
            }
        };

        elements.modalReauth.classList.add("open");
        setTimeout(() => elements.reauthInput.focus(), 150);
    }

    /**
     * Submits reauthentication verification sample to backend.
     */
    async function submitReauthVerification(vector) {
        elements.btnSubmitReauth.disabled = true;
        elements.reauthStatusResult.innerHTML = `<span style="color: var(--cyan-neon);">Analizando dinámica con Gradient Boosting y Métricas Estadísticas...</span>`;

        try {
            const payload = {
                risk_event: state.currentRiskEvent,
                challenge_nonce: state.currentNonce,
                timestamp: Date.now() / 1000.0,
                vector: vector
            };

            const resp = await apiFetch("/api/reauth/verify", {
                method: "POST",
                body: payload
            });

            const data = await resp.json();

            if (resp.ok && data.match) {
                // Legitimate user match
                clearInterval(state.nonceCountdownTimer);
                elements.reauthStatusResult.innerHTML = `
                    <div class="alert-banner success" style="margin: 0.5rem 0;">
                        <span>✅</span>
                        <div>
                            <strong>Autenticación Exitosa:</strong> Score ${(data.score * 100).toFixed(1)}% vs Umbral ${(data.threshold * 100).toFixed(1)}%.
                            <br>Nivel de confianza Zero Trust restablecido a 100%.
                        </div>
                    </div>`;

                setTrustStatus("verified", "CONFIANZA VERIFICADA (100%)", "Reautenticación superada con éxito");

                setTimeout(() => {
                    closeAdaptiveReauthModal();
                    showAlert("Reautenticación completada. Tu operación ha sido autorizada.", "success", 6000);
                }, 1200);

            } else {
                // Impostor or verification failure (CP-S08: Session Revocation)
                clearInterval(state.nonceCountdownTimer);
                elements.reauthStatusResult.innerHTML = `
                    <div class="alert-banner danger" style="margin: 0.5rem 0;">
                        <span>🚨</span>
                        <div>
                            <strong>Acceso Denegado (CP-S08):</strong> Dinámica de tecleo anómala (Score: ${(data.score * 100).toFixed(1)}% < Umbral: ${(data.threshold * 100).toFixed(1)}%).
                            <br>La sesión ha sido <strong>revocada</strong> inmediatamente por seguridad.
                        </div>
                    </div>`;

                setTrustStatus("revoked", "SESIÓN REVOCADA (0%)", "Impostor detectado en reautenticación");

                setTimeout(() => {
                    closeAdaptiveReauthModal();
                    doLogout();
                }, 3500);
            }
        } catch (e) {
            elements.reauthStatusResult.innerHTML = `<span style="color: var(--crimson-danger);">Error: ${e.message}</span>`;
            elements.btnSubmitReauth.disabled = false;
        }
    }

    /**
     * Starts the countdown timer for the single-use nonce.
     */
    function startNonceCountdown(seconds) {
        clearInterval(state.nonceCountdownTimer);
        let remaining = seconds;
        elements.reauthCountdown.textContent = `⏱️ ${remaining}s`;

        state.nonceCountdownTimer = setInterval(() => {
            remaining--;
            if (remaining <= 0) {
                clearInterval(state.nonceCountdownTimer);
                elements.reauthCountdown.textContent = "⏱️ EXPIRADO";
                elements.reauthStatusResult.innerHTML = `<span style="color: var(--crimson-danger);">El nonce de seguridad ha expirado. Vuelve a intentar.</span>`;
                elements.btnSubmitReauth.disabled = true;
            } else {
                elements.reauthCountdown.textContent = `⏱️ ${remaining}s`;
            }
        }, 1000);
    }

    /**
     * Closes the reauth modal.
     */
    function closeAdaptiveReauthModal() {
        elements.modalReauth.classList.remove("open");
        clearInterval(state.nonceCountdownTimer);
        if (state.reauthCapture) {
            state.reauthCapture.detach();
        }
    }

    elements.btnCancelReauth.onclick = () => {
        closeAdaptiveReauthModal();
        showAlert("Desafío cancelado. La operación sensible no se ejecutó.", "warning");
    };

    /**
     * Executes Sensitive Corporate Action (e.g. fund wire transfer).
     */
    elements.formSensitiveAction.onsubmit = async (e) => {
        e.preventDefault();
        elements.sensitiveOpResult.innerHTML = `<span style="color: var(--cyan-neon);">Ejecutando operación corporativa bajo políticas Zero Trust...</span>`;

        try {
            const resp = await apiFetch("/api/operations/sensitive-action", {
                method: "POST",
                body: {
                    action_type: elements.opType.value,
                    amount: parseFloat(elements.opAmount.value),
                    destination_account: elements.opAccount.value,
                }
            });

            const data = await resp.json();

            if (resp.ok) {
                elements.sensitiveOpResult.innerHTML = `
                    <div class="alert-banner success">
                        <span>💰</span>
                        <div>
                            <strong>Operación Autorizada:</strong> ${data.message}
                            <br><small class="mono">Transacción validada por el Motor de Riesgo Zero Trust.</small>
                        </div>
                    </div>`;
                showAlert("Operación crítica ejecutada exitosamente.", "success");
            } else {
                const detail = data.detail || data;
                if (!detail.reauth_required) {
                    elements.sensitiveOpResult.innerHTML = `
                        <div class="alert-banner danger">
                            <span>❌</span>
                            <div>${detail || "Operación denegada."}</div>
                        </div>`;
                } else {
                    elements.sensitiveOpResult.innerHTML = `
                        <div class="alert-banner warning">
                            <span>🔒</span>
                            <div>Operación retenida: Reautenticación adaptativa requerida en modal.</div>
                        </div>`;
                }
            }
        } catch (err) {
            elements.sensitiveOpResult.innerHTML = `<div class="alert-banner danger">Error: ${err.message}</div>`;
        }
    };

    /**
     * Evaluates continuous session risk on demand.
     */
    elements.btnEvalRisk.onclick = async () => {
        try {
            const resp = await apiFetch("/api/reauth/evaluate");
            const data = await resp.json();

            if (resp.ok && !data.reauth_required) {
                showAlert(`Nivel de confianza validado: ${data.detail} (IP: ${data.current_ip})`, "success", 5000);
                setTrustStatus("verified", "CONFIANZA VERIFICADA (100%)", data.detail);
            } else {
                showAlert(`Riesgo Detectado: ${data.detail || "Reautenticación requerida"}`, "warning", 6000);
            }
        } catch (e) {
            showAlert(`Error al evaluar riesgo: ${e.message}`, "danger");
        }
    };

    /**
     * Threat Simulator Controls: Inject or Reset Spoofed IP.
     */
    elements.btnToggleSimIp.onclick = () => {
        const spoofed = elements.simSpoofedIp.value.trim() || "189.203.45.12";
        state.activeSimulatedIp = spoofed;
        updateIpDisplay();
        setTrustStatus("warning", "ALERTA: DISCREPANCIA DE IP", `IP simulada vía X-Forwarded-For: ${spoofed}`);
        showAlert(`IP externa inyectada (${spoofed}). La próxima petición detonará CP-S07 (ip_change).`, "warning", 8000);
    };

    elements.btnResetSimIp.onclick = () => {
        state.activeSimulatedIp = null;
        updateIpDisplay();
        setTrustStatus("verified", "CONFIANZA VERIFICADA (100%)", "IP local restaurada (127.0.0.1)");
        showAlert("Header X-Forwarded-For eliminado. Conexión restaurada a IP local.", "info", 5000);
    };

    /**
     * Admin Dashboard Data Loading (Users + Audit Logs).
     */
    async function loadAdminData() {
        try {
            // 1. Load users
            const usersResp = await apiFetch("/api/admin/users");
            if (usersResp.ok) {
                const users = await usersResp.json();
                renderUsersTable(users);
            }

            // 2. Load audit logs
            await refreshAuditLogs();
        } catch (e) {
            showAlert(`Error al cargar datos administrativos: ${e.message}`, "danger");
        }
    }

    function renderUsersTable(users) {
        elements.adminUsersTbody.innerHTML = "";
        users.forEach(u => {
            const tr = document.createElement("tr");
            const rolesList = u.roles.map(r => r.name || r).join(", ");
            const hasAdmin = rolesList.includes("admin");

            tr.innerHTML = `
                <td class="mono">#${u.id}</td>
                <td><strong>${u.username}</strong></td>
                <td>${u.email}</td>
                <td><span class="role-tag ${hasAdmin ? "admin" : ""}">${rolesList}</span></td>
                <td><span class="event-badge ${u.is_active ? "success" : "danger"}">${u.is_active ? "Activo" : "Bloqueado"}</span></td>
                <td>
                    ${!hasAdmin ? `<button class="btn btn-secondary btn-sm" onclick="window.assignAdminRole(${u.id})">Promover a Admin</button>` : `<span class="mono" style="color: var(--violet-admin);">Administrador</span>`}
                </td>
            `;
            elements.adminUsersTbody.appendChild(tr);
        });
    }

    window.assignAdminRole = async function(userId) {
        try {
            const resp = await apiFetch(`/api/admin/users/${userId}/roles`, {
                method: "POST",
                body: { role_name: "admin" }
            });
            if (resp.ok) {
                showAlert(`Rol 'admin' asignado correctamente al usuario #${userId}.`, "success");
                loadAdminData();
            } else {
                const err = await resp.json();
                showAlert(err.detail || "Error al asignar rol.", "danger");
            }
        } catch (e) {
            showAlert(`Error: ${e.message}`, "danger");
        }
    };

    async function refreshAuditLogs() {
        try {
            const auditResp = await apiFetch("/api/admin/audit-logs?limit=50");
            if (auditResp.ok) {
                const logs = await auditResp.json();
                renderAuditLogsTable(logs);
            }
        } catch (e) {
            console.error("Error refreshing audit logs:", e);
        }
    }

    function renderAuditLogsTable(logs) {
        elements.adminAuditTbody.innerHTML = "";
        logs.forEach(log => {
            const tr = document.createElement("tr");
            const type = log.event_type;
            let badgeClass = "info";
            if (type.includes("success") || type.includes("enrolled")) badgeClass = "success";
            else if (type.includes("risk") || type.includes("challenge") || type.includes("required")) badgeClass = "warning";
            else if (type.includes("failed") || type.includes("blocked") || type.includes("locked")) badgeClass = "danger";

            const dateStr = new Date(log.timestamp).toLocaleString();
            const detailsStr = log.details ? JSON.stringify(log.details) : "-";

            tr.innerHTML = `
                <td class="mono">${log.id}</td>
                <td class="mono" style="font-size: 0.75rem;">${dateStr}</td>
                <td><span class="event-badge ${badgeClass}">${log.event_type}</span></td>
                <td class="mono">${log.user_id !== null ? log.user_id : "-"}</td>
                <td class="mono">${log.ip_address}</td>
                <td class="mono" style="font-size: 0.72rem; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title='${detailsStr}'>${detailsStr}</td>
            `;
            elements.adminAuditTbody.appendChild(tr);
        });
    }

    elements.btnRefreshAudit.onclick = () => {
        refreshAuditLogs();
        showAlert("Bitácora de auditoría actualizada.", "info", 2000);
    };

    /**
     * Authentication Tab Switching (Login vs Register).
     */
    elements.tabLoginBtn.onclick = () => {
        elements.tabLoginBtn.classList.add("active");
        elements.tabRegisterBtn.classList.remove("active");
        elements.formLogin.classList.remove("hidden");
        elements.formRegister.classList.add("hidden");
    };

    elements.tabRegisterBtn.onclick = () => {
        elements.tabRegisterBtn.classList.add("active");
        elements.tabLoginBtn.classList.remove("active");
        elements.formRegister.classList.remove("hidden");
        elements.formLogin.classList.add("hidden");
    };

    // Quick Fill Demo Credentials
    elements.btnFillAdmin.onclick = () => {
        elements.loginUsername.value = "admin";
        elements.loginPassword.value = "AdminZeroTrust2026!";
    };

    elements.btnFillUser.onclick = () => {
        elements.loginUsername.value = "usuario_demo";
        elements.loginPassword.value = "Password123!";
    };

    /**
     * Login Form Handler (RF-02, CP-S06).
     */
    elements.formLogin.onsubmit = async (e) => {
        e.preventDefault();
        const username = elements.loginUsername.value.trim();
        const password = elements.loginPassword.value;

        try {
            const resp = await apiFetch("/api/auth/login", {
                method: "POST",
                body: { username, password }
            });

            const data = await resp.json();

            if (resp.ok) {
                showAlert(`Bienvenido, ${data.user.username}. Sesión JWT y cookie establecidas.`, "success");
                setupAuthenticatedSession(data.user, data.access_token);
            } else {
                showAlert(data.detail || "Error en autenticación de credenciales.", "danger");
            }
        } catch (err) {
            showAlert(`Error al conectar con el servidor: ${err.message}`, "danger");
        }
    };

    /**
     * Register Form Handler (RF-01).
     */
    elements.formRegister.onsubmit = async (e) => {
        e.preventDefault();
        const username = elements.regUsername.value.trim();
        const email = elements.regEmail.value.trim();
        const password = elements.regPassword.value;

        try {
            const resp = await apiFetch("/api/auth/register", {
                method: "POST",
                body: { username, email, password }
            });

            const data = await resp.json();

            if (resp.ok) {
                showAlert(`Cuenta creada con éxito para '${data.username}'. Ahora puedes iniciar sesión.`, "success", 7000);
                elements.loginUsername.value = username;
                elements.loginPassword.value = password;
                elements.tabLoginBtn.click();
            } else {
                showAlert(data.detail || "Error al registrar cuenta.", "danger");
            }
        } catch (err) {
            showAlert(`Error: ${err.message}`, "danger");
        }
    };

    /**
     * Logout Handler (RF-08).
     */
    async function doLogout() {
        try {
            await apiFetch("/api/auth/logout", { method: "POST" });
        } catch (_) {}

        state.currentUser = null;
        state.authToken = null;
        state.activeSimulatedIp = null;

        elements.userSessionBar.classList.add("hidden");
        elements.authenticatedWorkspace.classList.add("hidden");
        elements.viewAuth.classList.remove("hidden");
        setTrustStatus("revoked", "SIN SESIÓN ACTIVA", "Inicia sesión para ingresar al sistema");
        showAlert("Sesión revocada y cookie eliminada.", "info", 4000);
    }

    elements.btnLogout.onclick = doLogout;

    // Navigation Tab Click Handlers
    elements.navBiometricsBtn.onclick = () => switchWorkspaceTab("biometrics");
    elements.navOperationsBtn.onclick = () => switchWorkspaceTab("operations");
    elements.navAdminBtn.onclick = () => switchWorkspaceTab("admin");

    /**
     * Initial Session Check on page load (GET /api/auth/me).
     */
    async function checkInitialSession() {
        try {
            const resp = await apiFetch("/api/auth/me");
            if (resp.ok) {
                const user = await resp.json();
                setupAuthenticatedSession(user);
            } else {
                setTrustStatus("revoked", "SIN SESIÓN ACTIVA", "Inicia sesión para continuar");
            }
        } catch (_) {
            setTrustStatus("revoked", "CONEXIÓN DESCONECTADA", "Inicia el servidor back-end");
        }
    }

    // Run initial startup check
    checkInitialSession();

})();
