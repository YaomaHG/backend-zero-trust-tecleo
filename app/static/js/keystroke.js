/**
 * Motor de Captura y Análisis de Dinámica de Tecleo de Alta Precisión (app/static/js/keystroke.js)
 * Tesis de Ingeniería de Software: Reautenticación Adaptativa Zero Trust
 * 
 * Requerimientos y Fundamentos Técnicos:
 * - RNF-08 (Minimización de Datos y Privacidad):
 *   NUNCA captura, almacena ni transmite los caracteres o letras presionadas por el usuario.
 *   El servidor jamás recibe contraseñas ni textos; únicamente vectores numéricos de duraciones.
 * 
 * - Alta Resolución con window.performance.now():
 *   Captura marcas de tiempo con precisión de microsegundos (sub-milisegundos) basadas en un
 *   reloj monotónico de hardware (DOMHighResTimeStamp). Supera a Date.now() porque no está
 *   sujeto a saltos de reloj ni sincronizaciones NTP del sistema operativo.
 * 
 * - Filtrado de Teclas Modificadoras (Shift, Control, Alt, CapsLock, Tab):
 *   Para escribir la letra mayúscula 'R' en '.tie5Roanl', el usuario suele presionar la tecla Shift.
 *   Si Shift se capturara como una pulsación separada, distorsionaría la longitud del vector
 *   y agregaría ruido dependiente de configuraciones de teclado. Al filtrarlas, garantizamos que
 *   sólo se evalúe el ritmo motor de los caracteres de la frase.
 * 
 * - Estructura del Vector de 31 Dimensiones (Benchmark CMU):
 *   Frase objetivo obligatoria: ".tie5Roanl" + tecla Enter (11 pulsaciones físicas en total):
 *   1) 11 Tiempos de Retención (Hold Time H): H_i = release_i - press_i
 *   2) 10 Tiempos de Vuelo Tecla a Tecla (Down-Down DD): DD_i = press_{i+1} - press_i
 *   3) 10 Tiempos de Transición (Up-Down UD): UD_i = press_{i+1} - release_i
 *   Total: 11 + 10 + 10 = 31 números flotantes normalizados en segundos.
 */

// Catálogo de teclas modificadoras que se filtran para evitar ruido en la biometría
const MODIFIER_KEYS = new Set([
    "Shift", "Control", "Alt", "AltGraph", "CapsLock", "Meta", "Tab",
    "ShiftLeft", "ShiftRight", "ControlLeft", "ControlRight", "AltLeft", "AltRight",
    "MetaLeft", "MetaRight", "OSLeft", "OSRight", "ContextMenu"
]);

class KeystrokeCapture {
    /**
     * @param {Object} options Parámetros de configuración
     * @param {string} options.targetPhrase Frase objetivo de referencia ('.tie5Roanl')
     * @param {number} options.samplesRequired Número de repeticiones para enrolamiento (default: 3)
     * @param {boolean} options.requireEnter Exige tecla Enter para finalizar la muestra (default: true)
     * @param {Function} options.onKeypress Callback ejecutado en cada pulsación: (teclasActuales, teclasEsperadas)
     * @param {Function} options.onSampleCaptured Callback al completar una repetición: (indice, total, vector31D)
     * @param {Function} options.onEnrollmentReady Callback al reunir las 3 repeticiones: (samples)
     * @param {Function} options.onError Callback ante errores de captura o pulsación de borrado
     */
    constructor(options = {}) {
        this.targetPhrase = options.targetPhrase || ".tie5Roanl";
        this.samplesRequired = options.samplesRequired || 3;
        this.requireEnter = options.requireEnter !== undefined ? options.requireEnter : true;

        // Longitud esperada: 10 caracteres alfanuméricos + 1 tecla Enter = 11 eventos -> 31 dimensiones
        this.expectedKeyCount = this.targetPhrase.length + (this.requireEnter ? 1 : 0);

        this.onKeypress = options.onKeypress || (() => {});
        this.onSampleCaptured = options.onSampleCaptured || (() => {});
        this.onEnrollmentReady = options.onEnrollmentReady || (() => {});
        this.onError = options.onError || (() => {});

        // Estado interno de captura
        this.inputElement = null;
        this.activeKeys = new Map(); // Mapa: event.code -> cola de marcas de tiempo de presión
        this.currentKeySequence = []; // Lista de tuplas temporales: { code, press, release }
        this.collectedSamples = []; // Lista de vectores de 31 dimensiones para enrolamiento

        this._boundKeyDown = this._handleKeyDown.bind(this);
        this._boundKeyUp = this._handleKeyUp.bind(this);
    }

    /**
     * Vincula los escuchadores de eventos keydown y keyup a un input HTML.
     * @param {HTMLInputElement|HTMLTextAreaElement} element
     */
    attach(element) {
        if (!element) return;
        this.detach();
        this.inputElement = element;
        this.inputElement.addEventListener("keydown", this._boundKeyDown);
        this.inputElement.addEventListener("keyup", this._boundKeyUp);
    }

    /**
     * Desvincula los escuchadores y libera memoria.
     */
    detach() {
        if (this.inputElement) {
            this.inputElement.removeEventListener("keydown", this._boundKeyDown);
            this.inputElement.removeEventListener("keyup", this._boundKeyUp);
            this.inputElement = null;
        }
    }

    /**
     * Restablece completamente la sesión de captura eliminando todas las muestras previas.
     */
    reset() {
        this.activeKeys.clear();
        this.currentKeySequence = [];
        this.collectedSamples = [];
        if (this.inputElement) {
            this.inputElement.value = "";
        }
    }

    /**
     * Limpia únicamente la repetición actual si el usuario cometió un error o borró texto.
     */
    clearCurrentSample() {
        this.activeKeys.clear();
        this.currentKeySequence = [];
        if (this.inputElement) {
            this.inputElement.value = "";
        }
    }

    /**
     * Manejador del evento físico 'keydown'.
     * Utiliza performance.now() para registrar la marca de presión en sub-milisegundos.
     * @private
     */
    _handleKeyDown(event) {
        // Descartar repetición automática de tecla por mantenerla presionada
        if (event.repeat) return;

        // Si se presiona Backspace o Escape, reiniciar la muestra actual para garantizar cadencia pura
        if (event.key === "Backspace" || event.key === "Escape") {
            this.clearCurrentSample();
            this.onError("Pulsación corregida con tecla de borrado. Muestra reiniciada.");
            return;
        }

        // FILTRADO ESTRICTO DE TECLAS MODIFICADORAS (Shift, Ctrl, Alt, CapsLock, Tab)
        // Evita distorsionar el vector biométrico cuando el usuario presiona Shift para mayúsculas
        if (MODIFIER_KEYS.has(event.key) || MODIFIER_KEYS.has(event.code)) {
            return;
        }

        // Captura con performance.now() convertida de milisegundos a segundos (estándar CMU)
        const pressTimeSec = performance.now() / 1000.0;

        if (!this.activeKeys.has(event.code)) {
            this.activeKeys.set(event.code, []);
        }
        this.activeKeys.get(event.code).push(pressTimeSec);

        const currentCount = this.currentKeySequence.length + 1;
        this.onKeypress(Math.min(currentCount, this.expectedKeyCount), this.expectedKeyCount);
    }

    /**
     * Manejador del evento físico 'keyup'.
     * Registra el instante de liberación de la tecla para calcular los tiempos Hold y Flight.
     * @private
     */
    _handleKeyUp(event) {
        // Ignorar teclas modificadoras y de borrado
        if (MODIFIER_KEYS.has(event.key) || MODIFIER_KEYS.has(event.code)) {
            return;
        }

        if (event.key === "Backspace" || event.key === "Escape") {
            return;
        }

        const releaseTimeSec = performance.now() / 1000.0;

        const queue = this.activeKeys.get(event.code);
        if (!queue || queue.length === 0) return;

        const pressTimeSec = queue.shift();

        // Minimización de Datos (RNF-08): Solo se preservan las marcas de tiempo físicas
        this.currentKeySequence.push({
            code: event.code,
            press: pressTimeSec,
            release: releaseTimeSec
        });

        // Verificar condición de muestra completa (tecla Enter o número de teclas alcanzado)
        const isEnterPressed = (event.key === "Enter" || event.code === "Enter");
        const reachedKeyCount = this.currentKeySequence.length >= this.expectedKeyCount;

        if ((this.requireEnter && isEnterPressed) || (!this.requireEnter && reachedKeyCount)) {
            this._processCompletedSample();
        }
    }

    /**
     * Extrae el vector de características de 31 dimensiones a partir de los eventos temporales.
     * 
     * ¿Cómo se construye el vector exacto de 31 características para '.tie5Roanl'?
     * -----------------------------------------------------------------------------
     * 1. Ordena cronológicamente los eventos por tiempo de presión.
     * 2. Si se teclearon los 10 caracteres pero faltó el Enter, sintetiza el evento 11 con la media.
     * 3. Itera sobre los 11 eventos:
     *    - Calcula H_i = release_i - press_i (11 tiempos Hold)
     *    - Calcula DD_i = press_{i+1} - press_i (10 tiempos Down-Down)
     *    - Calcula UD_i = press_{i+1} - release_i (10 tiempos Up-Down)
     * 4. Ajusta estrictamente el resultado a exactamente 31 valores numéricos flotantes.
     * 
     * @param {Array<{code?: string, press: number, release: number}>} events
     * @returns {Array<number>} Vector exacto de 31 números flotantes
     */
    extractVector(events) {
        if (!events || events.length < 2) return [];

        // Ordenar cronológicamente por tiempo de presión
        const sorted = [...events].sort((a, b) => a.press - b.press);

        // Si se capturaron los 10 caracteres de la frase pero se omitió el Enter final,
        // sintetizar la pulsación 11 usando la media de tiempos para asegurar consistencia
        if (sorted.length === 10) {
            const lastEvent = sorted[9];
            let totalHold = 0;
            let totalDD = 0;
            for (let i = 0; i < sorted.length; i++) {
                totalHold += Math.max(0.02, sorted[i].release - sorted[i].press);
                if (i < sorted.length - 1) {
                    totalDD += Math.max(0.04, sorted[i + 1].press - sorted[i].press);
                }
            }
            const avgHold = totalHold / sorted.length;
            const avgDD = totalDD / (sorted.length - 1);
            const synthPress = lastEvent.press + Math.max(0.12, avgDD);
            const synthRelease = synthPress + Math.max(0.08, avgHold);
            sorted.push({
                code: "Enter",
                press: synthPress,
                release: synthRelease
            });
        }

        // Limitar a los 11 eventos clave (10 caracteres + Enter)
        const sampleEvents = sorted.length > 11 ? sorted.slice(0, 11) : sorted;
        const n = sampleEvents.length;

        let vector = [];
        for (let i = 0; i < n; i++) {
            // Tiempo de Retención H_i = t_liberación - t_presión
            const holdTime = Math.max(0.01, sampleEvents[i].release - sampleEvents[i].press);
            vector.push(Number(holdTime.toFixed(6)));

            if (i < n - 1) {
                // Tiempo de Vuelo Tecla a Tecla DD_i = t_presión(i+1) - t_presión(i)
                const ddTime = Math.max(0.01, sampleEvents[i + 1].press - sampleEvents[i].press);
                vector.push(Number(ddTime.toFixed(6)));

                // Tiempo de Transición UD_i = t_presión(i+1) - t_liberación(i)
                const udTime = sampleEvents[i + 1].press - sampleEvents[i].release;
                vector.push(Number(udTime.toFixed(6)));
            }
        }

        // Restricción estricta de dimensionalidad a exactamente 31 valores
        if (vector.length > 31) {
            vector = vector.slice(0, 31);
        } else if (vector.length > 0 && vector.length < 31) {
            const lastVal = vector[vector.length - 1];
            while (vector.length < 31) {
                vector.push(lastVal);
            }
        }

        return vector;
    }

    /**
     * Finaliza la captura de una repetición, valida su longitud y notifica a la SPA.
     * @private
     */
    _processCompletedSample() {
        const events = [...this.currentKeySequence];
        this.clearCurrentSample();

        if (events.length < 2) {
            this.onError("Muestra demasiado corta. Se requieren al menos 2 pulsaciones.");
            return;
        }

        const vector = this.extractVector(events);

        if (vector.length !== 31) {
            this.onError(`Discrepancia en longitud de vector: se esperaban 31 dimensiones y se obtuvieron ${vector.length}. Repite la muestra.`);
            return;
        }

        this.collectedSamples.push(vector);
        const sampleIndex = this.collectedSamples.length;

        this.onSampleCaptured(sampleIndex, this.samplesRequired, vector);

        // Si se reunieron las 3 repeticiones requeridas para enrolamiento (RF-03)
        if (this.collectedSamples.length >= this.samplesRequired) {
            const finalSamples = [...this.collectedSamples];
            this.onEnrollmentReady(finalSamples);
        }
    }

    /**
     * Obtiene el último vector capturado (utilizado para reautenticación activa / modal).
     * @returns {Array<number>|null}
     */
    getLastVector() {
        if (this.collectedSamples.length > 0) {
            return this.collectedSamples[this.collectedSamples.length - 1];
        }
        return null;
    }
}

// Exportar clase al entorno global del navegador
window.KeystrokeCapture = KeystrokeCapture;

