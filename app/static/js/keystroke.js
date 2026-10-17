/**
 * KeystrokeCapture - High-Resolution Keystroke Dynamics Timing Engine
 * Zero Trust Biometric Continuous Authentication (Thesis Section 3.6.3 & RNF-08)
 *
 * Enforces strict RNF-08 Data Minimization & Privacy:
 * - Employs window.performance.now() with sub-millisecond precision converted to seconds.
 * - Extracts physical hold durations (H), Down-Down latencies (DD), and Up-Down flight times (UD).
 * - NEVER processes, logs, or transmits key characters, letters, or plaintext strings to the backend.
 */

class KeystrokeCapture {
    /**
     * @param {Object} options Configuration parameters
     * @param {string} options.targetPhrase Expected target phrase reference (e.g., '.tie5Roanl')
     * @param {number} options.samplesRequired Number of repetitions needed for enrollment (default: 3)
     * @param {boolean} options.requireEnter Whether the Return/Enter key is required to complete the sample (default: true)
     * @param {Function} options.onKeypress Callback fired on each keypress: (currentKeys, targetKeys)
     * @param {Function} options.onSampleCaptured Callback fired on repetition completion: (sampleIndex, totalSamples, vector)
     * @param {Function} options.onEnrollmentReady Callback fired when all repetitions are collected: (samples)
     * @param {Function} options.onError Callback fired on error or inconsistency: (errorMessage)
     */
    constructor(options = {}) {
        this.targetPhrase = options.targetPhrase || ".tie5Roanl";
        this.samplesRequired = options.samplesRequired || 3;
        this.requireEnter = options.requireEnter !== undefined ? options.requireEnter : true;

        // Total expected key events: phrase length + 1 (Enter) if requireEnter is true
        this.expectedKeyCount = this.targetPhrase.length + (this.requireEnter ? 1 : 0);

        this.onKeypress = options.onKeypress || (() => {});
        this.onSampleCaptured = options.onSampleCaptured || (() => {});
        this.onEnrollmentReady = options.onEnrollmentReady || (() => {});
        this.onError = options.onError || (() => {});

        // Internal recording state
        this.inputElement = null;
        this.activeKeys = new Map(); // keyIdentifier -> press timestamp in seconds
        this.currentKeySequence = []; // List of { press: float, release: float }
        this.collectedSamples = []; // List of feature vectors for enrollment

        this._boundKeyDown = this._handleKeyDown.bind(this);
        this._boundKeyUp = this._handleKeyUp.bind(this);
    }

    /**
     * Attaches capture listeners to an HTML input or textarea element.
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
     * Detaches listeners and frees resources.
     */
    detach() {
        if (this.inputElement) {
            this.inputElement.removeEventListener("keydown", this._boundKeyDown);
            this.inputElement.removeEventListener("keyup", this._boundKeyUp);
            this.inputElement = null;
        }
    }

    /**
     * Resets the entire capture session, clearing all samples and input buffers.
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
     * Clears only the current single repetition buffer (e.g. after backspace or error).
     */
    clearCurrentSample() {
        this.activeKeys.clear();
        this.currentKeySequence = [];
        if (this.inputElement) {
            this.inputElement.value = "";
        }
    }

    /**
     * Internal keydown event listener with sub-millisecond precision.
     * @private
     */
    _handleKeyDown(event) {
        // Discard auto-repeat events caused by holding keys down
        if (event.repeat) return;

        // If backspace is pressed, reset the current sample to maintain clean timing vectors
        if (event.key === "Backspace" || event.key === "Escape") {
            this.clearCurrentSample();
            this.onError("Pulsación corregida con tecla de borrado. Muestra actual reiniciada.");
            return;
        }

        // Record high-precision timestamp converted from milliseconds to seconds
        const pressTimeSec = performance.now() / 1000.0;

        // Use a unique tracking key for key-down/up matching
        const keyId = `${event.code}_${this.currentKeySequence.length}`;
        this.activeKeys.set(keyId, pressTimeSec);

        this.onKeypress(this.currentKeySequence.length + 1, this.expectedKeyCount);
    }

    /**
     * Internal keyup event listener.
     * @private
     */
    _handleKeyUp(event) {
        const releaseTimeSec = performance.now() / 1000.0;

        // Find corresponding unreleased keypress
        const matchedEntry = Array.from(this.activeKeys.entries())
            .find(([k]) => k.startsWith(`${event.code}_`));

        if (!matchedEntry) return;

        const [keyId, pressTimeSec] = matchedEntry;
        this.activeKeys.delete(keyId);

        // Store pure timing tuple without characters or key names (RNF-08 Data Minimization)
        this.currentKeySequence.push({
            press: pressTimeSec,
            release: releaseTimeSec
        });

        // Check if sample completion condition is met
        const isEnterPressed = (event.key === "Enter" || event.code === "Enter");
        const reachedKeyCount = this.currentKeySequence.length >= this.expectedKeyCount;

        if ((this.requireEnter && isEnterPressed) || (!this.requireEnter && reachedKeyCount)) {
            this._processCompletedSample();
        }
    }

    /**
     * Extracts timing feature vector from raw key events: [H0, DD01, UD01, H1, ...].
     * Compatible with the backend extract_features_from_events (3n - 2 dimensions).
     * @param {Array<{press: number, release: number}>} events
     * @returns {Array<number>}
     */
    extractVector(events) {
        const n = events.length;
        if (n < 2) return [];

        const vector = [];
        for (let i = 0; i < n; i++) {
            // Hold duration H_i = release_i - press_i
            const holdTime = Math.max(0.01, events[i].release - events[i].press);
            vector.push(Number(holdTime.toFixed(6)));

            if (i < n - 1) {
                // Down-Down latency: press_{i+1} - press_i
                const ddTime = Math.max(0.01, events[i + 1].press - events[i].press);
                vector.push(Number(ddTime.toFixed(6)));

                // Up-Down flight time: press_{i+1} - release_i (can be negative on rollover)
                const udTime = events[i + 1].press - events[i].release;
                vector.push(Number(udTime.toFixed(6)));
            }
        }
        return vector;
    }

    /**
     * Finalizes the current repetition, computes vector, and triggers callbacks.
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

        // Verify dimension consistency if multiple samples are being collected
        if (this.collectedSamples.length > 0) {
            const expectedDim = this.collectedSamples[0].length;
            if (vector.length !== expectedDim) {
                this.onError(`Discrepancia en longitud de tecleo: se esperaban ${expectedDim} valores y se obtuvieron ${vector.length}. Por favor repite la muestra.`);
                return;
            }
        }

        this.collectedSamples.push(vector);
        const sampleIndex = this.collectedSamples.length;

        this.onSampleCaptured(sampleIndex, this.samplesRequired, vector);

        if (this.collectedSamples.length >= this.samplesRequired) {
            const finalSamples = [...this.collectedSamples];
            this.onEnrollmentReady(finalSamples);
        }
    }

    /**
     * Gets the last captured sample vector (useful for single-shot verification / challenge modal).
     * @returns {Array<number>|null}
     */
    getLastVector() {
        if (this.collectedSamples.length > 0) {
            return this.collectedSamples[this.collectedSamples.length - 1];
        }
        return null;
    }
}

// Export for browser global scope
window.KeystrokeCapture = KeystrokeCapture;
