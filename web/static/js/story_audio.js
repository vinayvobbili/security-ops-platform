/**
 * StoryAudio — Data sonification for stepper story modes
 * Uses Web Audio API to create audio cues for step navigation and data values.
 * Loaded as a global script; exposes window.StoryAudio.
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'story-audio-enabled';
    let ctx = null;     // AudioContext (created on first user gesture)
    let enabled = localStorage.getItem(STORAGE_KEY) === 'true';

    function ensureCtx() {
        if (!ctx) {
            ctx = new (window.AudioContext || window.webkitAudioContext)();
        }
        if (ctx.state === 'suspended') ctx.resume();
        return ctx;
    }

    // ── Tone primitives ──────────────────────────────────────

    /**
     * Play a sine tone at a given frequency for a given duration.
     * @param {number} freq  — Hz (200-800 typical range)
     * @param {number} dur   — seconds (0.08-0.3 typical)
     * @param {number} vol   — gain 0-1 (default 0.12, subtle)
     * @param {string} type  — oscillator type (sine, triangle, square)
     */
    function tone(freq, dur = 0.15, vol = 0.12, type = 'sine') {
        if (!enabled) return;
        try {
            const a = ensureCtx();
            const osc = a.createOscillator();
            const gain = a.createGain();
            osc.type = type;
            osc.frequency.setValueAtTime(freq, a.currentTime);
            gain.gain.setValueAtTime(vol, a.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, a.currentTime + dur);
            osc.connect(gain).connect(a.destination);
            osc.start(a.currentTime);
            osc.stop(a.currentTime + dur);
        } catch (_) { /* AudioContext not available */ }
    }

    /** Two-note rising chime */
    function chime(baseFreq, interval = 1.25) {
        tone(baseFreq, 0.12, 0.10, 'triangle');
        setTimeout(() => tone(baseFreq * interval, 0.18, 0.10, 'triangle'), 80);
    }

    // ── Public API ───────────────────────────────────────────

    /**
     * Play a step-transition tone. Pitch rises with step index,
     * giving an auditory sense of progression through the narrative.
     * @param {number} step  — current step index (0-based)
     * @param {number} total — total number of steps
     */
    function playStep(step, total) {
        if (!enabled) return;
        // Map step 0..total-1 to frequency 330..660 Hz (A4 octave range)
        const freq = 330 + (step / Math.max(total - 1, 1)) * 330;
        chime(freq);
    }

    /**
     * Play a brief click for minor interactions (dot click, collapse toggle).
     */
    function playClick() {
        tone(600, 0.06, 0.08, 'sine');
    }

    /**
     * Play a data-mapped tone. Maps a value within [min,max] to a frequency range.
     * Positive sentiment uses a major-third rise; negative uses a minor drop.
     * @param {number} value     — the data value
     * @param {number} min       — range minimum
     * @param {number} max       — range maximum
     * @param {boolean} isGood   — true = improvement, false = regression
     */
    function playDataTone(value, min, max, isGood = true) {
        if (!enabled) return;
        const ratio = Math.max(0, Math.min(1, (value - min) / (Math.max(max - min, 1))));
        const baseFreq = 300 + ratio * 400;
        if (isGood) {
            // Pleasant rising major third
            tone(baseFreq, 0.15, 0.10, 'triangle');
            setTimeout(() => tone(baseFreq * 1.26, 0.20, 0.08, 'triangle'), 100);
        } else {
            // Descending minor feel
            tone(baseFreq, 0.15, 0.10, 'sine');
            setTimeout(() => tone(baseFreq * 0.84, 0.20, 0.10, 'sine'), 100);
        }
    }

    /**
     * Play a completion flourish (last step reached).
     */
    function playComplete() {
        if (!enabled) return;
        const base = 440;
        tone(base, 0.12, 0.10, 'triangle');
        setTimeout(() => tone(base * 1.25, 0.12, 0.10, 'triangle'), 100);
        setTimeout(() => tone(base * 1.5, 0.25, 0.12, 'triangle'), 200);
    }

    // ── Toggle management ────────────────────────────────────

    function isEnabled() { return enabled; }

    function setEnabled(val) {
        enabled = !!val;
        localStorage.setItem(STORAGE_KEY, enabled);
        if (enabled) {
            // Play a confirmation tone when enabling
            playClick();
        }
    }

    function toggle() {
        setEnabled(!enabled);
        return enabled;
    }

    /**
     * Wire a speaker toggle button. Sets initial icon and handles clicks.
     * @param {string|HTMLElement} btnOrId — button element or its ID
     */
    function wireToggleButton(btnOrId) {
        const btn = typeof btnOrId === 'string' ? document.getElementById(btnOrId) : btnOrId;
        if (!btn) return;
        btn.textContent = enabled ? '🔊' : '🔇';
        btn.title = enabled ? 'Mute story audio' : 'Enable story audio';
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            toggle();
            btn.textContent = enabled ? '🔊' : '🔇';
            btn.title = enabled ? 'Mute story audio' : 'Enable story audio';
        });
    }

    // ── Count-up animation ──────────────────────────────────

    /**
     * Animate a number from 0 to target value inside an element.
     * Handles integers, decimals, percentages, time (m:ss), dollar amounts.
     * @param {HTMLElement} el       — element whose textContent will be animated
     * @param {string}      rawText  — final display text, e.g. "1,234", "42.5%", "3:15", "$8,200"
     * @param {number}      duration — ms (default 1200)
     */
    function countUp(el, rawText, duration) {
        if (!el || !rawText) return;
        duration = duration || 1200;
        const text = rawText.toString().trim();

        // Parse: detect prefix ($), suffix (%, h), time format (m:ss)
        const isTime = /^\d+:\d{2}$/.test(text);
        const prefix = text.match(/^([^0-9]*)/)?.[1] || '';
        const suffix = text.match(/([^0-9.,]*)$/)?.[1] || '';
        const numStr = text.replace(/[^0-9.]/g, '');
        const target = parseFloat(numStr) || 0;
        if (target === 0 && !isTime) { el.textContent = rawText; return; }

        const isDecimal = numStr.includes('.');
        const decimals = isDecimal ? (numStr.split('.')[1] || '').length : 0;
        const useCommas = text.includes(',');
        const start = performance.now();

        function frame(now) {
            const elapsed = now - start;
            const progress = Math.min(elapsed / duration, 1);
            // Ease out cubic
            const eased = 1 - Math.pow(1 - progress, 3);
            const current = target * eased;

            if (isTime) {
                // target is total seconds (parsed from m:ss → minutes * 60 + secs)
                const totalSecs = target * eased;
                const rawMins = text.split(':');
                const targetTotalSecs = parseInt(rawMins[0]) * 60 + parseInt(rawMins[1]);
                const curSecs = targetTotalSecs * eased;
                const m = Math.floor(curSecs / 60);
                const s = Math.round(curSecs % 60);
                el.textContent = m + ':' + s.toString().padStart(2, '0');
            } else {
                let display = isDecimal ? current.toFixed(decimals) : Math.round(current).toString();
                if (useCommas) display = Number(isDecimal ? current.toFixed(decimals) : Math.round(current)).toLocaleString(undefined, isDecimal ? {minimumFractionDigits: decimals, maximumFractionDigits: decimals} : {});
                el.textContent = prefix + display + suffix;
            }

            if (progress < 1) requestAnimationFrame(frame);
            else el.textContent = rawText; // Ensure exact final value
        }
        requestAnimationFrame(frame);
    }

    // ── Text-to-Speech (narration) ────────────────────────────

    const NARRATION_KEY = 'story-narration-enabled';
    let narrationEnabled = localStorage.getItem(NARRATION_KEY) === 'true';

    function speak(text) {
        if (!narrationEnabled || !window.speechSynthesis || !text) return;
        window.speechSynthesis.cancel();
        const utter = new SpeechSynthesisUtterance(text);
        utter.rate = 1.0;
        utter.pitch = 1.0;
        utter.volume = 0.8;
        // Pick a natural voice if available
        const voices = window.speechSynthesis.getVoices();
        const preferred = voices.find(v => v.lang.startsWith('en') && v.name.includes('Google')) ||
                          voices.find(v => v.lang.startsWith('en') && v.localService) ||
                          voices.find(v => v.lang.startsWith('en'));
        if (preferred) utter.voice = preferred;
        window.speechSynthesis.speak(utter);
    }

    function stopSpeaking() {
        if (window.speechSynthesis) window.speechSynthesis.cancel();
    }

    function isNarrationEnabled() { return narrationEnabled; }

    function setNarrationEnabled(val) {
        narrationEnabled = !!val;
        localStorage.setItem(NARRATION_KEY, narrationEnabled);
        if (!narrationEnabled) stopSpeaking();
    }

    function toggleNarration() {
        setNarrationEnabled(!narrationEnabled);
        return narrationEnabled;
    }

    /**
     * Wire a narration toggle button. Sets initial icon and handles clicks.
     * @param {string|HTMLElement} btnOrId — button element or its ID
     */
    function wireNarrationButton(btnOrId) {
        const btn = typeof btnOrId === 'string' ? document.getElementById(btnOrId) : btnOrId;
        if (!btn) return;
        btn.textContent = narrationEnabled ? '🗣️' : '🔕';
        btn.title = narrationEnabled ? 'Mute narration' : 'Enable narration (text-to-speech)';
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleNarration();
            btn.textContent = narrationEnabled ? '🗣️' : '🔕';
            btn.title = narrationEnabled ? 'Mute narration' : 'Enable narration (text-to-speech)';
        });
    }

    // ── Expose ───────────────────────────────────────────────

    window.StoryAudio = {
        playStep,
        playClick,
        playDataTone,
        playComplete,
        isEnabled,
        setEnabled,
        toggle,
        wireToggleButton,
        countUp,
        speak,
        stopSpeaking,
        isNarrationEnabled,
        setNarrationEnabled,
        toggleNarration,
        wireNarrationButton
    };
})();
