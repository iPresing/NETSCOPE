/**
 * NETSCOPE Capture Control Module
 *
 * Handles network capture operations via the REST API.
 */

(function() {
    'use strict';

    // DOM Elements
    const btnStart = document.getElementById('btn-start-capture');
    const btnStop = document.getElementById('btn-stop-capture');
    const captureInterface = document.getElementById('capture-interface');
    const captureDuration = document.getElementById('capture-duration');
    const captureFilter = document.getElementById('capture-filter');
    const statusDiv = document.getElementById('capture-status');
    const resultDiv = document.getElementById('capture-result');
    const errorDiv = document.getElementById('capture-error');
    const timerSpan = document.getElementById('capture-timer');

    // State
    let captureTimer = null;
    let elapsedSeconds = 0;
    let statusPollInterval = null;

    /**
     * Initialize capture controls
     */
    function init() {
        if (btnStart) {
            btnStart.addEventListener('click', startCapture);
        }
        if (btnStop) {
            btnStop.addEventListener('click', stopCapture);
        }

        // Check initial status
        checkCaptureStatus();
    }

    /**
     * Start a new capture
     */
    async function startCapture() {
        const config = {
            duration: parseInt(captureDuration.value, 10),
            interface: captureInterface.value,
            bpf_filter: captureFilter.value
        };

        // Hide previous results/errors
        hideElement(resultDiv);
        hideElement(errorDiv);

        try {
            btnStart.disabled = true;

            const response = await fetch('/api/captures/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });

            const data = await response.json();

            if (data.success) {
                showCaptureRunning();
                startTimer();
                startStatusPolling();
            } else {
                showError(data.error.message || 'Erreur de capture');
                btnStart.disabled = false;
            }
        } catch (error) {
            console.error('Capture start error:', error);
            showError('Erreur de connexion au serveur');
            btnStart.disabled = false;
        }
    }

    /**
     * Stop the current capture
     */
    async function stopCapture() {
        try {
            btnStop.disabled = true;

            const response = await fetch('/api/captures/stop', {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                stopTimer();
                stopStatusPolling();
                await loadLatestResult();
                showCaptureComplete();
            } else {
                showError(data.error.message || 'Erreur lors de l\'arrêt');
            }
        } catch (error) {
            console.error('Capture stop error:', error);
            showError('Erreur de connexion au serveur');
        } finally {
            btnStop.disabled = false;
        }
    }

    /**
     * Check current capture status
     */
    async function checkCaptureStatus() {
        try {
            const response = await fetch('/api/captures/status');
            const data = await response.json();

            if (data.success && data.session) {
                if (data.status === 'running') {
                    showCaptureRunning();
                    // Calculate elapsed time from start_time
                    if (data.session.start_time) {
                        const startTime = new Date(data.session.start_time);
                        elapsedSeconds = Math.floor((Date.now() - startTime.getTime()) / 1000);
                        updateTimerDisplay();
                    }
                    startTimer();
                    startStatusPolling();
                } else if (data.status === 'completed' || data.status === 'stopped') {
                    await loadLatestResult();
                    showCaptureComplete();
                }
            }
        } catch (error) {
            console.error('Status check error:', error);
        }
    }

    /**
     * Load latest capture results
     */
    async function loadLatestResult() {
        try {
            const response = await fetch('/api/captures/latest?parse=true');
            const data = await response.json();

            if (data.success && data.result) {
                updateResultDisplay(data.result);
                updateStatsCards(data.result.summary);
            }
        } catch (error) {
            console.error('Load result error:', error);
        }
    }

    /**
     * Update result display with capture data
     */
    function updateResultDisplay(result) {
        const packets = document.getElementById('result-packets');
        const duration = document.getElementById('result-duration');
        const ips = document.getElementById('result-ips');

        if (result.summary) {
            if (packets) packets.textContent = result.summary.total_packets + ' paquets';
            if (duration) duration.textContent = Math.round(result.summary.duration_actual_seconds || 0) + 's';
            if (ips) ips.textContent = result.summary.unique_ips + ' IPs';
        }
    }

    /**
     * Update stats cards with capture data
     */
    function updateStatsCards(summary) {
        if (!summary) return;

        const topIps = document.getElementById('stat-top-ips');
        const protocols = document.getElementById('stat-protocols');
        const ports = document.getElementById('stat-ports');
        const volume = document.getElementById('stat-volume');

        if (topIps) {
            topIps.textContent = summary.unique_ips || '--';
        }

        if (protocols && summary.protocols) {
            const protoList = Object.keys(summary.protocols);
            protocols.textContent = protoList.length > 0 ? protoList.join(', ') : '--';
        }

        if (ports) {
            ports.textContent = summary.unique_ports || '--';
        }

        if (volume) {
            const pkts = summary.total_packets || 0;
            volume.textContent = pkts > 1000 ? Math.round(pkts / 1000) + 'k pkts' : pkts + ' pkts';
        }
    }

    /**
     * Show capture running state
     */
    function showCaptureRunning() {
        hideElement(btnStart);
        showElement(btnStop);
        showElement(statusDiv);
        hideElement(resultDiv);
        hideElement(errorDiv);

        // Disable form controls
        captureInterface.disabled = true;
        captureDuration.disabled = true;
        captureFilter.disabled = true;
    }

    /**
     * Show capture complete state
     */
    function showCaptureComplete() {
        showElement(btnStart);
        hideElement(btnStop);
        hideElement(statusDiv);
        showElement(resultDiv);
        hideElement(errorDiv);

        // Enable form controls
        captureInterface.disabled = false;
        captureDuration.disabled = false;
        captureFilter.disabled = false;
        btnStart.disabled = false;
    }

    /**
     * Show error message
     */
    function showError(message) {
        const errorMsg = document.getElementById('error-message');
        if (errorMsg) {
            errorMsg.textContent = message;
        }
        showElement(errorDiv);
        showElement(btnStart);
        hideElement(btnStop);
        hideElement(statusDiv);

        // Enable form controls
        captureInterface.disabled = false;
        captureDuration.disabled = false;
        captureFilter.disabled = false;
    }

    /**
     * Start the capture timer
     */
    function startTimer() {
        stopTimer(); // Clear any existing timer
        captureTimer = setInterval(function() {
            elapsedSeconds++;
            updateTimerDisplay();
        }, 1000);
    }

    /**
     * Stop the capture timer
     */
    function stopTimer() {
        if (captureTimer) {
            clearInterval(captureTimer);
            captureTimer = null;
        }
        elapsedSeconds = 0;
    }

    /**
     * Update timer display
     */
    function updateTimerDisplay() {
        if (timerSpan) {
            timerSpan.textContent = elapsedSeconds + 's';
        }
    }

    /**
     * Start polling for status updates
     */
    function startStatusPolling() {
        stopStatusPolling(); // Clear any existing polling
        statusPollInterval = setInterval(async function() {
            try {
                const response = await fetch('/api/captures/status');
                const data = await response.json();

                if (data.success) {
                    if (data.status !== 'running') {
                        stopTimer();
                        stopStatusPolling();
                        await loadLatestResult();
                        showCaptureComplete();
                    }
                }
            } catch (error) {
                console.error('Status poll error:', error);
            }
        }, 2000); // Poll every 2 seconds
    }

    /**
     * Stop polling for status updates
     */
    function stopStatusPolling() {
        if (statusPollInterval) {
            clearInterval(statusPollInterval);
            statusPollInterval = null;
        }
    }

    /**
     * Show an element
     */
    function showElement(el) {
        if (el) el.style.display = '';
    }

    /**
     * Hide an element
     */
    function hideElement(el) {
        if (el) el.style.display = 'none';
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
