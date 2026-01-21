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

    // Detailed results elements
    const resultsSection = document.getElementById('capture-results-section');
    const rawDataSection = document.getElementById('raw-data-section');
    const btnShowRawData = document.getElementById('btn-show-raw-data');
    const btnCloseRawData = document.getElementById('btn-close-raw-data');

    // Well-known port names
    const PORT_NAMES = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
        123: 'NTP', 143: 'IMAP', 161: 'SNMP', 443: 'HTTPS', 465: 'SMTPS',
        587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 27017: 'MongoDB'
    };

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
        if (btnShowRawData) {
            btnShowRawData.addEventListener('click', showRawDataSection);
        }
        if (btnCloseRawData) {
            btnCloseRawData.addEventListener('click', hideRawDataSection);
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

                // Load anomalies after capture results (Story 2.2)
                if (window.loadAnomalies) {
                    window.loadAnomalies();
                }
            }
        } catch (error) {
            console.error('Load result error:', error);
        }
    }

    /**
     * Format bytes to human-readable format (KB/MB/GB)
     */
    function formatBytes(bytes) {
        if (bytes === 0 || bytes === null || bytes === undefined) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    /**
     * Format duration in seconds to human-readable format
     */
    function formatDuration(seconds) {
        if (!seconds) return '0s';
        const mins = Math.floor(seconds / 60);
        const secs = (seconds % 60).toFixed(1);
        return mins > 0 ? mins + 'm ' + secs + 's' : secs + 's';
    }

    /**
     * Get port name if known
     */
    function getPortName(port) {
        return PORT_NAMES[port] || '';
    }

    /**
     * Generate a progress bar HTML
     */
    function createProgressBar(percent) {
        const filled = Math.ceil(percent / 10);
        const empty = 10 - filled;
        return '<span class="progress-bar-inline">' +
            '<span class="progress-filled">' + '\u2588'.repeat(filled) + '</span>' +
            '<span class="progress-empty">' + '\u2591'.repeat(empty) + '</span>' +
            '</span>';
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

            // Update detailed results section
            updateDetailedResults(result.summary);
        }

        // Show results section
        if (resultsSection) {
            showElement(resultsSection);
        }
    }

    /**
     * Update detailed results section
     */
    function updateDetailedResults(summary) {
        // Summary stats
        const totalPackets = document.getElementById('result-total-packets');
        const durationFormatted = document.getElementById('result-duration-formatted');
        const volumeFormatted = document.getElementById('result-volume-formatted');
        const uniqueIps = document.getElementById('result-unique-ips');

        if (totalPackets) totalPackets.textContent = (summary.total_packets || 0).toLocaleString();
        if (durationFormatted) durationFormatted.textContent = formatDuration(summary.duration_actual_seconds);
        if (volumeFormatted) volumeFormatted.textContent = formatBytes(summary.total_bytes);
        if (uniqueIps) uniqueIps.textContent = summary.unique_ips || 0;

        // Top IPs table
        updateTopIpsTable(summary.top_ips || []);

        // Top Ports table
        updateTopPortsTable(summary.top_ports || []);

        // Protocols distribution
        updateProtocolsBars(summary.protocols || {}, summary.bytes_per_protocol || {}, summary.total_packets || 0);
    }

    /**
     * Update top IPs table
     */
    function updateTopIpsTable(topIps) {
        const tbody = document.getElementById('top-ips-table-body');
        if (!tbody) return;

        if (!topIps || topIps.length === 0) {
            tbody.innerHTML = '<tr class="placeholder-row"><td colspan="3" class="text-muted text-center">Aucune donn\u00e9e</td></tr>';
            return;
        }

        const maxCount = topIps[0]?.count || 1;
        let html = '';

        topIps.slice(0, 5).forEach(function(item) {
            const percent = Math.round((item.count / maxCount) * 100);
            html += '<tr>' +
                '<td class="ip-cell">' + item.ip + '</td>' +
                '<td class="count-cell">' + item.count + '</td>' +
                '<td class="bar-cell">' + createProgressBar(percent) + '</td>' +
                '</tr>';
        });

        tbody.innerHTML = html;
    }

    /**
     * Update top ports table
     */
    function updateTopPortsTable(topPorts) {
        const tbody = document.getElementById('top-ports-table-body');
        if (!tbody) return;

        if (!topPorts || topPorts.length === 0) {
            tbody.innerHTML = '<tr class="placeholder-row"><td colspan="3" class="text-muted text-center">Aucune donn\u00e9e</td></tr>';
            return;
        }

        const maxCount = topPorts[0]?.count || 1;
        let html = '';

        topPorts.slice(0, 5).forEach(function(item) {
            const percent = Math.round((item.count / maxCount) * 100);
            const portName = getPortName(item.port);
            const portDisplay = portName ? item.port + ' (' + portName + ')' : item.port;

            html += '<tr>' +
                '<td class="port-cell">' + portDisplay + '</td>' +
                '<td class="count-cell">' + item.count + '</td>' +
                '<td class="bar-cell">' + createProgressBar(percent) + '</td>' +
                '</tr>';
        });

        tbody.innerHTML = html;
    }

    /**
     * Update protocols distribution bars
     */
    function updateProtocolsBars(protocols, bytesPerProtocol, totalPackets) {
        const container = document.getElementById('protocols-bars');
        if (!container) return;

        const protoKeys = Object.keys(protocols);
        if (protoKeys.length === 0) {
            container.innerHTML = '<div class="protocol-placeholder text-muted text-center">Aucune donn\u00e9e</div>';
            return;
        }

        let html = '';
        protoKeys.forEach(function(proto) {
            const count = protocols[proto] || 0;
            const bytes = bytesPerProtocol[proto] || 0;
            const percent = totalPackets > 0 ? Math.round((count / totalPackets) * 100) : 0;

            html += '<div class="protocol-bar-item">' +
                '<span class="protocol-name">' + proto + '</span>' +
                '<div class="protocol-bar-container">' +
                '<div class="protocol-bar-fill" style="width: ' + percent + '%;"></div>' +
                '</div>' +
                '<span class="protocol-percent">' + percent + '%</span>' +
                '<span class="protocol-count">' + count + ' pkts</span>' +
                '<span class="protocol-bytes">' + formatBytes(bytes) + '</span>' +
                '</div>';
        });

        container.innerHTML = html;
    }

    /**
     * Update stats cards with capture data
     */
    function updateStatsCards(summary) {
        if (!summary) return;

        const topIps = document.getElementById('stat-top-ips');
        const topIpsList = document.getElementById('stat-top-ips-list');
        const protocols = document.getElementById('stat-protocols');
        const protocolsList = document.getElementById('stat-protocols-list');
        const ports = document.getElementById('stat-ports');
        const topPortsList = document.getElementById('stat-top-ports-list');
        const volume = document.getElementById('stat-volume');
        const volumeBytes = document.getElementById('stat-volume-bytes');

        // Top IPs card
        if (topIps) {
            topIps.textContent = summary.unique_ips || '--';
        }
        if (topIpsList && summary.top_ips && summary.top_ips.length > 0) {
            const topIp = summary.top_ips[0];
            topIpsList.innerHTML = '<span class="detail-item">#1: ' + topIp.ip + ' (' + topIp.count + ')</span>';
        }

        // Protocols card
        if (protocols && summary.protocols) {
            const protoList = Object.keys(summary.protocols);
            protocols.textContent = protoList.length > 0 ? protoList.length : '--';
        }
        if (protocolsList && summary.protocols) {
            const protoList = Object.keys(summary.protocols);
            protocolsList.innerHTML = '<span class="detail-item">' + (protoList.length > 0 ? protoList.join(', ') : '--') + '</span>';
        }

        // Ports card
        if (ports) {
            ports.textContent = summary.unique_ports || '--';
        }
        if (topPortsList && summary.top_ports && summary.top_ports.length > 0) {
            const topPort = summary.top_ports[0];
            const portName = getPortName(topPort.port);
            const display = portName ? topPort.port + ' (' + portName + ')' : topPort.port;
            topPortsList.innerHTML = '<span class="detail-item">#1: ' + display + '</span>';
        }

        // Volume card
        if (volume) {
            const pkts = summary.total_packets || 0;
            volume.textContent = pkts > 1000 ? Math.round(pkts / 1000) + 'k pkts' : pkts + ' pkts';
        }
        if (volumeBytes) {
            volumeBytes.innerHTML = '<span class="detail-item">' + formatBytes(summary.total_bytes) + '</span>';
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

    /**
     * Show raw data section and load packets
     */
    async function showRawDataSection() {
        if (rawDataSection) {
            showElement(rawDataSection);
            await loadRawPackets();
        }
    }

    /**
     * Hide raw data section
     */
    function hideRawDataSection() {
        if (rawDataSection) {
            hideElement(rawDataSection);
        }
    }

    /**
     * Load raw packets from API
     */
    async function loadRawPackets() {
        const tbody = document.getElementById('raw-data-table-body');
        if (!tbody) return;

        tbody.innerHTML = '<tr class="placeholder-row"><td colspan="7" class="text-muted text-center">Chargement...</td></tr>';

        try {
            const response = await fetch('/api/captures/latest?parse=true&include_packets=true&limit=100');
            const data = await response.json();

            if (data.success && data.packets && data.packets.length > 0) {
                updateRawDataTable(data.packets);
            } else {
                tbody.innerHTML = '<tr class="placeholder-row"><td colspan="7" class="text-muted text-center">Aucun paquet disponible</td></tr>';
            }
        } catch (error) {
            console.error('Load raw packets error:', error);
            tbody.innerHTML = '<tr class="placeholder-row"><td colspan="7" class="text-muted text-center">Erreur de chargement</td></tr>';
        }
    }

    /**
     * Update raw data table with packets
     */
    function updateRawDataTable(packets) {
        const tbody = document.getElementById('raw-data-table-body');
        if (!tbody) return;

        if (!packets || packets.length === 0) {
            tbody.innerHTML = '<tr class="placeholder-row"><td colspan="7" class="text-muted text-center">Aucun paquet</td></tr>';
            return;
        }

        let html = '';
        packets.slice(0, 100).forEach(function(pkt) {
            let timestamp = '--';
            if (pkt.timestamp) {
                const dateObj = new Date(pkt.timestamp);
                if (!isNaN(dateObj.getTime())) {
                    timestamp = dateObj.toLocaleTimeString();
                }
            }
            html += '<tr>' +
                '<td class="timestamp-cell">' + timestamp + '</td>' +
                '<td class="ip-cell">' + (pkt.ip_src || '--') + '</td>' +
                '<td class="ip-cell">' + (pkt.ip_dst || '--') + '</td>' +
                '<td class="port-cell">' + (pkt.port_src || '--') + '</td>' +
                '<td class="port-cell">' + (pkt.port_dst || '--') + '</td>' +
                '<td class="proto-cell">' + (pkt.protocol || '--') + '</td>' +
                '<td class="size-cell">' + (pkt.length || 0) + ' B</td>' +
                '</tr>';
        });

        tbody.innerHTML = html;
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();

/**
 * NETSCOPE Anomaly Display Module (Story 2.2)
 *
 * Handles anomaly display in the dashboard.
 */
(function() {
    'use strict';

    // DOM Elements
    const anomaliesSection = document.getElementById('anomalies-section');
    const anomaliesList = document.getElementById('anomalies-list');
    const anomaliesCount = document.getElementById('anomalies-count');
    const anomaliesCritical = document.getElementById('anomalies-critical');
    const anomaliesWarning = document.getElementById('anomalies-warning');

    // Criticality icons and labels
    const CRITICALITY_CONFIG = {
        critical: {
            icon: '\u{1F534}',  // Red circle
            label: 'CRITICAL',
            class: 'anomaly-critical'
        },
        warning: {
            icon: '\u{1F7E1}',  // Yellow circle
            label: 'ATTENTION',
            class: 'anomaly-warning'
        },
        normal: {
            icon: '\u{1F7E2}',  // Green circle
            label: 'NORMAL',
            class: 'anomaly-normal'
        }
    };

    /**
     * Load anomalies from API
     */
    async function loadAnomalies() {
        try {
            const response = await fetch('/api/anomalies?latest=true');
            const data = await response.json();

            if (data.success && data.result) {
                updateAnomaliesDisplay(data.result);
            }
        } catch (error) {
            console.error('Load anomalies error:', error);
        }
    }

    /**
     * Update anomalies display with data
     */
    function updateAnomaliesDisplay(result) {
        const anomalies = result.anomalies || [];
        const byCriticality = result.by_criticality || {};

        // Update counts
        if (anomaliesCount) {
            anomaliesCount.textContent = result.total || 0;
        }
        if (anomaliesCritical) {
            anomaliesCritical.textContent = byCriticality.critical || 0;
        }
        if (anomaliesWarning) {
            anomaliesWarning.textContent = byCriticality.warning || 0;
        }

        // Show/hide section based on anomalies
        if (anomaliesSection) {
            if (result.total > 0) {
                anomaliesSection.style.display = '';
            } else {
                anomaliesSection.style.display = 'none';
            }
        }

        // Update list
        if (anomaliesList) {
            if (anomalies.length === 0) {
                anomaliesList.innerHTML = '<p class="text-muted text-center">Aucune anomalie d\u00e9tect\u00e9e</p>';
                return;
            }

            let html = '';
            anomalies.forEach(function(anomaly) {
                html += createAnomalyCard(anomaly);
            });
            anomaliesList.innerHTML = html;
        }
    }

    /**
     * Create HTML for an anomaly card
     */
    function createAnomalyCard(anomaly) {
        const config = CRITICALITY_CONFIG[anomaly.criticality] || CRITICALITY_CONFIG.normal;
        const packetInfo = anomaly.packet_info || {};

        let connectionInfo = '';
        if (packetInfo.ip_src && packetInfo.ip_dst) {
            const srcPort = packetInfo.port_src ? ':' + packetInfo.port_src : '';
            const dstPort = packetInfo.port_dst ? ':' + packetInfo.port_dst : '';
            connectionInfo = packetInfo.ip_src + srcPort + ' \u2192 ' + packetInfo.ip_dst + dstPort;
            if (packetInfo.protocol) {
                connectionInfo += ' (' + packetInfo.protocol + ')';
            }
        }

        return '<div class="anomaly-card ' + config.class + '">' +
            '<div class="anomaly-header">' +
            '<span class="anomaly-icon">' + config.icon + '</span>' +
            '<span class="anomaly-value">' + escapeHtml(anomaly.matched_value) + '</span>' +
            '<span class="anomaly-badge">' + config.label + '</span>' +
            '</div>' +
            '<div class="anomaly-details">' +
            '<span class="anomaly-type">' + getMatchTypeLabel(anomaly.match_type) + '</span>' +
            (anomaly.source_file ? ' <span class="anomaly-source">(' + escapeHtml(anomaly.source_file) + ')</span>' : '') +
            '</div>' +
            (connectionInfo ? '<div class="anomaly-connection">\u2192 ' + escapeHtml(connectionInfo) + '</div>' : '') +
            '</div>';
    }

    /**
     * Get human-readable match type label
     */
    function getMatchTypeLabel(matchType) {
        switch (matchType) {
            case 'ip': return 'IP blacklist\u00e9e';
            case 'domain': return 'Domaine blacklist\u00e9';
            case 'term': return 'Terme suspect';
            default: return 'Anomalie';
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Expose loadAnomalies globally for use after capture completion
    window.loadAnomalies = loadAnomalies;

    // Load anomalies on page load if there might be existing data
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', loadAnomalies);
    } else {
        loadAnomalies();
    }
})();

/**
 * NETSCOPE Blacklist Control Module
 *
 * Handles blacklist stats display and reload operations.
 */
(function() {
    'use strict';

    // DOM Elements
    const btnReload = document.getElementById('btn-reload-blacklists');
    const ipsCount = document.getElementById('blacklist-ips-count');
    const domainsCount = document.getElementById('blacklist-domains-count');
    const termsCount = document.getElementById('blacklist-terms-count');
    const totalCount = document.getElementById('blacklist-total');

    /**
     * Initialize blacklist controls
     */
    function init() {
        if (btnReload) {
            btnReload.addEventListener('click', reloadBlacklists);
        }
    }

    /**
     * Reload blacklists from server
     */
    async function reloadBlacklists() {
        if (!btnReload) return;

        // Show loading state
        btnReload.classList.add('loading');
        btnReload.disabled = true;
        const originalText = btnReload.innerHTML;
        btnReload.innerHTML = '&#8987; Chargement...';

        try {
            const response = await fetch('/api/blacklists/reload', {
                method: 'POST'
            });

            const data = await response.json();

            if (data.success) {
                // Update stats display
                updateBlacklistStats(data.result);
                showToast('success', 'Blacklists recharg\u00e9es avec succ\u00e8s');
            } else {
                showToast('error', data.error.message || 'Erreur de rechargement');
            }
        } catch (error) {
            console.error('Blacklist reload error:', error);
            showToast('error', 'Erreur de connexion au serveur');
        } finally {
            // Reset button state
            btnReload.classList.remove('loading');
            btnReload.disabled = false;
            btnReload.innerHTML = originalText;
        }
    }

    /**
     * Update blacklist stats display
     */
    function updateBlacklistStats(stats) {
        if (ipsCount) ipsCount.textContent = stats.ips_count || 0;
        if (domainsCount) domainsCount.textContent = stats.domains_count || 0;
        if (termsCount) termsCount.textContent = stats.terms_count || 0;
        if (totalCount) totalCount.textContent = stats.total_entries || 0;
    }

    /**
     * Show a toast notification
     */
    function showToast(type, message) {
        // Check if toast container exists, create if not
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        // Create toast element
        const toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.textContent = message;
        container.appendChild(toast);

        // Show toast
        setTimeout(function() {
            toast.classList.add('toast-visible');
        }, 10);

        // Hide and remove toast after 3 seconds
        setTimeout(function() {
            toast.classList.remove('toast-visible');
            setTimeout(function() {
                toast.remove();
            }, 300);
        }, 3000);
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
