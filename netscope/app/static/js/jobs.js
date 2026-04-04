/**
 * NETSCOPE Inspection Page Module (Story 4b.7)
 *
 * Handles packet inspection via URL redirection to the packets viewer.
 * The form no longer creates Scapy jobs — it builds filter params and
 * redirects to /packets with those params applied.
 * Job history is displayed in read-only mode.
 *
 * Lessons Learned Epic 1/2/3/4:
 * - IIFE pattern with 'use strict' (rule #5)
 * - Use NetScopeUtils.escapeHtml() for XSS protection (rule #3)
 * - Always check element existence before DOM manipulation (rule #4)
 * - Always if (!response.ok) before JSON parse (rule #6)
 */
(function() {
    'use strict';

    // DOM Elements (rule #4: check existence before manipulation)
    var targetIpEl = document.getElementById('job-target-ip');
    var targetPortEl = document.getElementById('job-target-port');
    var portDirectionEl = document.getElementById('job-port-direction');
    var protocolEl = document.getElementById('job-protocol');
    var inspectBtnEl = document.getElementById('btn-inspect-packets');
    var historyListEl = document.getElementById('jobs-history-list');

    // Use shared utilities from NetScopeUtils
    var escapeHtml = window.NetScopeUtils ? window.NetScopeUtils.escapeHtml : function(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    var showToast = window.NetScopeUtils ? window.NetScopeUtils.showToast : function() {};

    // IP validation regex (rule #13)
    var IP_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

    // Valid port directions (rule #13 - client-side validation)
    var VALID_DIRECTIONS = ['src', 'dst', 'both'];

    // Status display configuration (for history rendering)
    var STATUS_CONFIG = {
        running:   { icon: '<span class="dot-indicator dot-indicator--info"></span>',    label: 'En cours',   class: 'status-running' },
        pending:   { icon: '<span class="dot-indicator dot-indicator--muted"></span>',   label: 'En attente', class: 'status-pending' },
        completed: { icon: '<span class="dot-indicator dot-indicator--normal"></span>',  label: 'Termin\u00e9',    class: 'status-completed' },
        failed:    { icon: '<span class="dot-indicator dot-indicator--critical"></span>', label: '\u00c9chec',      class: 'status-failed' },
        cancelled: { icon: '<span class="dot-indicator dot-indicator--warning"></span>', label: 'Annul\u00e9',     class: 'status-cancelled' }
    };

    /**
     * Build filter URL and redirect to packets viewer (replaces createJob)
     */
    function inspectPackets() {
        if (!targetIpEl) return;

        var ip = targetIpEl.value.trim();
        if (!ip) {
            showToast('Veuillez saisir une adresse IP', 'error');
            return;
        }

        // Client-side IP validation (rule #13)
        if (!IP_PATTERN.test(ip)) {
            showToast('Adresse IP invalide: ' + ip, 'error');
            return;
        }

        var params = ['ip=' + encodeURIComponent(ip)];

        if (targetPortEl && targetPortEl.value) {
            var port = parseInt(targetPortEl.value, 10);
            if (port >= 1 && port <= 65535) {
                params.push('port=' + port);

                // Direction only when port is specified (rule #13)
                if (portDirectionEl && portDirectionEl.value) {
                    var dir = portDirectionEl.value;
                    if (VALID_DIRECTIONS.indexOf(dir) !== -1) {
                        params.push('direction=' + encodeURIComponent(dir));
                    }
                }
            } else {
                showToast('Port invalide (1-65535)', 'error');
                return;
            }
        }

        if (protocolEl && protocolEl.value) {
            params.push('protocol=' + encodeURIComponent(protocolEl.value));
        }

        var url = '/packets?' + params.join('&');
        console.info('[jobs] Redirecting to packets viewer: ' + url);
        window.location.href = url;
    }

    /**
     * Load job history from GET /api/jobs (read-only)
     */
    function loadJobHistory() {
        console.debug('[jobs] Loading job history');

        fetch('/api/jobs')
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP error! status: ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                if (data.success && data.result) {
                    renderHistoryJobs(data.result.jobs || []);
                    console.debug('[jobs] Loaded ' + (data.result.count || 0) + ' jobs (history)');
                }
            })
            .catch(function(error) {
                console.error('[jobs] Error loading job history:', error);
            });
    }

    /**
     * Render all jobs in history (read-only, no stop/cancel buttons)
     * @param {Array} jobs - List of job objects
     */
    function renderHistoryJobs(jobs) {
        if (!historyListEl) return;

        if (jobs.length === 0) {
            historyListEl.innerHTML = '<p class="text-muted text-center">Aucun job ex\u00e9cut\u00e9</p>';
            return;
        }

        var html = '';
        jobs.forEach(function(job) {
            var spec = job.spec || {};
            var result = job.result || {};
            var config = STATUS_CONFIG[job.status] || STATUS_CONFIG.completed;
            if (job.status === 'cancelled' && result.error_message === 'Arr\u00eat\u00e9 manuellement') {
                config = { icon: config.icon, label: 'Arr\u00eat\u00e9', class: config.class };
            }
            var target = escapeHtml(spec.target_ip || '');
            if (spec.target_port) target += ':' + spec.target_port;
            var packets = result.packets_captured || 0;
            var error = result.error_message ? escapeHtml(result.error_message) : '';

            html += '<div class="job-item ' + config.class + '">' +
                '<div class="job-header">' +
                    '<span class="job-status-icon">' + config.icon + '</span>' +
                    '<span class="job-target">' + target + '</span>' +
                    '<span class="job-status-label">' + config.label + '</span>' +
                    '<span class="job-id">' + escapeHtml(job.id || '') + '</span>' +
                '</div>' +
                (job.status === 'completed' ?
                    '<div class="job-result"><span class="packets-count">' + packets + ' paquets captur\u00e9s</span></div>' : '') +
                (error ? '<div class="job-error">' + error + '</div>' : '') +
            '</div>';
        });

        historyListEl.innerHTML = html;
    }

    /**
     * Toggle port direction select based on port field value
     */
    function updatePortDirectionState() {
        if (!portDirectionEl) return;
        var hasPort = targetPortEl && targetPortEl.value.trim() !== '';
        portDirectionEl.disabled = !hasPort;
        if (!hasPort) {
            portDirectionEl.value = 'both';
        }
    }

    /**
     * Initialize the inspection page module
     */
    function init() {
        console.debug('[jobs] Initializing inspection page module');

        // Inspect button handler (redirect to packets viewer)
        if (inspectBtnEl) {
            inspectBtnEl.addEventListener('click', function(e) {
                e.preventDefault();
                inspectPackets();
            });
        }

        // Port field change toggles direction select
        if (targetPortEl) {
            targetPortEl.addEventListener('input', updatePortDirectionState);
        }

        // Load job history (read-only)
        loadJobHistory();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
