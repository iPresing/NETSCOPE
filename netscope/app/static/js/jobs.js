/**
 * NETSCOPE Jobs Page Module (Story 4.1)
 *
 * Handles inspection job creation, listing, and real-time updates.
 * Consumes API endpoints POST/GET /api/jobs
 *
 * Lessons Learned Epic 1/2/3:
 * - IIFE pattern with 'use strict' (rule #5)
 * - Use NetScopeUtils.escapeHtml() for XSS protection (rule #3)
 * - Always check element existence before DOM manipulation (rule #4)
 * - Always if (!response.ok) before JSON parse (rule #6)
 * - Polling/auto-refresh for real-time widgets (rule #10)
 */
(function() {
    'use strict';

    // DOM Elements
    var targetIpEl = document.getElementById('job-target-ip');
    var targetPortEl = document.getElementById('job-target-port');
    var protocolEl = document.getElementById('job-protocol');
    var durationEl = document.getElementById('job-duration');
    var createBtnEl = document.getElementById('btn-create-job');
    var activeListEl = document.getElementById('jobs-active-list');
    var queueListEl = document.getElementById('jobs-queue-list');
    var historyListEl = document.getElementById('jobs-history-list');

    // Polling interval (rule #10)
    var POLL_INTERVAL_MS = 3000;
    var pollTimer = null;

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

    // Status display configuration
    var STATUS_CONFIG = {
        running:   { icon: '\uD83D\uDD04', label: 'En cours',  class: 'status-running' },
        pending:   { icon: '\u23F3',        label: 'En attente', class: 'status-pending' },
        completed: { icon: '\u2705',        label: 'Termine',    class: 'status-completed' },
        failed:    { icon: '\u274C',        label: 'Echec',      class: 'status-failed' },
        cancelled: { icon: '\u26D4',        label: 'Annule',     class: 'status-cancelled' }
    };

    /**
     * Create a job via POST /api/jobs
     */
    function createJob() {
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

        var body = { target_ip: ip };

        if (targetPortEl && targetPortEl.value) {
            var port = parseInt(targetPortEl.value, 10);
            if (port >= 1 && port <= 65535) {
                body.target_port = port;
            }
        }

        if (protocolEl && protocolEl.value) {
            body.protocol = protocolEl.value;
        }

        if (durationEl && durationEl.value) {
            var duration = parseInt(durationEl.value, 10);
            if (duration >= 5 && duration <= 120) {
                body.duration = duration;
            }
        }

        if (createBtnEl) {
            createBtnEl.disabled = true;
            createBtnEl.textContent = '\u23F3 Lancement...';
        }

        fetch('/api/jobs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        })
        .then(function(response) {
            if (!response.ok) {
                return response.json().then(function(err) { throw err; });
            }
            return response.json();
        })
        .then(function(data) {
            if (data.success) {
                showToast('Job cree - inspection en cours', 'success');
                console.info('[jobs] Job created (job_id=' + data.result.id + ')');
                // Reset form
                if (targetIpEl) targetIpEl.value = '';
                if (targetPortEl) targetPortEl.value = '';
                if (protocolEl) protocolEl.value = '';
                if (durationEl) durationEl.value = '30';
                loadJobs();
            }
        })
        .catch(function(error) {
            var msg = error.error ? error.error.message : 'Erreur lors du lancement';
            showToast(msg, 'error');
        })
        .finally(function() {
            if (createBtnEl) {
                createBtnEl.disabled = false;
                createBtnEl.innerHTML = '<span class="btn-icon">\uD83D\uDD2C</span> Lancer Inspection';
            }
        });
    }

    /**
     * Load all jobs from GET /api/jobs
     */
    function loadJobs() {
        console.debug('[jobs] Loading jobs list');

        fetch('/api/jobs')
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP error! status: ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                if (data.success && data.result) {
                    renderJobs(data.result.jobs || []);
                    console.debug('[jobs] Loaded ' + (data.result.count || 0) + ' jobs (slots=' + data.result.available_slots + ')');
                }
            })
            .catch(function(error) {
                console.error('[jobs] Error loading jobs:', error);
            });
    }

    /**
     * Render jobs into the three sections: active, queue, history
     * @param {Array} jobs - List of job objects
     */
    function renderJobs(jobs) {
        var active = [];
        var pending = [];
        var history = [];

        jobs.forEach(function(job) {
            switch (job.status) {
                case 'running':
                    active.push(job);
                    break;
                case 'pending':
                    pending.push(job);
                    break;
                default:
                    history.push(job);
            }
        });

        renderActiveJobs(active);
        renderQueueJobs(pending);
        renderHistoryJobs(history);

        // Start/stop polling based on active jobs
        if (active.length > 0 || pending.length > 0) {
            startPolling();
        } else {
            stopPolling();
        }
    }

    /**
     * Render active (running) jobs
     * @param {Array} jobs - Running jobs
     */
    function renderActiveJobs(jobs) {
        if (!activeListEl) return;

        if (jobs.length === 0) {
            activeListEl.innerHTML = '<p class="text-muted text-center">Aucun job en cours d\'execution</p>';
            return;
        }

        var html = '';
        jobs.forEach(function(job) {
            var spec = job.spec || {};
            var target = escapeHtml(spec.target_ip || '');
            if (spec.target_port) target += ':' + spec.target_port;
            var config = STATUS_CONFIG[job.status] || STATUS_CONFIG.running;

            html += '<div class="job-item ' + config.class + '">' +
                '<div class="job-header">' +
                    '<span class="job-status-icon">' + config.icon + '</span>' +
                    '<span class="job-target">' + target + '</span>' +
                    '<span class="job-id">' + escapeHtml(job.id || '') + '</span>' +
                '</div>' +
                '<div class="job-progress">' +
                    '<div class="progress-bar">' +
                        '<div class="progress-fill running" style="width: ' + (job.progress_percent || 0) + '%;"></div>' +
                    '</div>' +
                    '<span class="progress-text">' + (job.progress_percent || 0) + '%</span>' +
                '</div>' +
            '</div>';
        });

        activeListEl.innerHTML = html;
    }

    /**
     * Render pending (queued) jobs
     * @param {Array} jobs - Pending jobs
     */
    function renderQueueJobs(jobs) {
        if (!queueListEl) return;

        if (jobs.length === 0) {
            queueListEl.innerHTML = '<p class="text-muted text-center">Aucun job en attente</p>';
            return;
        }

        var html = '';
        jobs.forEach(function(job) {
            var spec = job.spec || {};
            var target = escapeHtml(spec.target_ip || '');
            if (spec.target_port) target += ':' + spec.target_port;

            html += '<div class="job-item status-pending">' +
                '<span class="job-status-icon">\u23F3</span>' +
                '<span class="job-target">' + target + '</span>' +
                '<span class="job-id">' + escapeHtml(job.id || '') + '</span>' +
            '</div>';
        });

        queueListEl.innerHTML = html;
    }

    /**
     * Render completed/failed/cancelled jobs
     * @param {Array} jobs - History jobs
     */
    function renderHistoryJobs(jobs) {
        if (!historyListEl) return;

        if (jobs.length === 0) {
            historyListEl.innerHTML = '<p class="text-muted text-center">Aucun job execute</p>';
            return;
        }

        var html = '';
        jobs.forEach(function(job) {
            var spec = job.spec || {};
            var result = job.result || {};
            var config = STATUS_CONFIG[job.status] || STATUS_CONFIG.completed;
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
                    '<div class="job-result"><span class="packets-count">' + packets + ' paquets captures</span></div>' : '') +
                (error ? '<div class="job-error">' + error + '</div>' : '') +
            '</div>';
        });

        historyListEl.innerHTML = html;
    }

    /**
     * Start polling for job updates (rule #10)
     */
    function startPolling() {
        if (pollTimer) return; // Already polling
        console.debug('[jobs] Starting polling (interval=' + POLL_INTERVAL_MS + 'ms)');
        pollTimer = setInterval(loadJobs, POLL_INTERVAL_MS);
    }

    /**
     * Stop polling
     */
    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
            console.debug('[jobs] Polling stopped');
        }
    }

    /**
     * Initialize the jobs page module
     */
    function init() {
        console.debug('[jobs] Initializing jobs page module');

        // Create button handler
        if (createBtnEl) {
            createBtnEl.addEventListener('click', function(e) {
                e.preventDefault();
                createJob();
            });
        }

        // Load initial jobs list
        loadJobs();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
