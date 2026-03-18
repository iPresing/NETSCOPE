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

    // DOM Elements (rule #4: check existence before manipulation)
    var targetIpEl = document.getElementById('job-target-ip');
    var targetPortEl = document.getElementById('job-target-port');
    var portDirectionEl = document.getElementById('job-port-direction');
    var protocolEl = document.getElementById('job-protocol');
    var durationEl = document.getElementById('job-duration');
    var createBtnEl = document.getElementById('btn-create-job');
    var activeListEl = document.getElementById('jobs-active-list');
    var queueListEl = document.getElementById('jobs-queue-list');
    var historyListEl = document.getElementById('jobs-history-list');
    var queueCapacityEl = document.getElementById('queue-capacity');
    var jobsSlotsEl = document.getElementById('jobs-slots');

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

    // Valid port directions (rule #13 - client-side validation)
    var VALID_DIRECTIONS = ['src', 'dst', 'both'];

    // Status display configuration
    var STATUS_CONFIG = {
        running:   { icon: '<span class="dot-indicator dot-indicator--info"></span>',    label: 'En cours',   class: 'status-running' },
        pending:   { icon: '<span class="dot-indicator dot-indicator--muted"></span>',   label: 'En attente', class: 'status-pending' },
        completed: { icon: '<span class="dot-indicator dot-indicator--normal"></span>',  label: 'Termin\u00e9',    class: 'status-completed' },
        failed:    { icon: '<span class="dot-indicator dot-indicator--critical"></span>', label: '\u00c9chec',      class: 'status-failed' },
        cancelled: { icon: '<span class="dot-indicator dot-indicator--warning"></span>', label: 'Annul\u00e9',     class: 'status-cancelled' }
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

                // Direction only when port is specified (rule #13)
                if (portDirectionEl && portDirectionEl.value) {
                    var dir = portDirectionEl.value;
                    if (VALID_DIRECTIONS.indexOf(dir) !== -1) {
                        body.target_port_direction = dir;
                    }
                }
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
            createBtnEl.textContent = 'Lancement...';
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
                var toastMsg = data.message || 'Job cree - inspection en cours';
                showToast(toastMsg, 'success');
                console.info('[jobs] Job created (job_id=' + data.result.id + ')');
                // Reset form
                if (targetIpEl) targetIpEl.value = '';
                if (targetPortEl) targetPortEl.value = '';
                if (portDirectionEl) {
                    portDirectionEl.value = 'both';
                }
                if (protocolEl) protocolEl.value = '';
                if (durationEl) durationEl.value = '30';
                // Update direction state after reset (let toggle logic handle disabled state)
                updatePortDirectionState();
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
                createBtnEl.innerHTML = 'Lancer Inspection';
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
                    renderJobs(data.result.jobs || [], data.result.queue_stats || null);
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
     * @param {Object|null} queueStats - Queue statistics from API
     */
    function renderJobs(jobs, queueStats) {
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

        renderActiveJobs(active, queueStats);
        renderQueueJobs(pending, queueStats);
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
     * @param {Object|null} queueStats - Queue statistics
     */
    function renderActiveJobs(jobs, queueStats) {
        // Slots indicator (rule #4: check element existence)
        if (jobsSlotsEl && queueStats) {
            var avail = queueStats.available_slots || 0;
            var max = queueStats.max_concurrent_jobs || 1;
            jobsSlotsEl.innerHTML = '<span class="slots-indicator">Slots: ' +
                escapeHtml(String(avail)) + '/' + escapeHtml(String(max)) + ' dispo</span>';
        }

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
                '<div class="job-actions">' +
                    '<button class="btn btn-sm btn-danger stop-job-btn" data-job-id="' + escapeHtml(job.id || '') + '">Arr\u00eater</button>' +
                '</div>' +
            '</div>';
        });

        activeListEl.innerHTML = html;
    }

    /**
     * Render pending (queued) jobs with position and capacity
     * @param {Array} jobs - Pending jobs
     * @param {Object|null} queueStats - Queue statistics
     */
    function renderQueueJobs(jobs, queueStats) {
        // Queue capacity indicator (rule #4: check element existence)
        if (queueCapacityEl && queueStats) {
            var pending = queueStats.pending_count || 0;
            var maxSize = queueStats.max_queue_size || 10;
            var pct = Math.round((pending / maxSize) * 100);
            var barColor = pct < 50 ? 'var(--matrix-green, #00ff41)' :
                           pct < 80 ? 'var(--alert-amber, #ffb700)' :
                                      'var(--danger-red, #ff3333)';
            queueCapacityEl.innerHTML =
                '<div class="queue-capacity-label">File d\'attente: ' +
                escapeHtml(String(pending)) + '/' + escapeHtml(String(maxSize)) + ' jobs</div>' +
                '<div class="queue-capacity-bar" style="height:6px;background:rgba(255,255,255,0.1);border-radius:3px;margin-top:4px;">' +
                    '<div style="width:' + pct + '%;height:100%;background:' + barColor + ';border-radius:3px;transition:width 0.3s;"></div>' +
                '</div>';
        }

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
            var position = job.queue_position || 0;
            var jobsAhead = position > 0 ? position - 1 : 0;

            html += '<div class="job-item status-pending">' +
                '<div class="job-header">' +
                    '<span class="job-status-icon">\u23F3</span>' +
                    '<span class="job-target">' + target + '</span>' +
                    '<span class="queue-position">Position: ' + escapeHtml(String(position)) + '</span>' +
                    '<span class="job-id">' + escapeHtml(job.id || '') + '</span>' +
                '</div>' +
                '<div class="job-queue-info">' +
                    '<span class="jobs-ahead">' + escapeHtml(String(jobsAhead)) + ' jobs devant</span>' +
                    '<button class="btn btn-sm btn-outline cancel-job-btn" data-job-id="' + escapeHtml(job.id || '') + '">Annuler</button>' +
                '</div>' +
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
            // Task 5.2: Differentiate cancelled label based on error_message
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
                    '<div class="job-result"><span class="packets-count">' + packets + ' paquets captures</span></div>' : '') +
                (error ? '<div class="job-error">' + error + '</div>' : '') +
            '</div>';
        });

        historyListEl.innerHTML = html;
    }

    /**
     * Cancel or stop a job via POST /api/jobs/{id}/cancel (Story 4.6 - Task 4.3)
     * @param {string} jobId - Job ID to cancel
     */
    function cancelJob(jobId) {
        fetch('/api/jobs/' + encodeURIComponent(jobId) + '/cancel', { method: 'POST' })
            .then(function(response) {
                if (!response.ok) {
                    return response.json().then(function(err) { throw err; });
                }
                return response.json();
            })
            .then(function(data) {
                showToast(data.message || 'Job annul\u00e9', 'success');
                loadJobs();
            })
            .catch(function(error) {
                var msg = error.error ? error.error.message : 'Erreur lors de l\'annulation';
                showToast(msg, 'error');
                loadJobs();
            });
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
    /**
     * Toggle port direction select based on port field value (Story 4.2 - Task 5.3)
     */
    function updatePortDirectionState() {
        if (!portDirectionEl) return;
        var hasPort = targetPortEl && targetPortEl.value.trim() !== '';
        portDirectionEl.disabled = !hasPort;
        if (!hasPort) {
            portDirectionEl.value = 'both';
        }
    }

    function init() {
        console.debug('[jobs] Initializing jobs page module');

        // Create button handler
        if (createBtnEl) {
            createBtnEl.addEventListener('click', function(e) {
                e.preventDefault();
                createJob();
            });
        }

        // Port field change toggles direction select (Story 4.2 - Task 5.3)
        if (targetPortEl) {
            targetPortEl.addEventListener('input', updatePortDirectionState);
        }

        // Event delegation for stop/cancel buttons (Story 4.6 - Task 4.4)
        if (activeListEl) {
            activeListEl.addEventListener('click', function(e) {
                var btn = e.target.closest('.stop-job-btn');
                if (btn && !btn.disabled) {
                    btn.disabled = true;
                    cancelJob(btn.getAttribute('data-job-id'));
                }
            });
        }

        if (queueListEl) {
            queueListEl.addEventListener('click', function(e) {
                var btn = e.target.closest('.cancel-job-btn');
                if (btn && !btn.disabled) {
                    btn.disabled = true;
                    cancelJob(btn.getAttribute('data-job-id'));
                }
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
