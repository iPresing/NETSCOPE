/**
 * NETSCOPE Health Score Widget Module (Story 3.2, Story 3.3, Story 3.5)
 *
 * Displays network health score with simple progress bar (Story 3.1 style).
 * Story 3.3: Added whitelist hits indicator display.
 * Story 3.5: Added score evolution indicator (delta between captures).
 * Integrates with HealthScoreCalculator backend (Story 3.1).
 *
 * Lessons Learned Epic 1/2:
 * - IIFE pattern with 'use strict'
 * - Always check element existence before DOM manipulation
 * - Use NetScopeUtils.escapeHtml() for XSS prevention
 * - Validate HTTP responses with if (!response.ok)
 */
(function() {
    'use strict';

    // Constants
    var STATUS_THRESHOLDS = {
        NORMAL: 80,
        WARNING: 50
    };
    var STATUS_LABELS = {
        normal: 'Réseau Sain',
        warning: 'Attention',
        critical: 'Critique'
    };
    var POLLING_INTERVAL_MS = 5000;

    // Global state
    var globalWidgetInstance = null;
    var pollingIntervalId = null;
    var isPollingEnabled = false;

    /**
     * HealthScoreWidget class
     * @param {HTMLElement|string} container - Container element or selector
     */
    function HealthScoreWidget(container) {
        // Handle selector or element
        if (typeof container === 'string') {
            this.container = document.querySelector(container);
        } else {
            this.container = container;
        }

        if (!this.container) {
            console.warn('[HealthScoreWidget] Container not found');
            return;
        }

        // State
        this.currentScore = null;
        this.currentStatus = null;
        this.scoreData = null;
        this.isLoading = false;

        // DOM references (populated after render or from existing DOM)
        this.elements = {
            widget: null,
            barFill: null,
            scoreValue: null,
            scoreMax: null,
            statusLabel: null,
            detailsBtn: null,
            // Story 3.3: Whitelist indicator elements
            whitelistIndicator: null,
            whitelistText: null,
            whitelistImpact: null,
            // Story 3.5: Evolution indicator elements
            evolutionContainer: null,
            evolutionArrow: null,
            evolutionDelta: null,
            evolutionMessage: null
        };

        this.init();
    }

    /**
     * Initialize the widget
     */
    HealthScoreWidget.prototype.init = function() {
        // Check if widget HTML already exists (server-rendered) - simple style
        var existingWidget = this.container.querySelector('.score-display-widget');
        if (existingWidget) {
            this.cacheElements();
        } else {
            this.render();
        }
        this.bindEvents();
    };

    /**
     * Cache DOM element references from existing HTML (simple style)
     */
    HealthScoreWidget.prototype.cacheElements = function() {
        this.elements.widget = this.container.querySelector('.score-display-widget');
        this.elements.barFill = this.container.querySelector('.progress-fill');
        this.elements.scoreValue = this.container.querySelector('.score-value');
        this.elements.scoreMax = this.container.querySelector('.score-max');
        this.elements.statusLabel = this.container.querySelector('.score-status');
        this.elements.detailsBtn = this.container.querySelector('#btn-health-score-details');
        // Story 3.3: Cache whitelist indicator elements
        this.elements.whitelistIndicator = this.container.querySelector('.whitelist-indicator');
        this.elements.whitelistText = this.container.querySelector('.whitelist-indicator__text');
        this.elements.whitelistImpact = this.container.querySelector('.whitelist-indicator__impact');
        // Story 3.5: Cache evolution indicator elements
        this.elements.evolutionContainer = this.container.querySelector('.score-evolution');
        this.elements.evolutionArrow = this.container.querySelector('.score-evolution__arrow');
        this.elements.evolutionDelta = this.container.querySelector('.score-evolution__delta');
        this.elements.evolutionMessage = this.container.querySelector('.score-evolution__message');
    };

    /**
     * Render the widget HTML structure (simple style)
     */
    HealthScoreWidget.prototype.render = function() {
        var html = [
            '<div class="score-display-widget score-display-widget--empty">',
            '  <div class="score-display">',
            '    <span class="score-value">--</span>',
            '    <span class="score-max">/100</span>',
            '  </div>',
            '  <div class="progress-bar">',
            '    <div class="progress-fill progress-fill--normal" style="width: 0%;"></div>',
            '  </div>',
            '  <p class="score-status">--%</p>',
            '  <div class="whitelist-indicator whitelist-indicator--hidden" id="whitelist-indicator" data-hits="0" data-impact="0">',
            '    <span class="whitelist-indicator__icon">&#128737;</span>',
            '    <span class="whitelist-indicator__text" id="whitelist-text">0 whitelist hits</span>',
            '    <span class="whitelist-indicator__impact" id="whitelist-impact" style="display: none;"></span>',
            '  </div>',
            '  <div class="score-evolution score-evolution--hidden" id="score-evolution">',
            '    <span class="score-evolution__arrow" id="score-evolution-arrow"></span>',
            '    <span class="score-evolution__delta" id="score-evolution-delta"></span>',
            '    <span class="score-evolution__message" id="score-evolution-message"></span>',
            '  </div>',
            '  <button class="btn btn-sm" id="btn-health-score-details" style="display: none;">Détails</button>',
            '</div>'
        ].join('\n');

        this.container.innerHTML = html;
        this.cacheElements();
    };

    /**
     * Bind event listeners
     */
    HealthScoreWidget.prototype.bindEvents = function() {
        var self = this;

        if (this.elements.detailsBtn) {
            this.elements.detailsBtn.addEventListener('click', function(e) {
                e.preventDefault();
                self.showDetails();
            });
        }
    };

    /**
     * Validate score data before processing
     * @param {Object} scoreData - Data to validate
     * @returns {boolean} True if valid
     */
    HealthScoreWidget.prototype.validateScoreData = function(scoreData) {
        if (!scoreData) {
            console.warn('[HealthScoreWidget] Score data is null/undefined');
            return false;
        }
        if (typeof scoreData.displayed_score !== 'number') {
            console.warn('[HealthScoreWidget] Invalid displayed_score:', scoreData.displayed_score);
            return false;
        }
        if (scoreData.displayed_score < 0 || scoreData.displayed_score > 100) {
            console.warn('[HealthScoreWidget] Score out of range:', scoreData.displayed_score);
            return false;
        }
        return true;
    };

    /**
     * Update the widget with new score data
     * @param {Object} scoreData - HealthScoreResult data from API
     */
    HealthScoreWidget.prototype.update = function(scoreData) {
        if (!this.validateScoreData(scoreData)) {
            return;
        }

        var score = Math.max(0, Math.min(100, scoreData.displayed_score));
        var statusColor = scoreData.status_color || this.getStatusFromScore(score);

        // Update state
        this.currentScore = score;
        this.currentStatus = statusColor;
        this.scoreData = scoreData;

        // Update progress bar
        this.updateBar(score, statusColor);

        // Update score display
        this.updateScoreDisplay(score, statusColor);

        // Update status label
        this.updateStatusLabel(statusColor);

        // Story 3.3: Update whitelist indicator
        this.updateWhitelistIndicator(
            scoreData.whitelist_hits || 0,
            scoreData.whitelist_impact || 0
        );

        // Show details button
        this.setHasData(true);
    };

    /**
     * Update the progress bar
     */
    HealthScoreWidget.prototype.updateBar = function(score, status) {
        if (!this.elements.barFill) return;

        this.elements.barFill.style.width = score + '%';
        this.setColor(status);
    };

    /**
     * Update the numeric score display (simple style)
     */
    HealthScoreWidget.prototype.updateScoreDisplay = function(score, status) {
        if (!this.elements.scoreValue) return;

        this.elements.scoreValue.textContent = score;
        this.elements.scoreValue.className = 'score-value score-value--' + status;
    };

    /**
     * Update the status label (simple style)
     */
    HealthScoreWidget.prototype.updateStatusLabel = function(status) {
        if (!this.elements.statusLabel) return;

        this.elements.statusLabel.textContent = STATUS_LABELS[status] || '--%';
        this.elements.statusLabel.className = 'score-status score-status--' + status;
    };

    /**
     * Update whitelist indicator (Story 3.3)
     * @param {number} hits - Number of whitelist hits
     * @param {number} impact - Points hidden by whitelist
     */
    HealthScoreWidget.prototype.updateWhitelistIndicator = function(hits, impact) {
        if (!this.elements.whitelistIndicator) return;

        if (hits > 0) {
            this.elements.whitelistIndicator.classList.remove('whitelist-indicator--hidden');
            if (this.elements.whitelistText) {
                var text = hits + ' whitelist hit' + (hits !== 1 ? 's' : '');
                this.elements.whitelistText.textContent = text;
            }
            if (this.elements.whitelistImpact) {
                if (impact < 0) {
                    this.elements.whitelistImpact.textContent = '(' + Math.abs(impact) + ' pts masqués)';
                    this.elements.whitelistImpact.style.display = '';
                } else {
                    this.elements.whitelistImpact.style.display = 'none';
                }
            }
        } else {
            this.elements.whitelistIndicator.classList.add('whitelist-indicator--hidden');
        }
    };

    /**
     * Update score evolution indicator (Story 3.5)
     * @param {Object|null} evolutionData - ScoreEvolution data from API
     */
    HealthScoreWidget.prototype.updateEvolution = function(evolutionData) {
        if (!this.elements.evolutionContainer) return;

        // Hide if no evolution data or first capture (no previous score)
        if (!evolutionData || evolutionData.previous_score === null) {
            this.elements.evolutionContainer.classList.add('score-evolution--hidden');
            // Show "Premiere capture" message if it's first capture
            if (evolutionData && evolutionData.previous_score === null && this.elements.evolutionMessage) {
                this.elements.evolutionContainer.classList.remove('score-evolution--hidden');
                this.elements.evolutionContainer.classList.remove('score-evolution--up', 'score-evolution--down', 'score-evolution--stable');
                this.elements.evolutionContainer.classList.add('score-evolution--first');
                if (this.elements.evolutionArrow) {
                    this.elements.evolutionArrow.textContent = '';
                }
                if (this.elements.evolutionDelta) {
                    this.elements.evolutionDelta.textContent = '';
                }
                this.elements.evolutionMessage.textContent = evolutionData.message || 'Premiere capture';
            }
            return;
        }

        var direction = evolutionData.direction;
        var delta = evolutionData.delta;

        // Show container
        this.elements.evolutionContainer.classList.remove('score-evolution--hidden');

        // Reset direction classes
        this.elements.evolutionContainer.classList.remove(
            'score-evolution--up',
            'score-evolution--down',
            'score-evolution--stable',
            'score-evolution--first'
        );
        this.elements.evolutionContainer.classList.add('score-evolution--' + direction);

        // Update arrow (textContent for XSS safety per Lessons Learned)
        if (this.elements.evolutionArrow) {
            if (direction === 'up') {
                this.elements.evolutionArrow.textContent = '\u2191'; // ↑
            } else if (direction === 'down') {
                this.elements.evolutionArrow.textContent = '\u2193'; // ↓
            } else {
                this.elements.evolutionArrow.textContent = '\u2192'; // →
            }
        }

        // Update delta text
        if (this.elements.evolutionDelta) {
            if (direction === 'up') {
                this.elements.evolutionDelta.textContent = '+' + delta + ' pts';
            } else if (direction === 'down') {
                this.elements.evolutionDelta.textContent = delta + ' pts';
            } else {
                this.elements.evolutionDelta.textContent = 'Stable';
            }
        }

        // Clear message for non-first captures
        if (this.elements.evolutionMessage) {
            this.elements.evolutionMessage.textContent = '';
        }
    };

    /**
     * Set the color/status of the progress bar
     */
    HealthScoreWidget.prototype.setColor = function(status) {
        if (!this.elements.barFill) return;

        this.elements.barFill.classList.remove(
            'progress-fill--normal',
            'progress-fill--warning',
            'progress-fill--critical'
        );
        this.elements.barFill.classList.add('progress-fill--' + status);
    };

    /**
     * Get status from score value
     */
    HealthScoreWidget.prototype.getStatusFromScore = function(score) {
        if (score >= STATUS_THRESHOLDS.NORMAL) {
            return 'normal';
        } else if (score >= STATUS_THRESHOLDS.WARNING) {
            return 'warning';
        }
        return 'critical';
    };

    /**
     * Toggle between empty state and data state (simple style)
     */
    HealthScoreWidget.prototype.setHasData = function(hasData) {
        if (!this.elements.widget) return;

        if (hasData) {
            this.elements.widget.classList.remove('score-display-widget--empty');
            if (this.elements.detailsBtn) {
                this.elements.detailsBtn.style.display = '';
            }
        } else {
            this.elements.widget.classList.add('score-display-widget--empty');
            if (this.elements.detailsBtn) {
                this.elements.detailsBtn.style.display = 'none';
            }
        }
    };

    /**
     * Set loading state
     */
    HealthScoreWidget.prototype.setLoading = function(loading) {
        this.isLoading = loading;
    };

    /**
     * Reset widget to empty state (simple style)
     */
    HealthScoreWidget.prototype.reset = function() {
        this.currentScore = null;
        this.currentStatus = null;
        this.scoreData = null;

        if (this.elements.scoreValue) {
            this.elements.scoreValue.textContent = '--';
            this.elements.scoreValue.className = 'score-value';
        }

        if (this.elements.barFill) {
            this.elements.barFill.style.width = '0%';
        }

        if (this.elements.statusLabel) {
            this.elements.statusLabel.textContent = '--%';
            this.elements.statusLabel.className = 'score-status';
        }

        // Story 3.3: Reset whitelist indicator
        this.updateWhitelistIndicator(0, 0);

        // Story 3.5: Reset evolution indicator
        this.updateEvolution(null);

        this.setHasData(false);
        this.setColor('normal');
    };

    /**
     * Show details modal (M4 fix)
     */
    HealthScoreWidget.prototype.showDetails = function() {
        if (!this.scoreData) {
            console.warn('[HealthScoreWidget] No score data for details');
            return;
        }

        // Show the health score details modal
        showHealthScoreModal(this.scoreData);
    };

    /**
     * Fetch latest health score from API
     */
    HealthScoreWidget.prototype.fetchScore = function() {
        var self = this;

        this.setLoading(true);

        // Story 3.5: Fetch both score and evolution in parallel
        return Promise.all([
            fetch('/api/health/score'),
            fetch('/api/health/evolution')
        ])
            .then(function(responses) {
                // Validate both responses
                return Promise.all(responses.map(function(response) {
                    if (!response.ok) {
                        throw new Error('HTTP error: ' + response.status);
                    }
                    return response.json();
                }));
            })
            .then(function(results) {
                self.setLoading(false);

                var scoreData = results[0];
                var evolutionData = results[1];

                if (scoreData.success && scoreData.data) {
                    self.update(scoreData.data);
                } else if (scoreData.success && scoreData.data === null) {
                    self.reset();
                    return null;
                } else {
                    console.warn('[HealthScoreWidget] Score API error:', scoreData.error);
                }

                // Update evolution indicator (Story 3.5)
                if (evolutionData.success) {
                    self.updateEvolution(evolutionData.data);
                }

                return { score: scoreData.data, evolution: evolutionData.data };
            })
            .catch(function(error) {
                self.setLoading(false);
                console.error('[HealthScoreWidget] Fetch error:', error);
                return null;
            });
    };

    /**
     * Get current score value
     */
    HealthScoreWidget.prototype.getScore = function() {
        return this.currentScore;
    };

    /**
     * Get current status
     */
    HealthScoreWidget.prototype.getStatus = function() {
        return this.currentStatus;
    };

    // =========================================================================
    // Health Score Modal (M4 fix - Details button functionality)
    // =========================================================================

    /**
     * Show health score details modal
     * @param {Object} scoreData - HealthScoreResult data
     */
    function showHealthScoreModal(scoreData) {
        // Check for existing modal or create one
        var modal = document.getElementById('health-score-modal');
        if (!modal) {
            modal = createHealthScoreModal();
            document.body.appendChild(modal);
        }

        // Populate modal content
        populateHealthScoreModal(modal, scoreData);

        // Show modal
        modal.style.display = 'flex';

        // Close on backdrop click
        modal.addEventListener('click', function(e) {
            if (e.target === modal) {
                hideHealthScoreModal();
            }
        });
    }

    /**
     * Create the health score modal element
     */
    function createHealthScoreModal() {
        var modal = document.createElement('div');
        modal.id = 'health-score-modal';
        modal.className = 'health-score-modal';
        modal.innerHTML = [
            '<div class="health-score-modal__content card">',
            '  <div class="health-score-modal__header">',
            '    <h3 class="health-score-modal__title">D&eacute;tails Score Sant&eacute;</h3>',
            '    <button class="health-score-modal__close btn btn-sm btn-danger" id="btn-close-health-modal">&times;</button>',
            '  </div>',
            '  <div class="health-score-modal__body" id="health-score-modal-body">',
            '  </div>',
            '</div>'
        ].join('\n');

        // Bind close button
        var closeBtn = modal.querySelector('#btn-close-health-modal');
        if (closeBtn) {
            closeBtn.addEventListener('click', hideHealthScoreModal);
        }

        return modal;
    }

    /**
     * Populate modal with score data (Story 3.4: Added whitelist details and nudge)
     */
    function populateHealthScoreModal(modal, scoreData) {
        var body = modal.querySelector('#health-score-modal-body');
        if (!body) return;

        var statusClass = 'status-' + (scoreData.status_color || 'normal');
        var statusLabel = STATUS_LABELS[scoreData.status_color] || 'Score';

        // Build whitelist details section (Story 3.4)
        var whitelistHtml = buildWhitelistDetailsHtml(scoreData);

        // Build nudge if large gap (Story 3.4)
        var nudgeHtml = buildNudgeHtml(scoreData);

        var html = [
            '<div class="health-score-detail">',
            '  <div class="health-score-detail__score ' + statusClass + '">',
            '    <span class="health-score-detail__value">' + scoreData.displayed_score + '</span>',
            '    <span class="health-score-detail__max">/100</span>',
            '    <span class="health-score-detail__label">' + statusLabel + '</span>',
            '  </div>',
            '  <div class="health-score-detail__breakdown">',
            '    <h4>Analyse</h4>',
            '    <div class="health-score-detail__row">',
            '      <span class="label">Score de base:</span>',
            '      <span class="value">' + (scoreData.base_score || 100) + '</span>',
            '    </div>',
            '    <div class="health-score-detail__row">',
            '      <span class="label">Score reel:</span>',
            '      <span class="value">' + (scoreData.real_score || scoreData.displayed_score) + '</span>',
            '    </div>',
            '    <div class="health-score-detail__row critical">',
            '      <span class="label">Anomalies critiques:</span>',
            '      <span class="value">' + (scoreData.critical_count || 0) + '</span>',
            '    </div>',
            '    <div class="health-score-detail__row warning">',
            '      <span class="label">Anomalies attention:</span>',
            '      <span class="value">' + (scoreData.warning_count || 0) + '</span>',
            '    </div>',
            '    <div class="health-score-detail__row">',
            '      <span class="label">Elements whitelistes:</span>',
            '      <span class="value">' + (scoreData.whitelist_hits || 0) + '</span>',
            '    </div>',
            '    <div class="health-score-detail__row">',
            '      <span class="label">Impact whitelist:</span>',
            '      <span class="value">' + Math.abs(scoreData.whitelist_impact || 0) + ' pts masques</span>',
            '    </div>',
            '  </div>',
            whitelistHtml,
            nudgeHtml,
            '</div>'
        ].join('\n');

        body.innerHTML = html;
    }

    /**
     * Echappe les caracteres HTML pour prevenir XSS
     * Fallback si NetScopeUtils n'est pas disponible
     * @param {string} str - Chaine a echapper
     * @returns {string} Chaine echappee
     */
    function escapeHtmlFallback(str) {
        if (!str) return '';
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    /**
     * Echappe HTML en utilisant NetScopeUtils ou fallback securise
     * @param {string} str - Chaine a echapper
     * @returns {string} Chaine echappee
     */
    function safeEscapeHtml(str) {
        if (window.NetScopeUtils && typeof NetScopeUtils.escapeHtml === 'function') {
            return NetScopeUtils.escapeHtml(str);
        }
        return escapeHtmlFallback(str);
    }

    /**
     * Construit la section HTML des details whitelist (Story 3.4)
     * @param {Object} scoreData - Donnees HealthScoreResult
     * @returns {string} Chaine HTML pour les details whitelist
     */
    function buildWhitelistDetailsHtml(scoreData) {
        var details = scoreData.whitelist_details || [];

        if (details.length === 0) {
            return '<div class="whitelist-details-empty">Aucun element whiteliste</div>';
        }

        var items = details.map(function(hit) {
            var target = hit.ip || (hit.port ? 'Port ' + hit.port : 'Element');
            var critClass = hit.criticality === 'critical' ? 'critical' : 'warning';
            var safeTarget = safeEscapeHtml(target);
            var safeReason = safeEscapeHtml(hit.reason || '');
            return [
                '<div class="whitelist-details-item whitelist-details-item--' + critClass + '">',
                '  <span class="whitelist-details-item__target">' + safeTarget + '</span>',
                '  <span class="whitelist-details-item__impact">' + hit.impact + ' pts</span>',
                '  <span class="whitelist-details-item__reason">' + safeReason + '</span>',
                '</div>'
            ].join('\n');
        });

        return [
            '<div class="whitelist-details-section">',
            '  <h4>Elements Whitelistes</h4>',
            '  <div class="whitelist-details-list">',
            items.join('\n'),
            '  </div>',
            '</div>'
        ].join('\n');
    }

    /**
     * Construit le HTML du nudge si ecart important entre scores (Story 3.4 AC4)
     * @param {Object} scoreData - Donnees HealthScoreResult
     * @returns {string} Chaine HTML pour le nudge ou chaine vide
     */
    function buildNudgeHtml(scoreData) {
        var impact = scoreData.whitelist_impact || 0;
        // Impact negatif = whitelist masque des points (score affiche > score reel)
        // Nudge si ecart > 20 points
        if (impact >= -20) {
            return ''; // Pas de nudge si ecart <= 20
        }

        var details = scoreData.whitelist_details || [];
        var totalHidden = details.length;
        var criticalHidden = details.filter(function(h) {
            return h.criticality === 'critical';
        }).length;
        var warningHidden = totalHidden - criticalHidden;

        // Construire un message informatif avec le total et le detail
        var message = 'Conseil: ' + totalHidden + ' anomalie' +
            (totalHidden > 1 ? 's' : '') + ' masquee' +
            (totalHidden > 1 ? 's' : '') + ' par la whitelist';

        // Ajouter le detail si mix critique/warning
        if (criticalHidden > 0 && warningHidden > 0) {
            message += ' (' + criticalHidden + ' critique' +
                (criticalHidden > 1 ? 's' : '') + ', ' +
                warningHidden + ' warning' + (warningHidden > 1 ? 's' : '') + ')';
        } else if (criticalHidden > 0) {
            message += ' (' + criticalHidden + ' critique' +
                (criticalHidden > 1 ? 's' : '') + ')';
        }

        message += '. Verifiez si legitimes.';

        return [
            '<div class="health-score-nudge">',
            '  <span class="health-score-nudge__icon">&#9888;</span>',
            '  <span class="health-score-nudge__text">' + message + '</span>',
            '</div>'
        ].join('\n');
    }

    /**
     * Hide health score modal
     */
    function hideHealthScoreModal() {
        var modal = document.getElementById('health-score-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    // =========================================================================
    // Global Functions (used by capture.js and for auto-refresh)
    // =========================================================================

    /**
     * Get or create global widget instance
     */
    function getWidgetInstance() {
        if (!globalWidgetInstance) {
            // Look for container by ID or find widget directly
            var container = document.getElementById('health-score-widget');
            if (!container) {
                container = document.querySelector('.score-display-widget');
                if (container) {
                    container = container.parentElement;
                }
            }
            if (container) {
                globalWidgetInstance = new HealthScoreWidget(container);
            }
        }
        return globalWidgetInstance;
    }

    /**
     * Load/refresh health score from API
     * Called after capture completion to update the widget (AC5)
     */
    function loadHealthScore() {
        var widget = getWidgetInstance();

        if (!widget || !widget.container) {
            console.warn('[HealthScore] Widget container not found');
            return Promise.resolve(null);
        }

        return widget.fetchScore();
    }

    /**
     * Start polling for health score updates (H2 fix - AC5)
     * @param {number} [intervalMs] - Polling interval in milliseconds
     */
    function startHealthScorePolling(intervalMs) {
        if (isPollingEnabled) {
            return; // Already polling
        }

        var interval = intervalMs || POLLING_INTERVAL_MS;
        isPollingEnabled = true;

        pollingIntervalId = setInterval(function() {
            loadHealthScore();
        }, interval);

        console.log('[HealthScore] Polling started (interval=' + interval + 'ms)');
    }

    /**
     * Stop polling for health score updates
     */
    function stopHealthScorePolling() {
        if (pollingIntervalId) {
            clearInterval(pollingIntervalId);
            pollingIntervalId = null;
        }
        isPollingEnabled = false;
        console.log('[HealthScore] Polling stopped');
    }

    /**
     * Check if polling is active
     */
    function isHealthScorePolling() {
        return isPollingEnabled;
    }

    // =========================================================================
    // Initialization
    // =========================================================================

    /**
     * Initialize module on DOM ready
     */
    function initModule() {
        // Auto-initialize widgets with data attribute
        var autoInitContainers = document.querySelectorAll('[data-health-score-widget]');
        autoInitContainers.forEach(function(container) {
            new HealthScoreWidget(container);
        });

        // Initialize global widget if exists (simple style)
        var widgetContainer = document.getElementById('health-score-widget');
        if (widgetContainer) {
            globalWidgetInstance = new HealthScoreWidget(widgetContainer.parentElement || widgetContainer);

            // If widget has server-rendered data, read initial state
            var initialScore = widgetContainer.dataset.score;
            if (initialScore && initialScore !== '') {
                console.log('[HealthScore] Widget initialized with server data');
            }
        }
        // Note: Details button binding is handled by widget.bindEvents()
    }

    // Export to global NetScope namespace
    window.NetScope = window.NetScope || {};
    window.NetScope.HealthScoreWidget = HealthScoreWidget;

    // Export global functions for use after capture completion (Story 3.2 AC5)
    window.loadHealthScore = loadHealthScore;
    window.startHealthScorePolling = startHealthScorePolling;
    window.stopHealthScorePolling = stopHealthScorePolling;
    window.isHealthScorePolling = isHealthScorePolling;

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initModule);
    } else {
        initModule();
    }
})();
