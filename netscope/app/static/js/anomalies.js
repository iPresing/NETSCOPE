/**
 * NETSCOPE Anomalies Page Module (Story 2.7)
 *
 * Handles anomaly list display with progress bars and human context.
 * Consumes API endpoint /api/anomalies?latest=true&include_breakdown=true
 *
 * Lessons Learned Epic 1 & Stories 2.1-2.6:
 * - IIFE pattern with 'use strict'
 * - Use NetScopeUtils.escapeHtml() for XSS protection
 * - Always check element existence before DOM manipulation
 */
(function() {
    'use strict';

    // DOM Elements
    var anomalyListEl = document.getElementById('anomaly-list');
    var emptyStateEl = document.getElementById('anomaly-empty-state');
    var summaryCriticalEl = document.getElementById('summary-critical');
    var summaryWarningEl = document.getElementById('summary-warning');
    var summaryNormalEl = document.getElementById('summary-normal');

    // Criticality configuration
    var CRITICALITY_CONFIG = {
        critical: {
            indicator: '\u{1F534}',  // Red circle emoji
            class: 'critical',
            label: 'CRITIQUE'
        },
        warning: {
            indicator: '\u{1F7E1}',  // Yellow circle emoji
            class: 'warning',
            label: 'ATTENTION'
        },
        normal: {
            indicator: '\u{1F7E2}',  // Green circle emoji
            class: 'normal',
            label: 'NORMAL'
        }
    };

    // Use shared utilities from NetScopeUtils
    var escapeHtml = window.NetScopeUtils ? window.NetScopeUtils.escapeHtml : function(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    /**
     * Load anomalies from API
     */
    function loadAnomalies() {
        console.debug('[anomalies] Loading anomalies page');
        console.debug('[anomalies] Fetching /api/anomalies?latest=true&include_breakdown=true');

        fetch('/api/anomalies?latest=true&include_breakdown=true')
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP error! status: ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                if (data.success && data.result) {
                    renderAnomalyList(data.result);
                    updateSummarySection(data.result.by_criticality);
                    var total = data.result.total || 0;
                    var byCrit = data.result.by_criticality || {};
                    console.info('[anomalies] Rendered ' + total + ' anomalies (critical=' +
                        (byCrit.critical || 0) + ', warning=' + (byCrit.warning || 0) +
                        ', normal=' + (byCrit.normal || 0) + ')');
                } else {
                    showEmptyState();
                }
            })
            .catch(function(error) {
                console.error('[anomalies] Error loading anomalies:', error);
                showEmptyState();
            });
    }

    /**
     * Render the anomaly list (already sorted by score from API)
     * @param {Object} result - API result with anomalies array
     */
    function renderAnomalyList(result) {
        var anomalies = result.anomalies || [];

        if (anomalies.length === 0) {
            showEmptyState();
            return;
        }

        if (!anomalyListEl) return;

        // Hide empty state
        if (emptyStateEl) {
            emptyStateEl.style.display = 'none';
        }

        // Sort by score descending (API already sorts by criticality, but we sort by score for AC1)
        anomalies.sort(function(a, b) {
            return b.score - a.score;
        });

        // Build HTML
        var html = '';
        anomalies.forEach(function(anomaly) {
            html += renderAnomalyItem(anomaly);
        });

        anomalyListEl.innerHTML = html;

        // Add event listeners for action buttons
        addActionListeners();
    }

    /**
     * Render a single anomaly item with progress bar
     * @param {Object} anomaly - Anomaly data from API
     * @returns {string} HTML string
     */
    function renderAnomalyItem(anomaly) {
        var criticality = anomaly.criticality || 'normal';
        var config = CRITICALITY_CONFIG[criticality] || CRITICALITY_CONFIG.normal;
        var progressWidth = calculateProgressWidth(anomaly.score);
        var humanContext = anomaly.human_context || {};
        var packetInfo = anomaly.packet_info || {};

        // Build connection info
        var valueDisplay = escapeHtml(anomaly.matched_value);
        if (packetInfo.port_dst) {
            valueDisplay += ':' + packetInfo.port_dst;
        }

        // Get match type label
        var matchTypeLabel = getMatchTypeLabel(anomaly.match_type);

        // Build context section - using actual HumanContext fields from Story 2.5
        var contextHtml = '';
        if (humanContext.short_message || humanContext.explanation) {
            var contextText = escapeHtml(humanContext.short_message || '');
            if (humanContext.explanation) {
                contextText += ' - ' + escapeHtml(humanContext.explanation);
            }
            var recommendation = humanContext.action_hint ? escapeHtml(humanContext.action_hint) : '';

            contextHtml = '<div class="anomaly-context">' +
                '<p class="context-summary">' + contextText + '</p>' +
                (recommendation ? '<p class="context-recommendation">' + recommendation + '</p>' : '') +
                '</div>';
        }

        return '<div class="anomaly-item anomaly-' + config.class + '" data-anomaly-id="' + escapeHtml(anomaly.id) + '">' +
            '<div class="anomaly-header">' +
                '<span class="anomaly-indicator">' + config.indicator + '</span>' +
                '<span class="anomaly-value">' + valueDisplay + '</span>' +
                '<span class="anomaly-type">' + escapeHtml(matchTypeLabel) + '</span>' +
            '</div>' +
            '<div class="anomaly-score">' +
                '<div class="progress-bar">' +
                    '<div class="progress-fill ' + config.class + '" style="width: ' + progressWidth + '%;"></div>' +
                '</div>' +
                '<span class="score-value">' + anomaly.score + '/100</span>' +
            '</div>' +
            contextHtml +
            '<div class="anomaly-actions">' +
                '<button class="btn btn-sm btn-outline btn-inspect" disabled title="Epic 4 - Inspection Scapy">' +
                    '\u{1F52C} Inspecter' +
                '</button>' +
                '<button class="btn btn-sm btn-outline btn-whitelist" disabled title="Epic 3 - Whitelist">' +
                    '\u2705 Whitelist' +
                '</button>' +
            '</div>' +
        '</div>';
    }

    /**
     * Calculate progress bar width from score
     * @param {number} score - Score 0-100
     * @returns {number} Width percentage (0-100)
     */
    function calculateProgressWidth(score) {
        if (typeof score !== 'number') {
            score = parseInt(score, 10) || 0;
        }
        return Math.min(100, Math.max(0, score));
    }

    /**
     * Get human-readable match type label
     * @param {string} matchType - 'ip', 'domain', 'term'
     * @returns {string} Human-readable label
     */
    function getMatchTypeLabel(matchType) {
        var labels = {
            'ip': 'IP blacklistee',
            'domain': 'Domaine blackliste',
            'term': 'Terme suspect'
        };
        return labels[matchType] || 'Anomalie';
    }

    /**
     * Update summary section with by_criticality counts
     * @param {Object} byCriticality - {critical: n, warning: n, normal: n}
     */
    function updateSummarySection(byCriticality) {
        var counts = byCriticality || { critical: 0, warning: 0, normal: 0 };

        if (summaryCriticalEl) {
            summaryCriticalEl.textContent = counts.critical || 0;
        }
        if (summaryWarningEl) {
            summaryWarningEl.textContent = counts.warning || 0;
        }
        if (summaryNormalEl) {
            summaryNormalEl.textContent = counts.normal || 0;
        }
    }

    /**
     * Show empty state message and reset UI to initial state.
     * Clears any existing anomaly items and resets summary counts to zero.
     */
    function showEmptyState() {
        if (emptyStateEl) {
            emptyStateEl.style.display = 'block';
        }
        // Clear any existing anomaly items but keep empty state
        if (anomalyListEl) {
            var items = anomalyListEl.querySelectorAll('.anomaly-item');
            items.forEach(function(item) {
                item.remove();
            });
        }
        // Reset summary counts
        updateSummarySection({ critical: 0, warning: 0, normal: 0 });
    }

    /**
     * Add event listeners for action buttons (disabled for now, prep for Epic 3 & 4)
     */
    function addActionListeners() {
        // Inspect buttons - Epic 4
        var inspectBtns = document.querySelectorAll('.btn-inspect');
        inspectBtns.forEach(function(btn) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                // Disabled - will be implemented in Epic 4
                console.debug('[anomalies] Inspect button clicked (Epic 4)');
            });
        });

        // Whitelist buttons - Epic 3
        var whitelistBtns = document.querySelectorAll('.btn-whitelist');
        whitelistBtns.forEach(function(btn) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                // Disabled - will be implemented in Epic 3
                console.debug('[anomalies] Whitelist button clicked (Epic 3)');
            });
        });
    }

    /**
     * Initialize the anomalies page module
     */
    function init() {
        console.debug('[anomalies] Initializing anomalies page module');
        loadAnomalies();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
