/**
 * NETSCOPE Anomalies Page Module (Story 2.7 + 2.8)
 *
 * Handles anomaly list display with progress bars, human context,
 * filtering, searching, and sorting.
 * Consumes API endpoint /api/anomalies?latest=true&include_breakdown=true
 *
 * Lessons Learned Epic 1 & Stories 2.1-2.7:
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
    var severityFilterEl = document.getElementById('severity-filter');
    var typeFilterEl = document.getElementById('type-filter');
    var searchFilterEl = document.getElementById('search-filter');
    var filterCountEl = document.getElementById('filter-count');

    // State variables for filtering and sorting (Story 2.8)
    var allAnomalies = [];
    var currentSortField = 'score';
    var currentSortDirection = 'desc';

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
     * Debounce utility for search input (Story 2.8)
     * @param {Function} func - Function to debounce
     * @param {number} wait - Milliseconds to wait
     * @returns {Function} Debounced function
     */
    function debounce(func, wait) {
        var timeout;
        return function() {
            var context = this;
            var args = arguments;
            clearTimeout(timeout);
            timeout = setTimeout(function() {
                func.apply(context, args);
            }, wait);
        };
    }

    /**
     * Filter anomalies by severity level (Story 2.8 - AC2)
     * @param {Array} anomalies - List of anomalies
     * @param {string} severity - 'all', 'critical', 'warning', 'normal'
     * @returns {Array} Filtered anomalies
     */
    function filterBySeverity(anomalies, severity) {
        if (severity === 'all') return anomalies;
        return anomalies.filter(function(a) {
            return a.criticality === severity;
        });
    }

    /**
     * Filter anomalies by match type (Story 2.8 - AC3)
     * @param {Array} anomalies - List of anomalies
     * @param {string} matchType - 'all', 'ip', 'domain', 'term'
     * @returns {Array} Filtered anomalies
     */
    function filterByType(anomalies, matchType) {
        if (matchType === 'all') return anomalies;
        return anomalies.filter(function(a) {
            return a.match_type === matchType;
        });
    }

    /**
     * Filter anomalies by search text (Story 2.8 - AC1)
     * Searches in matched_value, human_context.short_message, and human_context.explanation
     * @param {Array} anomalies - List of anomalies
     * @param {string} searchText - Text to search
     * @returns {Array} Filtered anomalies
     */
    function filterBySearch(anomalies, searchText) {
        if (!searchText || searchText.trim() === '') return anomalies;
        var search = searchText.toLowerCase().trim();
        return anomalies.filter(function(a) {
            // Search in matched_value
            if (a.matched_value && a.matched_value.toLowerCase().indexOf(search) !== -1) return true;
            // Search in human_context.short_message
            if (a.human_context && a.human_context.short_message &&
                a.human_context.short_message.toLowerCase().indexOf(search) !== -1) return true;
            // Search in human_context.explanation
            if (a.human_context && a.human_context.explanation &&
                a.human_context.explanation.toLowerCase().indexOf(search) !== -1) return true;
            return false;
        });
    }

    /**
     * Sort anomalies by field (Story 2.8 - AC4, AC5)
     * @param {Array} anomalies - List of anomalies
     * @param {string} field - 'score', 'value'
     * @param {string} direction - 'asc', 'desc'
     * @returns {Array} Sorted anomalies (new array)
     */
    function sortAnomalies(anomalies, field, direction) {
        var sorted = anomalies.slice(); // Clone array
        sorted.sort(function(a, b) {
            var valA, valB;
            switch (field) {
                case 'score':
                    valA = a.score || 0;
                    valB = b.score || 0;
                    break;
                case 'value':
                    valA = (a.matched_value || '').toLowerCase();
                    valB = (b.matched_value || '').toLowerCase();
                    break;
                default:
                    valA = a.score || 0;
                    valB = b.score || 0;
            }

            if (valA < valB) return direction === 'asc' ? -1 : 1;
            if (valA > valB) return direction === 'asc' ? 1 : -1;
            return 0;
        });
        return sorted;
    }

    /**
     * Update filter count indicator (Story 2.8 - AC6)
     * @param {number} filtered - Number of filtered anomalies
     * @param {number} total - Total number of anomalies
     */
    function updateFilterCount(filtered, total) {
        if (filterCountEl) {
            if (filtered === total) {
                filterCountEl.textContent = total + ' anomalies';
            } else {
                filterCountEl.textContent = filtered + ' / ' + total + ' anomalies';
            }
        }
    }

    /**
     * Show empty state when filters return no results (Story 2.8 - AC6)
     */
    function showFilteredEmptyState() {
        if (anomalyListEl) {
            anomalyListEl.innerHTML =
                '<div class="anomaly-empty-state">' +
                    '<p class="text-muted text-center">Aucune anomalie ne correspond aux filtres</p>' +
                    '<button class="btn btn-outline" id="reset-filters-btn">Reinitialiser filtres</button>' +
                '</div>';

            var resetBtn = document.getElementById('reset-filters-btn');
            if (resetBtn) {
                resetBtn.addEventListener('click', resetFilters);
            }
        }
    }

    /**
     * Reset all filters to default (Story 2.8 - AC7)
     */
    function resetFilters() {
        if (severityFilterEl) severityFilterEl.value = 'all';
        if (typeFilterEl) typeFilterEl.value = 'all';
        if (searchFilterEl) searchFilterEl.value = '';

        // Reset sort indicators
        updateSortIndicators('score', 'desc');
        currentSortField = 'score';
        currentSortDirection = 'desc';

        applyAllFilters();
        console.debug('[anomalies] Filters reset to default');
    }

    /**
     * Apply all filters and re-render list (Story 2.8 - AC6)
     */
    function applyAllFilters() {
        var severity = severityFilterEl ? severityFilterEl.value : 'all';
        var matchType = typeFilterEl ? typeFilterEl.value : 'all';
        var searchText = searchFilterEl ? searchFilterEl.value : '';

        var filtered = allAnomalies.slice();
        filtered = filterBySeverity(filtered, severity);
        filtered = filterByType(filtered, matchType);
        filtered = filterBySearch(filtered, searchText);
        filtered = sortAnomalies(filtered, currentSortField, currentSortDirection);

        console.debug('[anomalies] Filter applied (severity=' + severity + ', type=' + matchType + ', search="' + searchText + '")');
        console.debug('[anomalies] Sort applied (field=' + currentSortField + ', direction=' + currentSortDirection + ')');
        console.info('[anomalies] Filtered ' + filtered.length + '/' + allAnomalies.length + ' anomalies displayed');

        updateFilterCount(filtered.length, allAnomalies.length);

        if (filtered.length === 0 && allAnomalies.length > 0) {
            showFilteredEmptyState();
        } else if (filtered.length === 0) {
            showEmptyState();
        } else {
            renderAnomalyList({ anomalies: filtered, total: filtered.length }, true);
        }
    }

    /**
     * Toggle sort direction on header click (Story 2.8 - AC4, AC5)
     * @param {string} field - Field to sort by
     */
    function toggleSort(field) {
        if (currentSortField === field) {
            currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            currentSortField = field;
            currentSortDirection = field === 'score' ? 'desc' : 'asc';
        }

        updateSortIndicators(currentSortField, currentSortDirection);
        applyAllFilters();
    }

    /**
     * Update visual sort indicators (Story 2.8 - AC4)
     * @param {string} field - Current sort field
     * @param {string} direction - Current sort direction
     */
    function updateSortIndicators(field, direction) {
        var headers = document.querySelectorAll('.sortable-header');
        headers.forEach(function(header) {
            var indicator = header.querySelector('.sort-indicator');
            var headerField = header.getAttribute('data-sort-field');

            if (indicator) {
                if (headerField === field) {
                    indicator.classList.add('active');
                    indicator.textContent = direction === 'asc' ? '\u25B2' : '\u25BC';
                } else {
                    indicator.classList.remove('active');
                    indicator.textContent = '\u25BC';
                }
            }
        });
    }

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
                    // Store all anomalies for filtering (Story 2.8)
                    allAnomalies = data.result.anomalies || [];
                    console.debug('[anomalies] Loaded ' + allAnomalies.length + ' anomalies into memory');

                    // Apply initial sort and render
                    applyAllFilters();
                    updateSummarySection(data.result.by_criticality);
                    var total = data.result.total || 0;
                    var byCrit = data.result.by_criticality || {};
                    console.info('[anomalies] Rendered ' + total + ' anomalies (critical=' +
                        (byCrit.critical || 0) + ', warning=' + (byCrit.warning || 0) +
                        ', normal=' + (byCrit.normal || 0) + ')');
                } else {
                    allAnomalies = [];
                    showEmptyState();
                    updateFilterCount(0, 0);
                }
            })
            .catch(function(error) {
                console.error('[anomalies] Error loading anomalies:', error);
                allAnomalies = [];
                showEmptyState();
                updateFilterCount(0, 0);
            });
    }

    /**
     * Render the anomaly list
     * @param {Object} result - API result with anomalies array
     * @param {boolean} skipSort - Skip sorting if already sorted by filters
     */
    function renderAnomalyList(result, skipSort) {
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

        // Sort by score descending if not already sorted by filters
        if (!skipSort) {
            anomalies.sort(function(a, b) {
                return b.score - a.score;
            });
        }

        // Build HTML with sortable headers (Story 2.8)
        var html = buildSortableHeaders();
        anomalies.forEach(function(anomaly) {
            html += renderAnomalyItem(anomaly);
        });

        anomalyListEl.innerHTML = html;

        // Add event listeners for sort headers (Story 2.8)
        addSortHeaderListeners();

        // Add event listeners for action buttons
        addActionListeners();
    }

    /**
     * Build sortable headers HTML (Story 2.8 - AC4, AC5)
     * @returns {string} HTML for sortable headers
     */
    function buildSortableHeaders() {
        var scoreIndicator = currentSortField === 'score' ?
            (currentSortDirection === 'asc' ? '\u25B2' : '\u25BC') : '\u25BC';
        var valueIndicator = currentSortField === 'value' ?
            (currentSortDirection === 'asc' ? '\u25B2' : '\u25BC') : '\u25BC';
        var scoreActive = currentSortField === 'score' ? ' active' : '';
        var valueActive = currentSortField === 'value' ? ' active' : '';

        return '<div class="anomaly-list-headers">' +
            '<span class="sortable-header" data-sort-field="value">' +
                'IP/Valeur <span class="sort-indicator' + valueActive + '">' + valueIndicator + '</span>' +
            '</span>' +
            '<span class="sortable-header" data-sort-field="score">' +
                'Score <span class="sort-indicator' + scoreActive + '">' + scoreIndicator + '</span>' +
            '</span>' +
        '</div>';
    }

    /**
     * Add click listeners to sortable headers (Story 2.8)
     */
    function addSortHeaderListeners() {
        var headers = document.querySelectorAll('.sortable-header');
        headers.forEach(function(header) {
            header.addEventListener('click', function() {
                var field = this.getAttribute('data-sort-field');
                if (field) {
                    toggleSort(field);
                }
            });
        });
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
            var items = anomalyListEl.querySelectorAll('.anomaly-item, .anomaly-list-headers');
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
     * Setup filter event listeners (Story 2.8)
     */
    function setupFilterListeners() {
        // Severity filter change
        if (severityFilterEl) {
            severityFilterEl.addEventListener('change', function() {
                applyAllFilters();
            });
        }

        // Type filter change
        if (typeFilterEl) {
            typeFilterEl.addEventListener('change', function() {
                applyAllFilters();
            });
        }

        // Search filter with debounce (100ms per AC1 spec: <100ms)
        if (searchFilterEl) {
            var debouncedSearch = debounce(function() {
                applyAllFilters();
            }, 100);
            searchFilterEl.addEventListener('input', debouncedSearch);
        }

        console.debug('[anomalies] Filter listeners initialized');
    }

    /**
     * Initialize the anomalies page module
     */
    function init() {
        console.debug('[anomalies] Initializing anomalies page module');
        setupFilterListeners();
        loadAnomalies();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
