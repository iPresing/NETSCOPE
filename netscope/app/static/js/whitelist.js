/**
 * NETSCOPE Whitelist Management Module (Story 3.6)
 *
 * Handles whitelist CRUD operations on the /whitelist page.
 * Consumes API endpoints /api/whitelist (GET, POST, DELETE)
 *
 * Lessons Learned Epic 1/2/3:
 * - IIFE pattern with 'use strict'
 * - Use NetScopeUtils.escapeHtml() for XSS protection
 * - Always check element existence before DOM manipulation
 * - Always validate response.ok before parsing JSON
 */
(function() {
    'use strict';

    // DOM Elements
    var addForm = document.getElementById('whitelist-add-form');
    var valueInput = document.getElementById('wl-value');
    var reasonInput = document.getElementById('wl-reason');
    var addBtn = document.getElementById('wl-add-btn');
    var tbody = document.getElementById('whitelist-tbody');
    var countEl = document.getElementById('wl-count');
    var emptyEl = document.getElementById('whitelist-empty');
    var tableEl = document.getElementById('whitelist-table');

    // Use shared utilities from NetScopeUtils
    var escapeHtml = window.NetScopeUtils ? window.NetScopeUtils.escapeHtml : function(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    var showToast = window.NetScopeUtils ? window.NetScopeUtils.showToast : function() {};

    /**
     * Type labels for display
     */
    var TYPE_LABELS = {
        'ip': 'IP',
        'port': 'Port',
        'ip_port': 'IP:Port'
    };

    /**
     * Validation patterns
     */
    var IP_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    var PORT_PATTERN = /^\d+$/;
    var IP_PORT_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?):\d+$/;

    /**
     * Validate whitelist value format
     * @param {string} value - Value to validate
     * @returns {boolean} True if valid
     */
    function isValidValue(value) {
        if (!value || value.trim() === '') {
            return false;
        }
        value = value.trim();

        // Check IP:Port format
        if (IP_PORT_PATTERN.test(value)) {
            var parts = value.split(':');
            var port = parseInt(parts[1], 10);
            return port >= 1 && port <= 65535;
        }

        // Check Port format
        if (PORT_PATTERN.test(value)) {
            var port = parseInt(value, 10);
            return port >= 1 && port <= 65535;
        }

        // Check IP format
        if (IP_PATTERN.test(value)) {
            return true;
        }

        return false;
    }

    /**
     * Load all whitelist entries from API and render table
     */
    function loadWhitelistEntries() {
        fetch('/api/whitelist')
            .then(function(response) {
                if (!response.ok) {
                    throw new Error('HTTP error ' + response.status);
                }
                return response.json();
            })
            .then(function(data) {
                if (data.success) {
                    renderTable(data.result.entries);
                    updateCount(data.result.count);
                }
            })
            .catch(function(error) {
                console.error('[whitelist] Error loading entries:', error);
                showToast('Erreur lors du chargement de la whitelist', 'error');
            });
    }

    /**
     * Add a whitelist entry via API
     * @param {string} value - IP, Port, or IP:Port
     * @param {string} reason - Optional reason
     */
    function addWhitelistEntry(value, reason) {
        fetch('/api/whitelist', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({value: value, reason: reason})
        })
        .then(function(response) {
            if (!response.ok) {
                return response.json().then(function(data) {
                    throw data;
                });
            }
            return response.json();
        })
        .then(function(data) {
            if (data.success) {
                showToast('Element ajoute a la whitelist', 'success');
                if (valueInput) valueInput.value = '';
                if (reasonInput) reasonInput.value = '';
                loadWhitelistEntries();
            }
        })
        .catch(function(error) {
            var msg = error.error ? error.error.message : 'Erreur lors de l\'ajout';
            showToast(msg, 'error');
        });
    }

    /**
     * Remove a whitelist entry via API
     * @param {string} entryId - ID of the entry to remove
     */
    function removeWhitelistEntry(entryId) {
        fetch('/api/whitelist/' + entryId, {
            method: 'DELETE'
        })
        .then(function(response) {
            if (!response.ok) {
                return response.json().then(function(data) {
                    throw data;
                });
            }
            return response.json();
        })
        .then(function(data) {
            if (data.success) {
                showToast('Element supprime de la whitelist', 'success');
                loadWhitelistEntries();
            }
        })
        .catch(function(error) {
            var msg = error.error ? error.error.message : 'Erreur lors de la suppression';
            showToast(msg, 'error');
        });
    }

    /**
     * Render the whitelist table
     * @param {Array} entries - List of whitelist entries
     */
    function renderTable(entries) {
        if (!tbody) return;

        if (entries.length === 0) {
            tbody.innerHTML = '';
            if (emptyEl) emptyEl.style.display = 'block';
            if (tableEl) tableEl.style.display = 'none';
            return;
        }

        if (emptyEl) emptyEl.style.display = 'none';
        if (tableEl) tableEl.style.display = '';

        var html = '';
        entries.forEach(function(entry) {
            var typeLabel = TYPE_LABELS[entry.entry_type] || entry.entry_type;
            var dateStr = entry.created_at ? new Date(entry.created_at).toLocaleString('fr-FR') : '';
            var reason = entry.reason || '-';

            html += '<tr data-entry-id="' + escapeHtml(entry.id) + '">' +
                '<td>' + escapeHtml(typeLabel) + '</td>' +
                '<td><code>' + escapeHtml(entry.value) + '</code></td>' +
                '<td>' + escapeHtml(dateStr) + '</td>' +
                '<td>' + escapeHtml(reason) + '</td>' +
                '<td>' +
                    '<button class="btn btn-sm btn-danger btn-wl-delete" data-id="' + escapeHtml(entry.id) + '">' +
                        'Supprimer' +
                    '</button>' +
                '</td>' +
            '</tr>';
        });

        tbody.innerHTML = html;

        // Add delete button listeners
        var deleteBtns = tbody.querySelectorAll('.btn-wl-delete');
        deleteBtns.forEach(function(btn) {
            btn.addEventListener('click', function() {
                var id = this.getAttribute('data-id');
                if (id) {
                    removeWhitelistEntry(id);
                }
            });
        });
    }

    /**
     * Update entry count display
     * @param {number} count - Number of entries
     */
    function updateCount(count) {
        if (countEl) {
            countEl.textContent = count;
        }
    }

    /**
     * Initialize the whitelist page
     */
    function init() {
        console.debug('[whitelist] Initializing whitelist page module');

        // Add form submit handler
        if (addForm) {
            addForm.addEventListener('submit', function(e) {
                e.preventDefault();
                var value = valueInput ? valueInput.value.trim() : '';
                var reason = reasonInput ? reasonInput.value.trim() : '';

                if (!value) {
                    showToast('Veuillez entrer une valeur', 'error');
                    return;
                }

                if (!isValidValue(value)) {
                    showToast('Format invalide. Attendu: IP (192.168.1.1), Port (8080) ou IP:Port (192.168.1.1:8080)', 'error');
                    return;
                }

                addWhitelistEntry(value, reason);
            });
        }

        // Load entries
        loadWhitelistEntries();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
