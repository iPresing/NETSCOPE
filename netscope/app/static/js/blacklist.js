/**
 * NETSCOPE Blacklist Management Module (Story 4b.6)
 *
 * Handles blacklist CRUD operations on the /blacklist page.
 * Consumes API endpoints /api/blacklists (POST, DELETE), /api/blacklists/user (GET),
 * /api/blacklists/active (GET)
 *
 * Lessons Learned Epic 1/2/3/4:
 * - IIFE pattern with 'use strict'
 * - Use NetScopeUtils.escapeHtml() for XSS protection (retro rule #3)
 * - Always check element existence before DOM manipulation
 * - Always validate response.ok before parsing JSON
 */
(function() {
    'use strict';

    // DOM Elements
    var addForm = document.getElementById('blacklist-add-form');
    var typeSelect = document.getElementById('bl-type');
    var valueInput = document.getElementById('bl-value');
    var reasonInput = document.getElementById('bl-reason');
    var addBtn = document.getElementById('bl-add-btn');
    var tbody = document.getElementById('blacklist-tbody');
    var countEl = document.getElementById('bl-count');
    var emptyEl = document.getElementById('blacklist-empty');
    var tableEl = document.getElementById('blacklist-table');

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
        'domain': 'Domaine',
        'term': 'Terme'
    };

    /**
     * Validation patterns
     */
    var IP_PATTERN = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
    var DOMAIN_PATTERN = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?$/;

    /**
     * Validate blacklist value based on selected type
     * @param {string} value - Value to validate
     * @param {string} type - Entry type (ip, domain, term)
     * @returns {string|null} Error message or null if valid
     */
    function validateValue(value, type) {
        if (!value || value.trim() === '') {
            return 'Veuillez entrer une valeur';
        }
        value = value.trim();

        if (type === 'ip') {
            if (!IP_PATTERN.test(value)) {
                return 'Format IP invalide (ex: 192.168.1.100)';
            }
        } else if (type === 'domain') {
            if (!DOMAIN_PATTERN.test(value) || !/[a-zA-Z]/.test(value)) {
                return 'Format domaine invalide (ex: evil.com)';
            }
            if (value.length > 253) {
                return 'Domaine trop long (max 253 caractères)';
            }
        } else if (type === 'term') {
            if (value.length < 2) {
                return 'Terme trop court (min 2 caractères)';
            }
            if (value.length > 200) {
                return 'Terme trop long (max 200 caractères)';
            }
        }

        return null;
    }

    /**
     * Load all blacklist entries (defaults + user) and render table
     */
    function loadBlacklistEntries() {
        Promise.all([
            fetch('/api/blacklists/active').then(function(r) {
                if (!r.ok) throw new Error('HTTP error ' + r.status);
                return r.json();
            }),
            fetch('/api/blacklists/user').then(function(r) {
                if (!r.ok) throw new Error('HTTP error ' + r.status);
                return r.json();
            })
        ])
        .then(function(results) {
            var activeData = results[0];
            var userData = results[1];

            var allEntries = [];

            // Add default entries (from active lists)
            if (activeData.success && activeData.result) {
                var active = activeData.result;
                // Collect user values to avoid showing defaults that are also user entries
                var userValues = {};
                if (userData.success && userData.result) {
                    userData.result.entries.forEach(function(e) {
                        userValues[e.entry_type + ':' + e.value] = true;
                    });
                }

                if (active.ips) {
                    active.ips.forEach(function(ip) {
                        if (!userValues['ip:' + ip]) {
                            allEntries.push({
                                value: ip,
                                entry_type: 'ip',
                                source: 'default',
                                reason: '',
                                created_at: null,
                                id: null
                            });
                        }
                    });
                }
                if (active.domains) {
                    active.domains.forEach(function(d) {
                        if (!userValues['domain:' + d]) {
                            allEntries.push({
                                value: d,
                                entry_type: 'domain',
                                source: 'default',
                                reason: '',
                                created_at: null,
                                id: null
                            });
                        }
                    });
                }
                if (active.terms) {
                    active.terms.forEach(function(t) {
                        if (!userValues['term:' + t]) {
                            allEntries.push({
                                value: t,
                                entry_type: 'term',
                                source: 'default',
                                reason: '',
                                created_at: null,
                                id: null
                            });
                        }
                    });
                }
            }

            // Add user entries
            if (userData.success && userData.result) {
                userData.result.entries.forEach(function(entry) {
                    entry.source = 'user';
                    allEntries.push(entry);
                });
            }

            renderTable(allEntries);
            updateCount(allEntries.length);
        })
        .catch(function(error) {
            console.error('[blacklist] Error loading entries:', error);
            showToast('Erreur lors du chargement des blacklists', 'error');
        });
    }

    /**
     * Add a blacklist entry via API
     * @param {string} value - IP, domain, or term
     * @param {string} type - Entry type
     * @param {string} reason - Optional reason
     */
    function addBlacklistEntry(value, type, reason) {
        fetch('/api/blacklists', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({value: value, type: type, reason: reason})
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
                showToast('Element ajoute a la blacklist', 'success');
                if (valueInput) valueInput.value = '';
                if (reasonInput) reasonInput.value = '';
                loadBlacklistEntries();
            }
        })
        .catch(function(error) {
            var msg = error.error ? error.error.message : 'Erreur lors de l\'ajout';
            showToast(msg, 'error');
        });
    }

    /**
     * Remove a blacklist entry via API with confirmation
     * @param {string} entryId - ID of the entry to remove
     * @param {string} entryValue - Value for confirmation dialog
     */
    function removeBlacklistEntry(entryId, entryValue) {
        if (!confirm('Supprimer "' + entryValue + '" de la blacklist ?')) {
            return;
        }

        fetch('/api/blacklists/' + encodeURIComponent(entryId), {
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
                showToast('Element supprime de la blacklist', 'success');
                loadBlacklistEntries();
            }
        })
        .catch(function(error) {
            var msg = error.error ? error.error.message : 'Erreur lors de la suppression';
            showToast(msg, 'error');
        });
    }

    /**
     * Render the blacklist table
     * @param {Array} entries - List of blacklist entries (defaults + user)
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
            var typeLabel = TYPE_LABELS[entry.entry_type] || escapeHtml(entry.entry_type);
            var isUser = entry.source === 'user';
            var sourceBadge = isUser
                ? '<span class="badge badge-user">user</span>'
                : '<span class="badge badge-default">default</span>';
            var dateStr = entry.created_at
                ? new Date(entry.created_at).toLocaleString('fr-FR')
                : '-';
            var reason = entry.reason || '-';

            var actions = '';
            if (isUser && entry.id) {
                actions = '<button class="btn btn-sm btn-danger btn-bl-delete" ' +
                    'data-id="' + escapeHtml(entry.id) + '" ' +
                    'data-value="' + escapeHtml(entry.value) + '">' +
                    'Supprimer</button>';
            }

            html += '<tr data-entry-id="' + escapeHtml(entry.id || '') + '">' +
                '<td>' + escapeHtml(typeLabel) + '</td>' +
                '<td><code>' + escapeHtml(entry.value) + '</code></td>' +
                '<td>' + sourceBadge + '</td>' +
                '<td>' + escapeHtml(reason) + '</td>' +
                '<td>' + escapeHtml(dateStr) + '</td>' +
                '<td>' + actions + '</td>' +
            '</tr>';
        });

        tbody.innerHTML = html;

        // Add delete button listeners
        var deleteBtns = tbody.querySelectorAll('.btn-bl-delete');
        deleteBtns.forEach(function(btn) {
            btn.addEventListener('click', function() {
                var id = this.getAttribute('data-id');
                var value = this.getAttribute('data-value');
                if (id) {
                    removeBlacklistEntry(id, value);
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
     * Update placeholder based on selected type
     */
    function updatePlaceholder() {
        if (!valueInput || !typeSelect) return;
        var type = typeSelect.value;
        var placeholders = {
            'ip': 'Ex: 192.168.1.100',
            'domain': 'Ex: evil.com, malware.example.org',
            'term': 'Ex: malware, trojan, reverse shell'
        };
        valueInput.placeholder = placeholders[type] || '';
    }

    /**
     * Initialize the blacklist page
     */
    function init() {
        console.debug('[blacklist] Initializing blacklist page module');

        // Type select change handler
        if (typeSelect) {
            typeSelect.addEventListener('change', updatePlaceholder);
        }

        // Add form submit handler
        if (addForm) {
            addForm.addEventListener('submit', function(e) {
                e.preventDefault();
                var value = valueInput ? valueInput.value.trim() : '';
                var type = typeSelect ? typeSelect.value : 'term';
                var reason = reasonInput ? reasonInput.value.trim() : '';

                var error = validateValue(value, type);
                if (error) {
                    showToast(error, 'error');
                    return;
                }

                addBlacklistEntry(value, type, reason);
            });
        }

        // Load entries
        loadBlacklistEntries();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
