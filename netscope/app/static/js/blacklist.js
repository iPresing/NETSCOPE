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
    // Story 4b.9: panneau Sources
    var sourcesGrid = document.getElementById('bl-sources-grid');
    var sourcesCountEl = document.getElementById('bl-sources-count');

    // Story 4b.9: mapping valeur → nom fichier (ex: "ip:1.2.3.4" → "ips_malware.txt")
    // Construit depuis la réponse /api/blacklists/active.by_file
    var valueToFile = {};
    // Mapping nom fichier → short label (ex: "ips_malware.txt" → "ips_malware")
    var fileToShortName = {};

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
     * Build value-to-file index from /api/blacklists/active.by_file
     * so that each default entry can display the file it came from
     * (story 4b.9 AC4)
     * @param {Object} byFile - Mapping {filename: [entries]}
     */
    function indexByFile(byFile) {
        valueToFile = {};
        if (!byFile || typeof byFile !== 'object') return;
        Object.keys(byFile).forEach(function(filename) {
            var entries = byFile[filename];
            if (!Array.isArray(entries)) return;
            // Inférer le type depuis le nom du fichier
            var typeKey = 'term';
            if (filename.indexOf('ips_') === 0 || filename.indexOf('ip_') === 0) {
                typeKey = 'ip';
            } else if (filename.indexOf('domains_') === 0 || filename.indexOf('domain_') === 0) {
                typeKey = 'domain';
            }
            entries.forEach(function(entry) {
                var key = typeKey + ':' + (typeKey === 'domain' ? entry.toLowerCase() : entry);
                valueToFile[key] = filename;
            });
        });
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

            // Story 4b.9: indexer by_file avant le rendu pour attribution source
            if (activeData.success && activeData.result) {
                indexByFile(activeData.result.by_file);
            }

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
            var sourceBadge;
            if (isUser) {
                sourceBadge = '<span class="badge badge-user">user</span>';
            } else {
                // Story 4b.9: afficher le nom court du fichier si connu
                var lookupKey = entry.entry_type + ':' + (entry.entry_type === 'domain' ? String(entry.value).toLowerCase() : entry.value);
                var fileName = valueToFile[lookupKey];
                var shortName = fileName ? (fileToShortName[fileName] || fileName.replace(/\.txt$/, '')) : '';
                sourceBadge = shortName
                    ? '<span class="badge badge-default">default · ' + escapeHtml(shortName) + '</span>'
                    : '<span class="badge badge-default">default</span>';
            }
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
     * Load and render the default sources panel (story 4b.9 AC4)
     */
    function loadSourcesPanel() {
        if (!sourcesGrid) return;

        fetch('/api/blacklists/sources')
            .then(function(r) {
                if (!r.ok) throw new Error('HTTP error ' + r.status);
                return r.json();
            })
            .then(function(data) {
                if (!data.success || !data.result) {
                    sourcesGrid.innerHTML = '<p class="text-muted">' +
                        'Aucune source par défaut disponible.</p>';
                    return;
                }
                var metas = data.result.sources || [];
                if (sourcesCountEl) {
                    sourcesCountEl.textContent = metas.length;
                }
                // Indexer fileToShortName pour rendu table
                metas.forEach(function(m) {
                    if (m.file && m.name) {
                        fileToShortName[m.file] = m.name;
                    }
                });

                if (metas.length === 0) {
                    sourcesGrid.innerHTML = '<p class="text-muted">' +
                        'Aucune métadonnée .meta.yaml trouvée.</p>';
                    return;
                }

                var html = '';
                metas.forEach(function(meta) {
                    var sources = Array.isArray(meta.sources) ? meta.sources : [];
                    var sourceBadges = sources.map(function(s) {
                        var name = escapeHtml(s.name || 'unknown');
                        var license = escapeHtml(s.license || '');
                        var url = s.url || '';
                        if (url && /^https?:\/\//.test(url)) {
                            return '<a class="badge badge-source" href="' +
                                escapeHtml(url) + '" target="_blank" ' +
                                'rel="noopener noreferrer" title="' + license + '">' +
                                name + ' <span class="license">(' + license + ')</span></a>';
                        }
                        return '<span class="badge badge-source" title="' + license + '">' +
                            name + ' <span class="license">(' + license + ')</span></span>';
                    }).join(' ');

                    var lastUpdated = meta.last_updated
                        ? new Date(meta.last_updated).toLocaleDateString('fr-FR')
                        : '-';

                    html += '<div class="bl-source-card">' +
                        '<div class="bl-source-header">' +
                            '<span class="bl-source-name">' + escapeHtml(meta.name || meta.file || '') + '</span>' +
                            '<span class="bl-source-count">' + escapeHtml(String(meta.entries_count || 0)) + ' entrées</span>' +
                        '</div>' +
                        '<p class="bl-source-desc">' + escapeHtml(meta.description || '') + '</p>' +
                        '<div class="bl-source-badges">' + sourceBadges + '</div>' +
                        '<p class="bl-source-updated text-muted">Mis à jour : ' +
                            escapeHtml(lastUpdated) + '</p>' +
                        '</div>';
                });
                sourcesGrid.innerHTML = html;

                // Re-render table if already loaded so badges reflect fileToShortName
                loadBlacklistEntries();
            })
            .catch(function(error) {
                console.error('[blacklist] Error loading sources panel:', error);
                if (sourcesGrid) {
                    sourcesGrid.innerHTML = '<p class="text-muted">' +
                        'Impossible de charger les sources par défaut.</p>';
                }
                // Fallback: charger la liste même si le panneau a échoué
                loadBlacklistEntries();
            });
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

        // Story 4b.9: charger le panneau sources (qui déclenche loadBlacklistEntries
        // après pour que le mapping fileToShortName soit à jour)
        loadSourcesPanel();
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
