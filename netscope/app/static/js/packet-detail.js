/**
 * NETSCOPE Packet Detail Panel Module (Story 4.5)
 *
 * Slide-in panel showing layer dissection, hex dump, and ASCII payload
 * for a selected packet. Called from packets.js on row click.
 */
(function() {
    'use strict';

    var panelEl = document.getElementById('packet-detail-panel');
    var titleEl = document.getElementById('detail-panel-title');
    var summaryEl = document.getElementById('detail-panel-summary');
    var layersTab = document.getElementById('tab-layers');
    var hexTab = document.getElementById('tab-hex');
    var asciiTab = document.getElementById('tab-ascii');
    var closeBtnEl = document.getElementById('close-detail-panel');

    var escapeHtml = window.NetScopeUtils ? window.NetScopeUtils.escapeHtml : function(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    /**
     * Show packet detail panel for a specific packet
     * @param {string} captureId - Capture session ID
     * @param {number} packetIndex - Packet index in pcap
     */
    function showPacketDetail(captureId, packetIndex) {
        if (!panelEl) return;

        // Show panel with loading state
        panelEl.style.display = 'flex';
        setTimeout(function() { panelEl.classList.add('open'); }, 10);

        if (titleEl) titleEl.textContent = 'Paquet #' + packetIndex + ' ...';
        if (summaryEl) summaryEl.textContent = 'Chargement...';
        if (layersTab) layersTab.innerHTML = '<p class="text-muted">Chargement...</p>';
        if (hexTab) hexTab.innerHTML = '';
        if (asciiTab) asciiTab.innerHTML = '';

        // Fetch detail
        var url = '/api/packets/' + encodeURIComponent(captureId) + '/' + packetIndex;
        console.debug('[packet-detail] Fetching ' + url);

        fetch(url)
            .then(function(response) {
                if (!response.ok) {
                    return response.json().then(function(err) { throw err; });
                }
                return response.json();
            })
            .then(function(data) {
                if (data.success && data.result) {
                    renderDetail(data.result);
                } else {
                    showDetailError(data.error ? data.error.message : 'Erreur inconnue');
                }
            })
            .catch(function(error) {
                var msg = error.error ? error.error.message : (error.message || 'Erreur reseau');
                showDetailError(msg);
                console.error('[packet-detail] Error:', error);
            });
    }

    /**
     * Render packet detail data
     */
    function renderDetail(detail) {
        if (titleEl) {
            titleEl.textContent = 'Paquet #' + detail.packet_index + ' (' + detail.raw_bytes_length + ' octets)';
        }

        if (summaryEl) {
            summaryEl.textContent = detail.summary || '';
        }

        // Render layers accordion
        if (layersTab) {
            renderLayers(detail.layers || []);
        }

        // Render hex dump
        if (hexTab) {
            if (detail.hex_dump) {
                hexTab.innerHTML = '<pre class="hex-dump-content">' + escapeHtml(detail.hex_dump) + '</pre>';
            } else {
                hexTab.innerHTML = '<p class="text-muted">Aucun dump hex disponible</p>';
            }
        }

        // Render ASCII
        if (asciiTab) {
            if (detail.ascii_dump) {
                asciiTab.innerHTML = '<pre class="ascii-dump-content">' + escapeHtml(detail.ascii_dump) + '</pre>';
            } else {
                asciiTab.innerHTML = '<p class="text-muted">Aucun payload ASCII</p>';
            }
        }
    }

    /**
     * Render layers as accordion
     */
    function renderLayers(layers) {
        if (!layersTab) return;

        if (layers.length === 0) {
            layersTab.innerHTML = '<p class="text-muted">Aucune couche detectee</p>';
            return;
        }

        var html = '';
        layers.forEach(function(layer, index) {
            var isOpen = index === 0 ? ' open' : '';
            html += '<div class="layer-accordion' + isOpen + '">';
            html += '<div class="layer-header" data-layer-index="' + index + '">';
            html += '<span class="layer-arrow">&#x25B6;</span> ';
            html += '<span class="layer-name">' + escapeHtml(layer.name) + '</span>';
            html += '<span class="layer-field-count">(' + (layer.fields ? layer.fields.length : 0) + ' champs)</span>';
            html += '</div>';
            html += '<div class="layer-body"' + (index === 0 ? '' : ' style="display: none;"') + '>';

            if (layer.fields && layer.fields.length > 0) {
                html += '<table class="layer-fields-table">';
                layer.fields.forEach(function(field) {
                    html += '<tr>';
                    html += '<td class="field-name">' + escapeHtml(field.name) + '</td>';
                    html += '<td class="field-value">' + escapeHtml(field.value) + '</td>';
                    html += '</tr>';
                });
                html += '</table>';
            } else {
                html += '<p class="text-muted text-sm">Aucun champ</p>';
            }

            html += '</div>';
            html += '</div>';
        });

        layersTab.innerHTML = html;

        // Add accordion toggle listeners
        var headers = layersTab.querySelectorAll('.layer-header');
        headers.forEach(function(header) {
            header.addEventListener('click', function() {
                var accordion = this.parentElement;
                var body = accordion.querySelector('.layer-body');
                var isOpen = accordion.classList.contains('open');

                if (isOpen) {
                    accordion.classList.remove('open');
                    body.style.display = 'none';
                } else {
                    accordion.classList.add('open');
                    body.style.display = 'block';
                }
            });
        });
    }

    /**
     * Show error in detail panel
     */
    function showDetailError(msg) {
        if (summaryEl) summaryEl.textContent = '';
        if (layersTab) {
            layersTab.innerHTML = '<p class="text-muted">' + escapeHtml(msg) + '</p>';
        }
    }

    /**
     * Close the detail panel
     */
    function closePanel() {
        if (!panelEl) return;
        panelEl.classList.remove('open');
        setTimeout(function() { panelEl.style.display = 'none'; }, 300);

        // Remove row selection
        var rows = document.querySelectorAll('.packet-row.selected');
        rows.forEach(function(r) { r.classList.remove('selected'); });
    }

    /**
     * Setup tab switching
     */
    function setupTabs() {
        var tabBtns = document.querySelectorAll('.tab-btn');
        var tabContents = document.querySelectorAll('.tab-content');

        tabBtns.forEach(function(btn) {
            btn.addEventListener('click', function() {
                var targetTab = this.getAttribute('data-tab');

                // Update buttons
                tabBtns.forEach(function(b) { b.classList.remove('active'); });
                this.classList.add('active');

                // Update content
                tabContents.forEach(function(tc) { tc.classList.remove('active'); });
                var target = document.getElementById('tab-' + targetTab);
                if (target) target.classList.add('active');
            });
        });
    }

    /**
     * Initialize
     */
    function init() {
        setupTabs();

        if (closeBtnEl) {
            closeBtnEl.addEventListener('click', closePanel);
        }

        // Close on Escape key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && panelEl && panelEl.classList.contains('open')) {
                closePanel();
            }
        });
    }

    // Expose global function for packets.js
    window.showPacketDetail = showPacketDetail;

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
