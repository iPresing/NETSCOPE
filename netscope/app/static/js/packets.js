/**
 * NETSCOPE Packet Viewer Module (Story 4.4)
 *
 * Displays paginated packet table from pcap files.
 * Supports filtering by protocol/direction and anomaly context.
 */
(function() {
    'use strict';

    // DOM elements
    var tbodyEl = document.getElementById('packets-tbody');
    var bannerEl = document.getElementById('anomaly-context-banner');
    var packetCountEl = document.getElementById('packet-count');
    var paginationEl = document.getElementById('packet-pagination');
    var prevPageBtn = document.getElementById('prev-page');
    var nextPageBtn = document.getElementById('next-page');
    var paginationInfoEl = document.getElementById('pagination-info');
    var protocolFilterEl = document.getElementById('protocol-filter');
    var directionFilterEl = document.getElementById('direction-filter');

    // State
    var currentPage = 1;
    var totalPages = 1;
    var captureId = null;
    var anomalyId = null;
    var filterIp = null;
    var filterDomain = null;
    var filterPort = null;
    var filterProtocol = null;
    var filterDirection = null;
    var isManualFilter = false;
    var allPackets = []; // Current page packets for local filtering

    // Manual filter banner element
    var manualBannerEl = document.getElementById('manual-filter-banner');

    var escapeHtml = window.NetScopeUtils ? window.NetScopeUtils.escapeHtml : function(text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    /**
     * Parse URL query parameters
     */
    function getUrlParams() {
        var params = new URLSearchParams(window.location.search);
        anomalyId = params.get('anomaly_id');
        captureId = params.get('capture_id');
        filterIp = params.get('filter_ip') || params.get('ip');
        filterDomain = params.get('filter_domain');
        filterPort = params.get('port') ? parseInt(params.get('port'), 10) : null;
        filterProtocol = params.get('protocol') || null;
        filterDirection = params.get('direction') || null;
        var pageParam = params.get('page');
        if (pageParam) currentPage = parseInt(pageParam, 10) || 1;

        // Manual filter context (from inspection form, not anomaly)
        isManualFilter = !anomalyId && !!(filterIp || filterPort || filterProtocol || filterDirection);

        // Pre-fill select filters from URL params
        if (filterProtocol && protocolFilterEl) {
            protocolFilterEl.value = filterProtocol;
        }
        if (filterDirection && directionFilterEl) {
            directionFilterEl.value = filterDirection;
        }
    }

    /**
     * Build API URL with current parameters
     */
    function buildApiUrl(page) {
        var url = '/api/packets?per_page=50&page=' + page;
        if (anomalyId) url += '&anomaly_id=' + encodeURIComponent(anomalyId);
        if (captureId) url += '&capture_id=' + encodeURIComponent(captureId);
        if (filterIp) url += '&ip=' + encodeURIComponent(filterIp);
        if (filterDomain) url += '&filter_domain=' + encodeURIComponent(filterDomain);
        if (filterPort) url += '&port=' + filterPort;
        if (filterProtocol) url += '&protocol=' + encodeURIComponent(filterProtocol);
        if (filterDirection) url += '&direction=' + encodeURIComponent(filterDirection);
        return url;
    }

    /**
     * Load packets from API
     */
    function loadPackets(page) {
        currentPage = page || 1;
        var url = buildApiUrl(currentPage);

        console.debug('[packets] Fetching ' + url);

        fetch(url)
            .then(function(response) {
                if (!response.ok) {
                    return response.json().then(function(err) { throw err; });
                }
                return response.json();
            })
            .then(function(data) {
                if (data.success && data.result) {
                    var result = data.result;
                    captureId = result.capture_id;
                    allPackets = result.packets || [];
                    totalPages = result.pagination.total_pages;
                    currentPage = result.pagination.page;

                    // Show context banners (mutually exclusive)
                    if (result.anomaly_context) {
                        showAnomalyBanner(result.anomaly_context);
                    } else if (isManualFilter) {
                        showManualFilterBanner();
                    }

                    // Render
                    renderPacketTable(allPackets);
                    updatePagination(result.pagination);
                    updatePacketCount(result.filter_summary);
                } else {
                    showError(data.error ? data.error.message : 'Erreur inconnue');
                }
            })
            .catch(function(error) {
                var msg = error.error ? error.error.message : (error.message || 'Erreur reseau');
                showError(msg);
                console.error('[packets] Error:', error);
            });
    }

    /**
     * Show manual filter banner (from inspection form)
     */
    function showManualFilterBanner() {
        if (!manualBannerEl || !isManualFilter) return;
        manualBannerEl.style.display = 'block';

        var detailsEl = document.getElementById('manual-filter-details');
        if (detailsEl) {
            var badges = [];
            if (filterIp) badges.push('<span class="badge badge-info">IP: ' + escapeHtml(filterIp) + '</span>');
            if (filterPort) badges.push('<span class="badge badge-info">Port: ' + filterPort + '</span>');
            if (filterProtocol) badges.push('<span class="badge badge-info">Protocole: ' + escapeHtml(filterProtocol) + '</span>');
            if (filterDirection) badges.push('<span class="badge badge-info">Direction: ' + escapeHtml(filterDirection) + '</span>');
            detailsEl.innerHTML = badges.join(' ');
        }
    }

    /**
     * Show anomaly context banner
     */
    function showAnomalyBanner(ctx) {
        if (!bannerEl) return;
        bannerEl.style.display = 'block';

        var valueEl = document.getElementById('banner-matched-value');
        var typeEl = document.getElementById('banner-match-type');
        var scoreEl = document.getElementById('banner-score');

        if (valueEl) valueEl.textContent = ctx.matched_value || '';
        if (typeEl) {
            var typeLabels = { ip: 'IP', domain: 'Domaine', term: 'Terme' };
            typeEl.textContent = typeLabels[ctx.match_type] || ctx.match_type;
            typeEl.className = 'banner-type badge badge-' + (ctx.criticality === 'critical' ? 'danger' : ctx.criticality === 'warning' ? 'warning' : 'success');
        }
        if (scoreEl) scoreEl.textContent = 'Score: ' + ctx.score + '/100';
    }

    /**
     * Render packet table rows
     */
    function renderPacketTable(packets) {
        if (!tbodyEl) return;

        var protocol = protocolFilterEl ? protocolFilterEl.value : 'all';
        var direction = directionFilterEl ? directionFilterEl.value : 'all';

        // Local filtering
        var filtered = packets;
        if (protocol !== 'all') {
            filtered = filtered.filter(function(p) { return p.protocol === protocol; });
        }
        if (direction !== 'all' && filterIp) {
            filtered = filtered.filter(function(p) {
                if (direction === 'src') return p.ip_src === filterIp;
                if (direction === 'dst') return p.ip_dst === filterIp;
                return true;
            });
        }

        if (filtered.length === 0) {
            tbodyEl.innerHTML =
                '<tr class="placeholder-row">' +
                    '<td colspan="8" class="text-muted text-center">Aucun paquet trouve</td>' +
                '</tr>';
            return;
        }

        var html = '';
        filtered.forEach(function(pkt) {
            var time = pkt.timestamp ? new Date(pkt.timestamp).toLocaleTimeString('fr-FR', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 }) : '';
            var src = escapeHtml(pkt.ip_src || '') + (pkt.port_src ? ':' + pkt.port_src : '');
            var dst = escapeHtml(pkt.ip_dst || '') + (pkt.port_dst ? ':' + pkt.port_dst : '');
            var flags = escapeHtml(pkt.tcp_flags || '');
            var info = '';
            if (pkt.dns_queries && pkt.dns_queries.length > 0) {
                info = 'DNS: ' + escapeHtml(pkt.dns_queries[0]);
            } else if (pkt.http_host) {
                info = 'HTTP: ' + escapeHtml(pkt.http_host);
            }

            html += '<tr class="packet-row" data-capture-id="' + escapeHtml(captureId) + '" data-packet-index="' + pkt.index + '">' +
                '<td class="timestamp-cell">' + pkt.index + '</td>' +
                '<td class="timestamp-cell">' + time + '</td>' +
                '<td class="ip-cell">' + src + '</td>' +
                '<td class="ip-cell">' + dst + '</td>' +
                '<td class="proto-cell">' + escapeHtml(pkt.protocol || '') + '</td>' +
                '<td class="size-cell">' + (pkt.length || 0) + '</td>' +
                '<td class="proto-cell">' + flags + '</td>' +
                '<td class="text-muted">' + info + '</td>' +
            '</tr>';
        });

        tbodyEl.innerHTML = html;

        // Add click listeners for packet detail (Story 4.5)
        var rows = tbodyEl.querySelectorAll('.packet-row');
        rows.forEach(function(row) {
            row.addEventListener('click', function() {
                var cid = this.getAttribute('data-capture-id');
                var idx = parseInt(this.getAttribute('data-packet-index'), 10);
                if (window.showPacketDetail) {
                    // Highlight selected row
                    rows.forEach(function(r) { r.classList.remove('selected'); });
                    this.classList.add('selected');
                    window.showPacketDetail(cid, idx);
                }
            });
        });
    }

    /**
     * Update pagination controls
     */
    function updatePagination(pagination) {
        if (!paginationEl) return;
        paginationEl.style.display = 'flex';

        totalPages = pagination.total_pages;
        currentPage = pagination.page;

        if (paginationInfoEl) {
            paginationInfoEl.textContent = 'Page ' + currentPage + '/' + totalPages;
        }
        if (prevPageBtn) prevPageBtn.disabled = (currentPage <= 1);
        if (nextPageBtn) nextPageBtn.disabled = (currentPage >= totalPages);
    }

    /**
     * Update packet count display
     */
    function updatePacketCount(filterSummary) {
        if (!packetCountEl) return;
        if (filterSummary.total_filtered === filterSummary.total_unfiltered) {
            packetCountEl.textContent = filterSummary.total_filtered + ' paquets';
        } else {
            packetCountEl.textContent = filterSummary.total_filtered + ' / ' + filterSummary.total_unfiltered + ' paquets';
        }
    }

    /**
     * Show error in table
     */
    function showError(message) {
        if (!tbodyEl) return;
        tbodyEl.innerHTML =
            '<tr class="placeholder-row">' +
                '<td colspan="8" class="text-muted text-center">' + escapeHtml(message) + '</td>' +
            '</tr>';
    }

    /**
     * Setup event listeners
     */
    function setupListeners() {
        if (prevPageBtn) {
            prevPageBtn.addEventListener('click', function() {
                if (currentPage > 1) loadPackets(currentPage - 1);
            });
        }
        if (nextPageBtn) {
            nextPageBtn.addEventListener('click', function() {
                if (currentPage < totalPages) loadPackets(currentPage + 1);
            });
        }

        // Clear manual filters button (attached once, not on every loadPackets)
        var clearBtn = document.getElementById('clear-manual-filters');
        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                window.location.href = '/packets';
            });
        }

        // Local filters re-render current data
        if (protocolFilterEl) {
            protocolFilterEl.addEventListener('change', function() {
                renderPacketTable(allPackets);
            });
        }
        if (directionFilterEl) {
            directionFilterEl.addEventListener('change', function() {
                renderPacketTable(allPackets);
            });
        }
    }

    /**
     * Initialize
     */
    function init() {
        console.debug('[packets] Initializing packet viewer');
        getUrlParams();

        if (!captureId && !anomalyId && !isManualFilter) {
            showError('Aucun capture_id, anomaly_id ou filtre specifie');
            return;
        }

        setupListeners();
        loadPackets(currentPage);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
