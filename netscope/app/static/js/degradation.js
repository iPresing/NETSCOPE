/**
 * NETSCOPE Degradation Monitor
 * Story 4.7: Graceful Degradation (FR44)
 *
 * Polls /api/system/status every 5s to show/hide degradation banner.
 * Uses IIFE + 'use strict' pattern (rule #5).
 */

(function() {
    'use strict';

    var POLL_INTERVAL = 5000;
    var banner = null;
    var reasonEl = null;
    var wasDegraded = false;
    var pollTimer = null;

    function init() {
        banner = document.getElementById('degradation-banner');
        reasonEl = document.getElementById('degradation-reason');

        if (!banner || !reasonEl) {
            return;
        }

        pollStatus();
        pollTimer = setInterval(pollStatus, POLL_INTERVAL);
    }

    function pollStatus() {
        fetch('/api/system/status')
            .then(function(response) {
                if (!response.ok) {
                    return null;
                }
                return response.json();
            })
            .then(function(data) {
                if (!data || !data.success) {
                    return;
                }
                updateBanner(data.result);
            })
            .catch(function(err) {
                console.error('[NETSCOPE Degradation] Poll error:', err);
            });
    }

    function updateBanner(result) {
        if (!banner || !reasonEl) {
            return;
        }

        var isDegraded = result.degradation && result.degradation.is_degraded;
        var reason = result.resources && result.resources.reason;

        if (isDegraded) {
            reasonEl.textContent = reason || 'Ressources surchargées';
            banner.style.display = '';

            if (!wasDegraded && window.NetScopeUtils && window.NetScopeUtils.showToast) {
                window.NetScopeUtils.showToast(
                    'Mode économie activé — ' + (reason || 'CPU élevé'),
                    'warning'
                );
            }
        } else {
            banner.style.display = 'none';

            if (wasDegraded && window.NetScopeUtils && window.NetScopeUtils.showToast) {
                window.NetScopeUtils.showToast(
                    'Mode normal rétabli',
                    'success'
                );
            }
        }

        wasDegraded = isDegraded;
    }

    document.addEventListener('DOMContentLoaded', init);

})();
