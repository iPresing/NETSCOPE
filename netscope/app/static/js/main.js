/**
 * NETSCOPE Main JavaScript
 * Version: 0.1.0
 *
 * Core JavaScript functionality for NETSCOPE dashboard.
 * Uses Vanilla ES6+ - no frameworks.
 *
 * Note: Toast functionality is provided by toasts.js
 * Note: API client is provided by api.js
 */

(function() {
    'use strict';

    /**
     * Initialize the application when DOM is ready.
     */
    function init() {
        console.log('[NETSCOPE] Application initialized');
        initNavigation();
    }

    /**
     * Initialize navigation highlighting.
     * Adds 'is-active' class to current page link.
     */
    function initNavigation() {
        const currentPath = window.location.pathname;
        const navLinks = document.querySelectorAll('.nav-link');

        navLinks.forEach(function(link) {
            const href = link.getAttribute('href');
            if (href === currentPath) {
                link.classList.add('is-active');
            }
        });
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
