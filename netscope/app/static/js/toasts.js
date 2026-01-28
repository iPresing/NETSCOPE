/**
 * NETSCOPE Toast Notifications
 * Version: 0.1.0
 *
 * Standalone toast notification system.
 * Uses Vanilla ES6+.
 */

(function() {
    'use strict';

    /**
     * Toast configuration.
     * Durations per AC2 (Story 2.9):
     * - info/success: 3000ms (defaultDuration)
     * - warning/error: 5000ms (set in respective functions)
     */
    var config = {
        position: 'top-right',
        defaultDuration: 3000,  // 3s for info/success (AC2)
        warningDuration: 5000,  // 5s for warning/error (AC2)
        maxToasts: 5
    };

    /**
     * Get or create toast container.
     * @returns {HTMLElement} Toast container
     */
    function getContainer() {
        var container = document.getElementById('toast-container');

        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        return container;
    }

    /**
     * Show a toast notification.
     * @param {string} message - Message to display
     * @param {string} type - Toast type: 'info', 'success', 'warning', 'error'
     * @param {number} duration - Display duration in ms
     */
    function show(message, type, duration) {
        type = type || 'info';
        duration = duration || config.defaultDuration;

        var container = getContainer();

        // Limit number of toasts
        while (container.children.length >= config.maxToasts) {
            container.removeChild(container.firstChild);
        }

        // Create toast element
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.setAttribute('role', 'alert');

        // Icon based on type
        var icons = {
            info: 'ℹ️',
            success: '✅',
            warning: '⚠️',
            error: '❌'
        };

        toast.innerHTML = '<span class="toast-icon">' + (icons[type] || '') + '</span>' +
                          '<span class="toast-message">' + escapeHtml(message) + '</span>';

        container.appendChild(toast);

        // Trigger animation
        requestAnimationFrame(function() {
            toast.classList.add('toast-visible');
        });

        // Auto-remove
        setTimeout(function() {
            toast.classList.remove('toast-visible');
            setTimeout(function() {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, duration);
    }

    /**
     * Show info toast.
     * @param {string} message - Message to display
     * @param {number} duration - Display duration
     */
    function info(message, duration) {
        show(message, 'info', duration);
    }

    /**
     * Show success toast.
     * @param {string} message - Message to display
     * @param {number} duration - Display duration
     */
    function success(message, duration) {
        show(message, 'success', duration);
    }

    /**
     * Show warning toast.
     * @param {string} message - Message to display
     * @param {number} duration - Display duration (default 5000ms per AC2)
     */
    function warning(message, duration) {
        show(message, 'warning', duration || config.warningDuration);
    }

    /**
     * Show error toast.
     * @param {string} message - Message to display
     * @param {number} duration - Display duration (default 5000ms per AC2)
     */
    function error(message, duration) {
        show(message, 'error', duration || config.warningDuration);
    }

    /**
     * Escape HTML to prevent XSS.
     * Uses shared NetScopeUtils.escapeHtml if available, otherwise local fallback.
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    function escapeHtml(text) {
        // Use shared utility if available (loaded from capture.js)
        if (window.NetScopeUtils && window.NetScopeUtils.escapeHtml) {
            return window.NetScopeUtils.escapeHtml(text);
        }
        // Fallback for standalone usage
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Export toast functions
    window.NetScope = window.NetScope || {};
    window.NetScope.toast = {
        show: show,
        info: info,
        success: success,
        warning: warning,
        error: error
    };

})();
