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
     */
    var config = {
        position: 'top-right',
        defaultDuration: 3000,
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
     * @param {number} duration - Display duration
     */
    function warning(message, duration) {
        show(message, 'warning', duration);
    }

    /**
     * Show error toast.
     * @param {string} message - Message to display
     * @param {number} duration - Display duration
     */
    function error(message, duration) {
        show(message, 'error', duration || 5000);
    }

    /**
     * Escape HTML to prevent XSS.
     * @param {string} text - Text to escape
     * @returns {string} Escaped text
     */
    function escapeHtml(text) {
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
