"""Unit tests for toast clickable extension (Story 4b.8).

Tests the toasts.js extension supporting clickable toasts:
- show() accepts optional 4th parameter `options` (AC5)
- toast-clickable class added when clickable=true (AC5, AC7)
- Click handler navigates to href or calls onClick (AC7)
- Backward compatibility: existing calls without options work identically (AC5)
"""

import pytest


class TestToastClickableExtension:
    """Test toasts.js clickable toast support (Task 1)."""

    def test_show_accepts_options_parameter(self, client):
        """Test show() function signature includes options parameter."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'function show(message, type, duration, options)' in js

    def test_clickable_class_added_when_option_set(self, client):
        """Test toast-clickable class is added when options.clickable is true."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert "toast-clickable" in js
        assert "options.clickable" in js or "options && options.clickable" in js

    def test_click_handler_supports_href(self, client):
        """Test click handler navigates to options.href."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'options.href' in js
        assert 'window.location.href' in js

    def test_click_handler_supports_onclick_callback(self, client):
        """Test click handler calls options.onClick callback."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'options.onClick' in js

    def test_toast_removed_after_click(self, client):
        """Test toast is removed after click via removeToast()."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'removeToast(toast)' in js
        assert 'function removeToast(toast)' in js

    def test_auto_remove_timer_cleared_on_click(self, client):
        """Test auto-remove timer is cleared when toast is clicked."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'clearTimeout(autoRemoveTimer)' in js

    def test_backward_compatibility_show_without_options(self, client):
        """Test show() works without options (3 params) — backward compatible."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        # The function should still work with 3 params (options is optional)
        # Verify guard clause checks options exists before accessing properties
        assert 'options && options.clickable' in js

    def test_existing_convenience_methods_unchanged(self, client):
        """Test info/success/warning/error methods are unchanged."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'function info(message, duration)' in js
        assert 'function success(message, duration)' in js
        assert 'function warning(message, duration)' in js
        assert 'function error(message, duration)' in js

    def test_escape_html_still_applied(self, client):
        """Test escapeHtml is still applied to message in show()."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'escapeHtml(message)' in js

    def test_toast_api_exports_unchanged(self, client):
        """Test NetScope.toast API exports are unchanged."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'window.NetScope.toast' in js
        assert 'show: show' in js
        assert 'info: info' in js
        assert 'warning: warning' in js
        assert 'error: error' in js

    def test_role_alert_still_set(self, client):
        """Test role='alert' accessibility attribute still set on toast."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert "role" in js
        assert "alert" in js

    def test_max_toasts_limit_unchanged(self, client):
        """Test maxToasts limit (5) is still enforced."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'maxToasts: 5' in js


class TestToastClickableCSS:
    """Test CSS styles for clickable toasts (Task 4)."""

    def test_toast_clickable_cursor_pointer(self, client):
        """Test .toast-clickable has cursor: pointer."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.toast-clickable' in css
        assert 'cursor: pointer' in css

    def test_toast_clickable_hover_effect(self, client):
        """Test .toast-clickable:hover has brightness effect."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.toast-clickable:hover' in css
        assert 'filter: brightness' in css

    def test_existing_toast_styles_unchanged(self, client):
        """Test existing toast CSS classes still present."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.toast-container' in css
        assert '.toast-info' in css
        assert '.toast-success' in css
        assert '.toast-warning' in css
        assert '.toast-error' in css
        assert '.toast-visible' in css
