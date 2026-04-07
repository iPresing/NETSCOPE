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


class TestToastPersistentDuration:
    """Test persistent toast support (duration=0) — fix-2 2026-04-07.

    A duration of 0 means the toast does NOT auto-remove and persists until
    the user clicks it (when clickable). Used by anomaly toasts on critical
    detection so the user must explicitly acknowledge security alerts.
    """

    def test_show_treats_zero_duration_as_persistent(self, client):
        """Test show() does not fall back to defaultDuration when duration is 0."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        # Old buggy form: `duration = duration || config.defaultDuration;` would
        # treat 0 as falsy. New form must check undefined/null explicitly.
        assert 'duration === undefined || duration === null' in js
        # And must NOT use the old || fallback for duration directly inside show()
        fn_start = js.index('function show(message, type, duration, options)')
        fn = js[fn_start:fn_start + 1500]
        assert 'duration = duration || config.defaultDuration' not in fn

    def test_auto_remove_skipped_when_duration_zero(self, client):
        """Test setTimeout for auto-remove is gated by `duration > 0`."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        # The auto-remove block must be inside an `if (duration > 0)` guard
        assert 'if (duration > 0)' in js

    def test_auto_remove_timer_var_still_hoisted_for_click_handler(self, client):
        """Test autoRemoveTimer var is declared so the click handler closure works.

        When duration=0, no setTimeout is scheduled, but the click handler still
        calls clearTimeout(autoRemoveTimer). clearTimeout(undefined) is a no-op,
        so the variable just needs to exist in scope.
        """
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        # var declaration must be present
        assert 'var autoRemoveTimer' in js
        # Click handler still references it
        assert 'clearTimeout(autoRemoveTimer)' in js

    def test_default_duration_unchanged_for_undefined(self, client):
        """Test undefined duration still falls back to defaultDuration (3000ms)."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        # The fallback assignment must still happen for undefined/null
        assert 'duration = config.defaultDuration' in js


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
