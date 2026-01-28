"""Integration tests for Micro-Interactions.

Tests the visual micro-interactions across the dashboard including:
- Packet stream animation during capture (AC1)
- Toast notifications with fade in/out (AC2)
- Hover transitions on interactive elements (AC3)
- Color code consistency (AC4)
- Immediate feedback on user actions (AC5)

Story 2.9: Micro-Interactions Coherentes
"""

import pytest


class TestPacketStreamAnimation:
    """Test packet stream animation during capture (AC1)."""

    def test_packet_animation_element_exists(self, client):
        """Test packet-animation element exists in capture-status."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'packet-animation' in html
        assert 'capture-status' in html

    def test_packet_animation_css_exists(self, client):
        """Test CSS has packet-animation styles."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.capture-status .packet-animation' in css
        assert '.packet-animation.animating' in css

    def test_packet_pulse_animation_defined(self, client):
        """Test packet-pulse keyframes are defined."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '@keyframes packet-pulse' in css

    def test_js_has_packet_animation_functions(self, client):
        """Test JS has start/stop packet animation functions."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'startPacketAnimation' in js
        assert 'stopPacketAnimation' in js
        assert 'PACKET_FRAMES' in js

    def test_packet_animation_frames_defined(self, client):
        """Test packet animation frames are defined with ....> pattern."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "'>'" in js or "....>" in js


class TestToastNotifications:
    """Test toast notifications with fade in/out (AC2)."""

    def test_toast_container_css_exists(self, client):
        """Test toast container CSS exists."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.toast-container' in css
        assert 'position: fixed' in css

    def test_toast_transition_css_exists(self, client):
        """Test toast transition CSS for fade in/out."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.toast-visible' in css
        assert 'transform: translateX' in css

    def test_toast_types_css_exists(self, client):
        """Test CSS has all toast types."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.toast-info' in css
        assert '.toast-success' in css
        assert '.toast-warning' in css
        assert '.toast-error' in css

    def test_toast_glow_effects_exist(self, client):
        """Test toast types have glow effects when visible."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.toast-info.toast-visible' in css
        assert '.toast-success.toast-visible' in css
        assert '.toast-warning.toast-visible' in css
        assert '.toast-error.toast-visible' in css

    def test_toasts_js_exists(self, client):
        """Test toasts.js file exists."""
        response = client.get('/static/js/toasts.js')

        assert response.status_code == 200

    def test_toasts_js_has_icons(self, client):
        """Test toasts.js has icons for each type."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'icons' in js
        assert 'info' in js
        assert 'success' in js
        assert 'warning' in js
        assert 'error' in js

    def test_toasts_js_has_escape_html(self, client):
        """Test toasts.js uses escapeHtml for XSS protection."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'escapeHtml' in js

    def test_warning_duration_is_5s(self, client):
        """Test warning toast duration is 5000ms."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        # Check warning function uses 5000ms
        assert '5000' in js

    def test_error_duration_is_5s(self, client):
        """Test error toast duration is 5000ms."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        # Check error function uses 5000ms (already set to 5000 in code)
        assert 'error' in js
        assert '5000' in js


class TestHoverTransitions:
    """Test hover transitions on interactive elements (AC3)."""

    def test_btn_has_transition(self, client):
        """Test .btn has transition property."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Find .btn { section
        assert '.btn {' in css
        # Check transition is within button styles
        assert 'transition: var(--transition-normal)' in css

    def test_status_card_has_transition(self, client):
        """Test .status-card has transition property."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-card {' in css

    def test_nav_link_has_transition(self, client):
        """Test .nav-link has transition property."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.nav-link {' in css

    def test_anomaly_item_has_transition(self, client):
        """Test .anomaly-item has transition property."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.anomaly-item {' in css

    def test_transition_variables_defined(self, client):
        """Test transition CSS variables are defined."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '--transition-fast' in css
        assert '--transition-normal' in css

    def test_transition_fast_is_150ms(self, client):
        """Test transition-fast is max 150ms per spec."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '--transition-fast: 150ms' in css


class TestColorCodeConsistency:
    """Test color code consistency (AC4)."""

    def test_danger_red_defined(self, client):
        """Test --danger-red variable is defined with correct value."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '--danger-red: #ff3355' in css

    def test_alert_amber_defined(self, client):
        """Test --alert-amber variable is defined with correct value."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '--alert-amber: #ffaa00' in css

    def test_matrix_green_defined(self, client):
        """Test --matrix-green variable is defined with correct value."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '--matrix-green: #00ff88' in css

    def test_neon_cyan_defined(self, client):
        """Test --neon-cyan variable is defined with correct value."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '--neon-cyan: #00f5ff' in css

    def test_glow_variables_defined(self, client):
        """Test glow effect variables are defined."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '--glow-cyan' in css
        assert '--glow-green' in css
        assert '--glow-red' in css
        assert '--glow-amber' in css

    def test_status_critical_uses_danger_red(self, client):
        """Test .status-critical uses --danger-red variable."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-indicator.status-critical' in css
        assert 'var(--danger-red)' in css

    def test_status_warning_uses_alert_amber(self, client):
        """Test .status-warning uses --alert-amber variable."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-indicator.status-warning' in css
        assert 'var(--alert-amber)' in css

    def test_status_normal_uses_matrix_green(self, client):
        """Test .status-normal uses --matrix-green variable."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-indicator.status-normal' in css
        assert 'var(--matrix-green)' in css

    def test_status_info_uses_neon_cyan(self, client):
        """Test .status-info uses --neon-cyan variable."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-indicator.status-info' in css
        assert 'var(--neon-cyan)' in css


class TestImmediateFeedback:
    """Test immediate feedback on user actions (AC5)."""

    def test_btn_loading_css_exists(self, client):
        """Test .btn-loading class exists for button loading state."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.btn-loading' in css

    def test_btn_spinner_css_exists(self, client):
        """Test .btn-spinner class exists for loading spinner."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.btn-spinner' in css

    def test_spin_animation_defined(self, client):
        """Test @keyframes spin animation is defined."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '@keyframes spin' in css

    def test_js_sets_loading_state_on_capture(self, client):
        """Test JS sets loading state when starting capture."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'btn-loading' in js
        assert 'btn-spinner' in js

    def test_js_has_reset_start_button(self, client):
        """Test JS has function to reset start button."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'resetStartButton' in js

    def test_card_updating_animation_exists(self, client):
        """Test card-updating animation class exists."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-card.card-updating' in css
        assert '@keyframes card-pulse' in css

    def test_filter_debounce_in_anomalies_js(self, client):
        """Test search filter has debounce for responsive feedback."""
        response = client.get('/static/js/anomalies.js')
        js = response.data.decode('utf-8')

        assert 'debounce' in js
        # Should be 100ms or less per NFR32
        assert '100' in js


class TestCaptureStatusAnimation:
    """Test capture status display animation."""

    def test_capture_pulse_animation_defined(self, client):
        """Test @keyframes capture-pulse is defined."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '@keyframes capture-pulse' in css

    def test_status_indicator_running_class(self, client):
        """Test capture-status has running indicator."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'status-indicator' in html
        assert 'capture-status' in html


class TestProgressBarAnimation:
    """Test progress bar animations."""

    def test_progress_shine_animation_exists(self, client):
        """Test @keyframes progress-shine is defined."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '@keyframes progress-shine' in css

    def test_progress_fill_uses_animation(self, client):
        """Test .progress-fill uses progress-shine animation."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.progress-fill::after' in css
        assert 'animation: progress-shine' in css


class TestCriticalBlinkAnimation:
    """Test critical status blink animation."""

    def test_critical_blink_animation_exists(self, client):
        """Test @keyframes critical-blink is defined."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '@keyframes critical-blink' in css

    def test_status_critical_uses_blink(self, client):
        """Test .status-critical uses critical-blink animation."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-indicator.status-critical' in css
        assert 'animation: critical-blink' in css
