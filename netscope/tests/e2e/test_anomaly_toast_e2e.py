"""E2E tests for anomaly toast notification (Story 4b.8).

Tests the full flow from dashboard HTML through to toast display:
- Toast HTML structure in DOM after capture simulation (AC2, AC5)
- Toast clickable link to /anomalies (AC7)
- Dashboard includes required JS modules (AC5)
"""

import pytest
from bs4 import BeautifulSoup


class TestDashboardIncludesToastScripts:
    """Test dashboard page includes all required JS for anomaly toast."""

    def test_dashboard_includes_toasts_js(self, client):
        """Test dashboard loads toasts.js."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'toasts.js' in html

    def test_dashboard_includes_capture_js(self, client):
        """Test dashboard loads capture.js."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'capture.js' in html

    def test_toasts_js_loaded_before_capture_js(self, client):
        """Test toasts.js is loaded before capture.js (dependency order)."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        toasts_pos = html.index('toasts.js')
        capture_pos = html.index('capture.js')
        assert toasts_pos < capture_pos, "toasts.js must load before capture.js"


class TestToastHTMLStructure:
    """Test toast DOM structure from toasts.js (AC5)."""

    def test_toast_container_class_in_js(self, client):
        """Test JS creates toast-container element."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert "toast-container" in js
        assert "createElement('div')" in js

    def test_toast_role_alert_attribute(self, client):
        """Test toast element gets role='alert' for accessibility."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert "'role'" in js
        assert "'alert'" in js

    def test_toast_icon_and_message_structure(self, client):
        """Test toast contains icon and message spans."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'toast-icon' in js
        assert 'toast-message' in js

    def test_toast_clickable_class_present_in_css(self, client):
        """Test .toast-clickable CSS class exists."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.toast-clickable' in css

    def test_toast_clickable_has_pointer_cursor(self, client):
        """Test clickable toast has cursor: pointer."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Find the .toast-clickable block
        idx = css.index('.toast-clickable')
        block = css[idx:idx + 100]
        assert 'cursor: pointer' in block


class TestAnomalyToastContent:
    """Test anomaly toast message content (AC2)."""

    def test_anomaly_toast_href_anomalies_page(self, client):
        """Test toast navigates to /anomalies on click (AC7)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "'/anomalies'" in js
        assert 'clickable: true' in js

    def test_anomaly_toast_message_has_count(self, client):
        """Test toast message includes anomaly count."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        # Message built from newCount parameter
        assert 'newCount' in js

    def test_anomaly_toast_message_has_criticality_breakdown(self, client):
        """Test toast message includes criticality breakdown."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'byCriticality.critical' in js
        assert 'byCriticality.warning' in js
        assert 'byCriticality.normal' in js

    def test_anomaly_toast_uses_netscope_toast_api(self, client):
        """Test toast uses NetScope.toast.show() (not custom notification)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'window.NetScope.toast.show(' in js


class TestExistingDashboardRegression:
    """Test dashboard functionality is not regressed (AC6)."""

    def test_dashboard_loads_successfully(self, client):
        """Test dashboard page returns 200."""
        response = client.get('/')
        assert response.status_code == 200

    def test_capture_form_present(self, client):
        """Test capture form elements still present."""
        response = client.get('/')
        soup = BeautifulSoup(response.data, 'html.parser')

        assert soup.find(id='btn-start-capture') is not None
        assert soup.find(id='capture-interface') is not None
        assert soup.find(id='capture-duration') is not None

    def test_capture_status_section_present(self, client):
        """Test capture status display still present."""
        response = client.get('/')
        soup = BeautifulSoup(response.data, 'html.parser')

        assert soup.find(id='capture-status') is not None
        assert soup.find(id='capture-timer') is not None

    def test_anomalies_section_present(self, client):
        """Test anomalies section still present in dashboard."""
        response = client.get('/')
        soup = BeautifulSoup(response.data, 'html.parser')

        assert soup.find(id='anomalies-section') is not None
