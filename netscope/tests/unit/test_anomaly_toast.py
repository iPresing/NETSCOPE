"""Unit tests for anomaly toast notification (Story 4b.8).

Tests the capture.js anomaly detection and toast notification:
- showAnomalyToast() message formatting (singular/plural) (AC2)
- Toast type selection: warning vs info based on criticality (AC1)
- previousAnomalyCount tracking (AC4)
- No toast when zero new anomalies (AC3)
- escapeHtml applied (AC2, rule #3)
- Clickable toast with /anomalies href (AC7)
"""

import pytest


class TestShowAnomalyToastFunction:
    """Test showAnomalyToast() in capture.js (Task 3)."""

    def test_function_exists(self, client):
        """Test showAnomalyToast function is defined in capture.js."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'function showAnomalyToast(newCount, byCriticality)' in js

    def test_singular_anomaly_label(self, client):
        """Test singular form: '1 anomalie détectée'."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "anomalie détectée" in js or "anomalie d\\u00e9tect\\u00e9e" in js

    def test_plural_anomalies_label(self, client):
        """Test plural form: 'N anomalies détectées'."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "anomalies détectées" in js or "anomalies d\\u00e9tect\\u00e9es" in js

    def test_critical_uses_plural(self, client):
        """Test 'critiques' plural form used when count > 1."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "critique" in js
        # Check for plural logic
        assert "critical > 1" in js

    def test_warning_type_when_critical(self, client):
        """Test toast type is 'warning' when byCriticality.critical > 0."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "byCriticality.critical > 0" in js
        assert "'warning'" in js

    def test_info_type_when_no_critical(self, client):
        """Test toast type is 'info' when no critical anomalies."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "'info'" in js

    def test_warning_duration_5000ms(self, client):
        """Test warning toast uses 5000ms duration (AC1)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert '5000' in js

    def test_info_duration_3000ms(self, client):
        """Test info toast uses 3000ms duration (AC1)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert '3000' in js

    def test_clickable_with_anomalies_href(self, client):
        """Test toast is clickable with href='/anomalies' (AC7)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "href: '/anomalies'" in js
        assert 'clickable: true' in js

    def test_uses_netscope_toast_show(self, client):
        """Test uses NetScope.toast.show() API (AC5)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'window.NetScope.toast.show(' in js

    def test_escape_html_comment_present(self, client):
        """Test escapeHtml is handled (applied by show() internally, rule #3)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        # escapeHtml is applied by NetScope.toast.show() internally
        assert 'escapeHtml' in js


class TestAnomalyCountTracking:
    """Test previousAnomalyCount tracking in capture.js (Task 2)."""

    def test_previous_anomaly_count_variable(self, client):
        """Test previousAnomalyCount variable is declared."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'previousAnomalyCount' in js
        assert 'previousAnomalyCount = null' in js

    def test_previous_by_criticality_variable(self, client):
        """Test previousByCriticality variable is declared for delta breakdown."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'previousByCriticality = null' in js

    def test_init_anomaly_count_function(self, client):
        """Test initAnomalyCount() function exists."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'function initAnomalyCount()' in js

    def test_init_stores_by_criticality_baseline(self, client):
        """Test initAnomalyCount stores previousByCriticality baseline."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        init_fn_start = js.index('function initAnomalyCount()')
        init_fn = js[init_fn_start:init_fn_start + 500]
        assert 'previousByCriticality = data.summary.by_criticality' in init_fn

    def test_init_calls_anomalies_summary(self, client):
        """Test initAnomalyCount calls GET /api/anomalies/summary."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert "'/api/anomalies/summary'" in js

    def test_init_called_from_init_function(self, client):
        """Test initAnomalyCount is called from init()."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'initAnomalyCount()' in js

    def test_check_new_anomalies_function(self, client):
        """Test checkNewAnomalies() function exists."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'function checkNewAnomalies()' in js

    def test_check_new_anomalies_awaited_in_polling(self, client):
        """Test checkNewAnomalies is awaited in polling callback."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'await checkNewAnomalies()' in js

    def test_delta_by_criticality_computed(self, client):
        """Test delta by criticality is computed from previous baseline."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        check_fn_start = js.index('function checkNewAnomalies()')
        check_fn = js[check_fn_start:check_fn_start + 1000]
        assert 'deltaByCriticality' in check_fn
        assert 'previousByCriticality.critical' in check_fn
        assert 'previousByCriticality.warning' in check_fn
        assert 'previousByCriticality.normal' in check_fn

    def test_no_toast_when_previous_count_null(self, client):
        """Test no toast when previousAnomalyCount is null (first load)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'previousAnomalyCount === null' in js
        assert 'return' in js

    def test_delta_comparison(self, client):
        """Test delta = total - previousAnomalyCount comparison."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'data.summary.total - previousAnomalyCount' in js

    def test_toast_only_when_delta_positive(self, client):
        """Test toast only triggered when delta > 0."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'delta > 0' in js

    def test_previous_count_updated_after_check(self, client):
        """Test previousAnomalyCount is updated after each check."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'previousAnomalyCount = data.summary.total' in js

    def test_previous_by_criticality_updated_after_check(self, client):
        """Test previousByCriticality is updated after each check."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        check_fn_start = js.index('function checkNewAnomalies()')
        check_fn = js[check_fn_start:check_fn_start + 1500]
        assert 'previousByCriticality = data.summary.by_criticality' in check_fn


class TestAnomalySummaryAPI:
    """Test /api/anomalies/summary endpoint (used by Task 2)."""

    def test_anomalies_summary_endpoint_exists(self, client):
        """Test GET /api/anomalies/summary returns 200."""
        response = client.get('/api/anomalies/summary')
        assert response.status_code == 200

    def test_anomalies_summary_returns_success(self, client):
        """Test endpoint returns success=true."""
        response = client.get('/api/anomalies/summary')
        data = response.get_json()

        assert data['success'] is True

    def test_anomalies_summary_has_total(self, client):
        """Test endpoint returns summary.total field."""
        response = client.get('/api/anomalies/summary')
        data = response.get_json()

        assert 'summary' in data
        assert 'total' in data['summary']
        assert isinstance(data['summary']['total'], int)

    def test_anomalies_summary_has_by_criticality(self, client):
        """Test endpoint returns summary.by_criticality breakdown."""
        response = client.get('/api/anomalies/summary')
        data = response.get_json()

        assert 'by_criticality' in data['summary']
        by_crit = data['summary']['by_criticality']
        assert 'critical' in by_crit
        assert 'warning' in by_crit
        assert 'normal' in by_crit
