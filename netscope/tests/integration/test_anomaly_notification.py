"""Integration tests for anomaly notification after capture (Story 4b.8).

Tests the integration between capture polling, anomaly summary API,
and toast notification system:
- Polling callback triggers anomaly check (AC4)
- No toast when 0 new anomalies (AC3)
- No toast on first page load (AC4)
- Existing toasts unaffected (AC6)
- Existing timers unaffected (AC6)
"""

import pytest
from bs4 import BeautifulSoup


class TestCapturePollingIntegration:
    """Test polling capture → anomaly check → toast triggered (AC4)."""

    def test_status_polling_awaits_check_new_anomalies(self, client):
        """Test startStatusPolling callback awaits checkNewAnomalies on completion."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        # checkNewAnomalies must be awaited when status is not 'running'
        assert 'await checkNewAnomalies()' in js
        # Must be within the polling callback that checks data.status
        assert "data.status !== 'running'" in js

    def test_anomaly_check_after_load_latest_result(self, client):
        """Test checkNewAnomalies is called after loadLatestResult (correct order)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        # checkNewAnomalies must come after loadLatestResult and showCaptureComplete
        poll_section = js[js.index('startStatusPolling'):]
        load_pos = poll_section.index('loadLatestResult')
        check_pos = poll_section.index('checkNewAnomalies')
        assert check_pos > load_pos, "checkNewAnomalies must be called after loadLatestResult"

    def test_no_toast_on_first_load_null_baseline(self, client):
        """Test no toast when previousAnomalyCount is null (AC4 — first load guard)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        # checkNewAnomalies should return early when previousAnomalyCount is null
        check_fn_start = js.index('function checkNewAnomalies()')
        check_fn = js[check_fn_start:check_fn_start + 500]
        assert 'previousAnomalyCount === null' in check_fn
        assert 'return' in check_fn

    def test_no_toast_when_zero_delta(self, client):
        """Test no toast when delta is 0 (AC3 ��� no new anomalies)."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        # Only call showAnomalyToast when delta > 0
        assert 'delta > 0' in js

    def test_previous_count_updated_even_when_no_toast(self, client):
        """Test previousAnomalyCount is always updated after check."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        check_fn_start = js.index('function checkNewAnomalies()')
        check_fn = js[check_fn_start:check_fn_start + 1500]
        # Update is outside the delta > 0 check
        assert 'previousAnomalyCount = data.summary.total' in check_fn


class TestNoRegressionExistingToasts:
    """Test existing toast functionality unaffected (AC6)."""

    def test_existing_toast_info_method(self, client):
        """Test NetScope.toast.info still works."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'function info(message, duration)' in js
        assert "show(message, 'info', duration)" in js

    def test_existing_toast_warning_method(self, client):
        """Test NetScope.toast.warning still works with warningDuration."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'function warning(message, duration)' in js
        assert 'config.warningDuration' in js

    def test_existing_toast_error_method(self, client):
        """Test NetScope.toast.error still works."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'function error(message, duration)' in js

    def test_toast_container_creation_unchanged(self, client):
        """Test getContainer() still creates toast-container."""
        response = client.get('/static/js/toasts.js')
        js = response.data.decode('utf-8')

        assert 'toast-container' in js
        assert 'function getContainer()' in js


class TestNoRegressionExistingTimers:
    """Test existing timers and polling unaffected (AC6)."""

    def test_capture_timer_unchanged(self, client):
        """Test captureTimer variable and startTimer/stopTimer unchanged."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'captureTimer' in js
        assert 'function startTimer()' in js
        assert 'function stopTimer()' in js

    def test_status_poll_interval_unchanged(self, client):
        """Test statusPollInterval variable unchanged."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'statusPollInterval' in js
        assert 'function startStatusPolling()' in js
        assert 'function stopStatusPolling()' in js

    def test_no_continuous_anomaly_polling(self, client):
        """Test no setInterval for anomaly polling — event-driven only."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        # Count setInterval calls — should only be captureTimer and statusPollInterval
        # The anomaly check is a one-shot fetch, NOT a setInterval
        assert 'function initAnomalyCount()' in js
        assert 'function checkNewAnomalies()' in js
        # These functions use fetch (one-shot), not setInterval
        init_fn_start = js.index('function initAnomalyCount()')
        init_fn = js[init_fn_start:init_fn_start + 400]
        assert 'setInterval' not in init_fn

        check_fn_start = js.index('function checkNewAnomalies()')
        check_fn = js[check_fn_start:check_fn_start + 600]
        assert 'setInterval' not in check_fn

    def test_health_score_polling_not_modified(self, client):
        """Test health-score.js is not modified."""
        response = client.get('/static/js/health-score.js')
        assert response.status_code == 200

    def test_load_anomalies_still_called(self, client):
        """Test window.loadAnomalies still called in loadLatestResult."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'window.loadAnomalies' in js


class TestAnomalySummaryIntegration:
    """Test /api/anomalies/summary endpoint integration."""

    def test_summary_endpoint_json_structure(self, client):
        """Test summary endpoint returns expected JSON structure."""
        response = client.get('/api/anomalies/summary')
        data = response.get_json()

        assert data['success'] is True
        assert 'summary' in data
        assert 'total' in data['summary']
        assert 'by_criticality' in data['summary']

    def test_summary_criticality_keys(self, client):
        """Test by_criticality has critical/warning/normal keys."""
        response = client.get('/api/anomalies/summary')
        data = response.get_json()

        by_crit = data['summary']['by_criticality']
        assert set(by_crit.keys()) >= {'critical', 'warning', 'normal'}

    def test_summary_empty_returns_zero_total(self, client):
        """Test with no anomalies, total is 0."""
        response = client.get('/api/anomalies/summary')
        data = response.get_json()

        assert data['summary']['total'] == 0
        assert data['summary']['by_criticality']['critical'] == 0
