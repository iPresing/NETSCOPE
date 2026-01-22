"""Integration tests for Dashboard Status Cards.

Tests the 4 status cards (Top IPs, Protocols, Ports, Volume) integration
with the FourEssentials API.

Story 2.6: Dashboard 4 Cartes Status
"""

import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from app.models.capture import (
    CaptureResult,
    CaptureSession,
    CaptureConfig,
    CaptureStatus,
    CaptureSummary,
)
from app.core.analysis.four_essentials import reset_four_essentials_analyzer


@pytest.fixture(autouse=True)
def reset_analyzer():
    """Reset FourEssentialsAnalyzer singleton before and after each test."""
    reset_four_essentials_analyzer()
    yield
    reset_four_essentials_analyzer()


@pytest.fixture
def capture_session():
    """Create a sample capture session."""
    return CaptureSession(
        id="cap_20260123_150000",
        config=CaptureConfig(duration=120),
        status=CaptureStatus.COMPLETED,
        start_time=datetime.now(),
    )


@pytest.fixture
def normal_summary():
    """Create a normal capture summary."""
    return CaptureSummary(
        total_packets=100,
        total_bytes=50000,
        unique_ips=5,
        unique_ports=10,
        protocols={"TCP": 70, "UDP": 25, "ICMP": 5},
        top_ips=[
            ("192.168.1.10", 50),
            ("192.168.1.20", 30),
            ("192.168.1.1", 20),
        ],
        top_ports=[
            (80, 40),
            (443, 35),
            (53, 15),
            (22, 10),
        ],
        bytes_per_protocol={"TCP": 35000, "UDP": 12500, "ICMP": 2500},
        duration_actual=60.0,
    )


@pytest.fixture
def capture_result(capture_session, normal_summary):
    """Create a normal capture result."""
    return CaptureResult(
        session=capture_session,
        packets=[],
        summary=normal_summary,
    )


class TestDashboardStatusCardsHTML:
    """Test dashboard HTML has status cards structure (AC1)."""

    def test_dashboard_has_four_status_cards(self, client):
        """Test dashboard contains 4 status cards."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'card-ips' in html
        assert 'card-protocols' in html
        assert 'card-ports' in html
        assert 'card-volume' in html

    def test_status_cards_have_indicators(self, client):
        """Test status cards have indicator elements."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'indicator-ips' in html
        assert 'indicator-protocols' in html
        assert 'indicator-ports' in html
        assert 'indicator-volume' in html

    def test_status_cards_have_data_attributes(self, client):
        """Test status cards have data-card-type attributes for JS."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'data-card-type="ips"' in html
        assert 'data-card-type="protocols"' in html
        assert 'data-card-type="ports"' in html
        assert 'data-card-type="volume"' in html

    def test_status_cards_have_initial_state(self, client):
        """Test status cards show initial state message (AC7)."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        # Initial state should show placeholder message
        assert 'Lancez une capture' in html or '--' in html

    def test_essentials_modal_present(self, client):
        """Test essentials detail modal is in HTML (AC4)."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'essentials-modal' in html
        assert 'essentials-modal-body' in html
        assert 'btn-close-essentials-modal' in html


class TestStatusCardsIndicators:
    """Test status card indicator classes (AC2)."""

    def test_indicator_classes_exist_in_css(self, client):
        """Test CSS file has indicator classes."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-indicator.status-critical' in css
        assert '.status-indicator.status-warning' in css
        assert '.status-indicator.status-normal' in css
        assert '.status-indicator.status-inactive' in css

    def test_card_state_classes_exist(self, client):
        """Test CSS has card state classes."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-card.card-critical' in css
        assert '.status-card.card-warning' in css
        assert '.status-card.card-normal' in css
        assert '.status-card.card-inactive' in css

    def test_status_message_class_exists(self, client):
        """Test CSS has status message class (AC3)."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.status-message' in css


class TestFourEssentialsAPIIntegration:
    """Test Four Essentials API integration (AC5)."""

    def test_api_endpoint_exists(self, client):
        """Test /api/analysis/four-essentials endpoint exists."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            mock_manager.return_value.get_latest_result.return_value = None

            response = client.get('/api/analysis/four-essentials')

            assert response.status_code == 200

    def test_api_returns_json(self, client):
        """Test API returns JSON content type."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            mock_manager.return_value.get_latest_result.return_value = None

            response = client.get('/api/analysis/four-essentials')

            assert response.content_type == 'application/json'

    def test_api_with_capture_returns_result(self, client, capture_result):
        """Test API returns FourEssentialsResult with capture."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')
                data = json.loads(response.data)

                assert data['success'] is True
                assert data['result'] is not None
                assert 'top_ips' in data['result']
                assert 'protocols' in data['result']
                assert 'ports' in data['result']
                assert 'volume' in data['result']

    def test_api_indicators_are_emojis(self, client, capture_result):
        """Test API returns emoji indicators (AC2)."""
        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                response = client.get('/api/analysis/four-essentials')
                data = json.loads(response.data)

                result = data['result']
                valid_indicators = ['🔴', '🟡', '🟢']

                assert result['overall_indicator'] in valid_indicators
                assert result['top_ips']['indicator'] in valid_indicators
                assert result['protocols']['indicator'] in valid_indicators
                assert result['ports']['indicator'] in valid_indicators
                assert result['volume']['indicator'] in valid_indicators


class TestCaptureJSLoaded:
    """Test JavaScript for status cards is loaded."""

    def test_capture_js_loaded_on_dashboard(self, client):
        """Test capture.js is loaded on dashboard."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'capture.js' in html

    def test_capture_js_exists(self, client):
        """Test capture.js file exists and loads."""
        response = client.get('/static/js/capture.js')

        assert response.status_code == 200

    def test_capture_js_has_four_essentials_module(self, client):
        """Test capture.js contains Four Essentials module."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'loadFourEssentials' in js
        assert 'updateStatusCard' in js
        assert 'resetStatusCards' in js


class TestModalFunctionality:
    """Test modal detail functionality (AC4)."""

    def test_modal_css_exists(self, client):
        """Test modal CSS is defined."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.essentials-modal' in css
        assert '.essentials-modal-content' in css
        assert '.essentials-modal-header' in css
        assert '.essentials-modal-body' in css

    def test_modal_detail_css_exists(self, client):
        """Test modal detail styles exist."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        assert '.essentials-detail' in css
        assert '.essentials-status' in css
        assert '.essentials-table' in css


class TestNavigationToDetails:
    """Test navigation from cards to details (AC4)."""

    def test_cards_have_click_handlers_in_js(self, client):
        """Test JS has click handlers for cards."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        assert 'showCardDetails' in js
        assert 'hideCardDetails' in js
        assert "addEventListener('click'" in js

    def test_voir_link_present_on_cards(self, client):
        """Test 'Voir' link present on cards."""
        response = client.get('/')
        html = response.data.decode('utf-8')

        assert 'status-card-link' in html
        assert 'Voir' in html


class TestResponsiveDesign:
    """Test responsive CSS for status cards."""

    def test_responsive_css_exists(self, client):
        """Test responsive CSS media queries exist."""
        response = client.get('/static/css/style.css')
        css = response.data.decode('utf-8')

        # Check for responsive rules
        assert '@media' in css
        assert 'max-width: 768px' in css


class TestAutomaticUpdate:
    """Test automatic update after capture (AC6)."""

    def test_js_calls_four_essentials_after_capture(self, client):
        """Test JS calls loadFourEssentials after capture completion."""
        response = client.get('/static/js/capture.js')
        js = response.data.decode('utf-8')

        # Check loadLatestResult calls loadFourEssentials
        assert 'window.loadFourEssentials' in js
        assert 'loadFourEssentials()' in js


class TestAPIResponsePerformance:
    """Test API response performance (FR30 requires fast response)."""

    def test_api_response_under_200ms(self, client, capture_result):
        """Test API responds in under 200ms."""
        import time

        with patch('app.blueprints.api.analysis.get_tcpdump_manager') as mock_manager:
            with patch('app.blueprints.api.analysis.get_anomaly_store') as mock_store:
                mock_manager.return_value.get_latest_result.return_value = capture_result
                mock_store.return_value.get_by_capture.return_value = None

                start = time.time()
                response = client.get('/api/analysis/four-essentials')
                elapsed = time.time() - start

                assert response.status_code == 200
                assert elapsed < 0.2, f"API took {elapsed:.3f}s, expected <0.2s"
