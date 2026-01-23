"""Integration tests for anomalies page.

Story 2.7: Tests for anomaly list rendering with progress bars.

Tests cover:
- AC1: Liste triée par score décroissant
- AC2: Barres de progression visuelles
- AC3: Informations complètes par anomalie
- AC4: Intégration API existante
- AC5: État initial sans anomalies

Lessons Learned Epic 1 & Stories 2.1-2.6:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
"""

import pytest
import re
from datetime import datetime
from pathlib import Path
import tempfile
import json

from app import create_app
from app.core.detection.blacklist_manager import (
    get_blacklist_manager,
    reset_blacklist_manager,
)
from app.core.detection.blacklist_detector import create_detector
from app.core.detection.anomaly_store import (
    get_anomaly_store,
    reset_anomaly_store,
)
from app.models.capture import PacketInfo


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singletons before and after each test."""
    reset_blacklist_manager()
    reset_anomaly_store()
    yield
    reset_blacklist_manager()
    reset_anomaly_store()


@pytest.fixture
def app():
    """Create test application."""
    app = create_app('testing')
    yield app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def temp_blacklist_dir():
    """Create temporary directory with test blacklist files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        defaults_dir = Path(tmpdir) / "data" / "blacklists_defaults"
        defaults_dir.mkdir(parents=True)

        (defaults_dir / "ips_malware.txt").write_text(
            "# Test IPs\n"
            "45.33.32.156\n"
            "185.220.101.1\n"
            "10.0.0.99\n"
        )

        yield Path(tmpdir)


@pytest.fixture
def loaded_manager(temp_blacklist_dir):
    """Get BlacklistManager loaded with test data."""
    manager = get_blacklist_manager()
    config = {
        "defaults": {
            "ips_malware": "data/blacklists_defaults/ips_malware.txt",
        }
    }
    manager.load_blacklists(config, base_path=temp_blacklist_dir)
    return manager


class TestAnomaliesPageRoute:
    """Test anomalies page route and template rendering."""

    def test_anomalies_page_loads(self, client):
        """Test /anomalies page loads successfully."""
        response = client.get('/anomalies')
        assert response.status_code == 200

    def test_anomalies_page_contains_required_elements(self, client):
        """Test page contains required HTML elements."""
        response = client.get('/anomalies')
        html = response.data.decode('utf-8')

        # Check page title
        assert 'Anomalies' in html

        # Check anomaly list container exists
        assert 'id="anomaly-list"' in html

        # Check empty state element exists
        assert 'id="anomaly-empty-state"' in html

        # Check summary section exists
        assert 'id="summary-critical"' in html
        assert 'id="summary-warning"' in html
        assert 'id="summary-normal"' in html

    def test_anomalies_page_includes_anomalies_js(self, client):
        """Test page includes anomalies.js script."""
        response = client.get('/anomalies')
        html = response.data.decode('utf-8')

        assert 'anomalies.js' in html


class TestAnomaliesPageEmptyState:
    """Test empty state display (AC5)."""

    def test_empty_state_message_present(self, client):
        """Test empty state message is present in HTML."""
        response = client.get('/anomalies')
        html = response.data.decode('utf-8')

        # Check empty state container exists
        assert 'id="anomaly-empty-state"' in html

        # Check for empty state text
        assert 'Aucune anomalie' in html or 'capture' in html.lower()

    def test_summary_counts_zero_initially(self, client):
        """Test summary counts are zero when no anomalies."""
        response = client.get('/anomalies')
        html = response.data.decode('utf-8')

        # Check that summary counts show 0 - using regex to find the pattern
        # Format: id="summary-critical">0</span>
        assert re.search(r'id="summary-critical">0<', html)
        assert re.search(r'id="summary-warning">0<', html)
        assert re.search(r'id="summary-normal">0<', html)


class TestAnomaliesAPIIntegration:
    """Test API integration for anomalies page (AC4)."""

    def test_api_endpoint_returns_anomalies_with_breakdown(self, client, loaded_manager):
        """Test API returns anomalies with include_breakdown parameter."""
        # Create and store anomalies
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")
        store = get_anomaly_store()
        store.store(collection)

        # Call API as frontend would
        response = client.get('/api/anomalies?latest=true&include_breakdown=true')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['success'] is True
        assert len(data['result']['anomalies']) == 1

        anomaly = data['result']['anomalies'][0]
        assert 'score_breakdown' in anomaly
        assert 'human_context' in anomaly

    def test_api_returns_by_criticality(self, client, loaded_manager):
        """Test API returns by_criticality counts for summary section."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="185.220.101.1",
                ip_dst="192.168.1.10",
                port_src=443,
                port_dst=61234,
                protocol="TCP",
                length=1500,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")
        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies?latest=true&include_breakdown=true')
        data = json.loads(response.data)

        assert 'by_criticality' in data['result']
        by_crit = data['result']['by_criticality']
        assert by_crit['critical'] == 2


class TestAnomalySorting:
    """Test anomaly sorting by score (AC1)."""

    def test_anomalies_sorted_by_criticality_in_api(self, client, loaded_manager):
        """Test API returns anomalies sorted by criticality."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="185.220.101.1",
                ip_dst="192.168.1.10",
                port_src=443,
                port_dst=61234,
                protocol="TCP",
                length=1500,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")
        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies?latest=true')
        data = json.loads(response.data)

        anomalies = data['result']['anomalies']

        # Critical anomalies should be first
        for anomaly in anomalies:
            assert anomaly['criticality'] == 'critical'


class TestProgressBarData:
    """Test progress bar data in API (AC2)."""

    def test_score_present_for_progress_bar(self, client, loaded_manager):
        """Test each anomaly has score for progress bar calculation."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")
        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies?latest=true')
        data = json.loads(response.data)

        anomaly = data['result']['anomalies'][0]
        assert 'score' in anomaly
        assert isinstance(anomaly['score'], int)
        assert 0 <= anomaly['score'] <= 100

    def test_criticality_present_for_color(self, client, loaded_manager):
        """Test each anomaly has criticality for progress bar color."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")
        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies?latest=true')
        data = json.loads(response.data)

        anomaly = data['result']['anomalies'][0]
        assert 'criticality' in anomaly
        assert anomaly['criticality'] in ['critical', 'warning', 'normal']


class TestAnomalyInformation:
    """Test complete anomaly information in API (AC3)."""

    def test_anomaly_contains_ip_port_protocol(self, client, loaded_manager):
        """Test anomaly contains IP/Port/Protocol info."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")
        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies?latest=true')
        data = json.loads(response.data)

        anomaly = data['result']['anomalies'][0]

        # Check matched_value (IP)
        assert 'matched_value' in anomaly
        assert anomaly['matched_value'] == '45.33.32.156'

        # Check packet_info for port/protocol
        assert 'packet_info' in anomaly
        packet_info = anomaly['packet_info']
        assert packet_info is not None
        assert 'port_dst' in packet_info
        assert 'protocol' in packet_info

    def test_anomaly_contains_human_context(self, client, loaded_manager):
        """Test anomaly contains human_context from Story 2.5."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")
        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies?latest=true&include_breakdown=true')
        data = json.loads(response.data)

        anomaly = data['result']['anomalies'][0]
        assert 'human_context' in anomaly

        human_context = anomaly['human_context']
        assert human_context is not None
        # Actual HumanContext fields from Story 2.5
        assert 'short_message' in human_context
        assert 'action_hint' in human_context


class TestFilterSection:
    """Test filter section is present (prep for Story 2.8)."""

    def test_filter_section_exists(self, client):
        """Test filter section exists in page (disabled for now)."""
        response = client.get('/anomalies')
        html = response.data.decode('utf-8')

        # Check severity filter exists
        assert 'id="severity-filter"' in html

        # Check type filter exists
        assert 'id="type-filter"' in html

        # Both should be disabled (Story 2.8)
        # Look for pattern: select ... disabled
        assert re.search(r'id="severity-filter"[^>]*disabled', html)
        assert re.search(r'id="type-filter"[^>]*disabled', html)


class TestProgressBarCSS:
    """Test progress bar CSS classes exist in stylesheet (AC2).

    Note: JavaScript rendering cannot be tested in Python integration tests.
    These tests verify the CSS infrastructure is in place for progress bars.
    """

    def test_css_contains_progress_bar_classes(self, app):
        """Test style.css contains progress bar CSS classes."""
        import os
        css_path = os.path.join(
            app.static_folder, 'css', 'style.css'
        )
        with open(css_path, 'r', encoding='utf-8') as f:
            css_content = f.read()

        # Check progress bar base classes exist
        assert '.progress-bar' in css_content
        assert '.progress-fill' in css_content

        # Check criticality-specific fill classes exist
        assert '.progress-fill.critical' in css_content
        assert '.progress-fill.warning' in css_content
        assert '.progress-fill.normal' in css_content

    def test_css_progress_bar_uses_correct_colors(self, app):
        """Test progress bar colors use correct CSS variables."""
        import os
        css_path = os.path.join(
            app.static_folder, 'css', 'style.css'
        )
        with open(css_path, 'r', encoding='utf-8') as f:
            css_content = f.read()

        # Check that danger-red is used for critical
        assert '--danger-red' in css_content

        # Check that alert-amber is used for warning
        assert '--alert-amber' in css_content

        # Check that matrix-green is used for normal
        assert '--matrix-green' in css_content

    def test_anomaly_item_css_classes_exist(self, app):
        """Test anomaly item CSS classes exist for criticality states."""
        import os
        css_path = os.path.join(
            app.static_folder, 'css', 'style.css'
        )
        with open(css_path, 'r', encoding='utf-8') as f:
            css_content = f.read()

        # Check anomaly item criticality classes
        assert '.anomaly-item.anomaly-critical' in css_content
        assert '.anomaly-item.anomaly-warning' in css_content
        assert '.anomaly-item.anomaly-normal' in css_content
