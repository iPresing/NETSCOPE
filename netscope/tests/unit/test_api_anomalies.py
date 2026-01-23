"""Unit tests for anomalies API endpoint.

Story 2.7: Tests for include_breakdown parameter and human_context in response.

Lessons Learned Epic 1 & Stories 2.1-2.6:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
"""

import pytest
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
from app.models.anomaly import Anomaly, AnomalyCollection, CriticalityLevel, MatchType, BlacklistMatch


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
        # Create defaults directory
        defaults_dir = Path(tmpdir) / "data" / "blacklists_defaults"
        defaults_dir.mkdir(parents=True)

        # Create ips_malware.txt with known malicious IPs
        (defaults_dir / "ips_malware.txt").write_text(
            "# Test IPs\n"
            "45.33.32.156\n"
            "185.220.101.1\n"
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


class TestIncludeBreakdownParameter:
    """Tests for include_breakdown query parameter (Story 2.7 Task 6.1)."""

    def test_include_breakdown_false_by_default(self, client, loaded_manager):
        """Test score_breakdown is NOT included when include_breakdown is not set."""
        # Create and store anomaly
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

        # Call API without include_breakdown
        response = client.get('/api/anomalies?latest=true')
        assert response.status_code == 200

        data = json.loads(response.data)
        anomaly = data['result']['anomalies'][0]

        # score_breakdown should NOT be present
        assert 'score_breakdown' not in anomaly

    def test_include_breakdown_true(self, client, loaded_manager):
        """Test score_breakdown IS included when include_breakdown=true."""
        # Create and store anomaly
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

        # Call API with include_breakdown=true
        response = client.get('/api/anomalies?latest=true&include_breakdown=true')
        assert response.status_code == 200

        data = json.loads(response.data)
        anomaly = data['result']['anomalies'][0]

        # score_breakdown SHOULD be present
        assert 'score_breakdown' in anomaly
        assert anomaly['score_breakdown'] is not None

    def test_include_breakdown_contains_expected_fields(self, client, loaded_manager):
        """Test score_breakdown contains expected fields."""
        # Create and store anomaly
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
        breakdown = data['result']['anomalies'][0]['score_breakdown']

        # Check expected fields per Story 2.3
        assert 'blacklist_score' in breakdown
        assert 'heuristic_score' in breakdown
        assert 'total_score' in breakdown
        assert 'criticality' in breakdown


class TestHumanContextInResponse:
    """Tests for human_context in API response (Story 2.7 Task 6.2)."""

    def test_human_context_included_in_response(self, client, loaded_manager):
        """Test human_context is included when present on anomaly."""
        # Create and store anomaly with human_context
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

        # human_context should be present (added by Story 2.5)
        assert 'human_context' in anomaly
        assert anomaly['human_context'] is not None

    def test_human_context_contains_expected_fields(self, client, loaded_manager):
        """Test human_context contains expected fields from Story 2.5."""
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
        human_context = data['result']['anomalies'][0]['human_context']

        # Check expected fields per Story 2.5 HumanContext dataclass
        assert 'short_message' in human_context
        assert 'explanation' in human_context
        assert 'risk_level' in human_context
        assert 'indicator' in human_context
        assert 'action_hint' in human_context


class TestByCriticalityCounts:
    """Tests for by_criticality counts in response (Story 2.7 AC1)."""

    def test_by_criticality_present_in_response(self, client, loaded_manager):
        """Test by_criticality is present in API response."""
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

        response = client.get('/api/anomalies?latest=true')
        data = json.loads(response.data)

        assert 'by_criticality' in data['result']
        by_crit = data['result']['by_criticality']

        assert 'critical' in by_crit
        assert 'warning' in by_crit
        assert 'normal' in by_crit

    def test_by_criticality_counts_correct(self, client, loaded_manager):
        """Test by_criticality counts are correct."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=1,
                port_dst=1,
                protocol="TCP",
                length=100,
            ),
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="185.220.101.1",
                ip_dst="192.168.1.10",
                port_src=2,
                port_dst=2,
                protocol="TCP",
                length=100,
            ),
        ]
        collection = detector.detect_all(packets, capture_id="cap_test")
        store = get_anomaly_store()
        store.store(collection)

        response = client.get('/api/anomalies?latest=true')
        data = json.loads(response.data)

        by_crit = data['result']['by_criticality']
        # Both IPs are blacklisted, so both should be critical
        assert by_crit['critical'] == 2
        assert by_crit['warning'] == 0
        assert by_crit['normal'] == 0


class TestAnomaliesSortedByScore:
    """Tests for anomalies sorted by score (Story 2.7 AC1)."""

    def test_anomalies_sorted_by_criticality(self, client, loaded_manager):
        """Test anomalies are sorted by criticality (critical first)."""
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
        assert len(anomalies) >= 1

        # All should be critical in this test
        for anomaly in anomalies:
            assert anomaly['criticality'] == 'critical'


class TestEmptyAnomaliesResponse:
    """Tests for empty anomalies response (Story 2.7 AC5)."""

    def test_empty_response_format(self, client):
        """Test empty response has correct format."""
        response = client.get('/api/anomalies?latest=true')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['success'] is True
        assert data['result']['total'] == 0
        assert data['result']['anomalies'] == []
        assert data['result']['by_criticality'] == {
            'critical': 0,
            'warning': 0,
            'normal': 0
        }
