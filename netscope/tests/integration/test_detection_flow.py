"""Integration tests for detection flow.

Tests the complete flow: capture -> parse -> detect -> API.
Story 2.2: Detection Blacklists 3 Types
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
from app.core.detection.blacklist_detector import (
    BlacklistDetector,
    create_detector,
)
from app.core.detection.anomaly_store import (
    get_anomaly_store,
    reset_anomaly_store,
)
from app.models.capture import PacketInfo
from app.models.anomaly import CriticalityLevel


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


class TestDetectionToAPIFlow:
    """Test detection results accessible via API (AC5)."""

    def test_detect_and_store_anomalies(self, loaded_manager):
        """Test that detected anomalies are stored in AnomalyStore."""
        # Create packets with blacklisted IP
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

        # Detect and store
        detector = create_detector()
        collection = detector.detect_all(packets, capture_id="cap_test_001")

        store = get_anomaly_store()
        store.store(collection)

        # Verify stored
        stored = store.get_by_capture("cap_test_001")
        assert stored is not None
        assert stored.total == 1
        assert stored.anomalies[0].match.matched_value == "45.33.32.156"

    def test_get_latest_anomalies(self, loaded_manager):
        """Test get_latest returns most recent collection."""
        store = get_anomaly_store()

        # Store first collection
        detector = create_detector()
        packets1 = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=1,
                port_dst=1,
                protocol="TCP",
                length=100,
            ),
        ]
        collection1 = detector.detect_all(packets1, capture_id="cap_001")
        store.store(collection1)

        # Store second collection
        packets2 = [
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
        collection2 = detector.detect_all(packets2, capture_id="cap_002")
        store.store(collection2)

        # Get latest should return second collection
        latest = store.get_latest()
        assert latest is not None
        assert latest.capture_id == "cap_002"

    def test_get_anomaly_by_id(self, loaded_manager):
        """Test retrieving specific anomaly by ID."""
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

        # Get anomaly by ID
        anomaly_id = collection.anomalies[0].id
        retrieved = store.get_anomaly(anomaly_id)

        assert retrieved is not None
        assert retrieved.id == anomaly_id
        assert retrieved.match.matched_value == "45.33.32.156"


class TestAPIEndpoints:
    """Test anomalies API endpoints (AC5)."""

    def test_get_anomalies_empty(self, client):
        """Test GET /api/anomalies returns empty when no anomalies."""
        response = client.get('/api/anomalies')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['success'] is True
        assert data['result']['total'] == 0
        assert data['result']['anomalies'] == []

    def test_get_anomalies_with_data(self, client, loaded_manager):
        """Test GET /api/anomalies returns detected anomalies."""
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

        # Call API
        response = client.get('/api/anomalies')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['success'] is True
        assert data['result']['total'] == 1
        assert len(data['result']['anomalies']) == 1

        anomaly = data['result']['anomalies'][0]
        assert anomaly['match_type'] == 'ip'
        assert anomaly['matched_value'] == '45.33.32.156'
        assert anomaly['criticality'] == 'critical'

    def test_get_anomalies_by_capture_id(self, client, loaded_manager):
        """Test GET /api/anomalies?capture_id=X filters by capture."""
        store = get_anomaly_store()
        detector = create_detector()

        # Store anomalies for two captures
        packets1 = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=1,
                port_dst=1,
                protocol="TCP",
                length=100,
            ),
        ]
        collection1 = detector.detect_all(packets1, capture_id="cap_001")
        store.store(collection1)

        packets2 = [
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
        collection2 = detector.detect_all(packets2, capture_id="cap_002")
        store.store(collection2)

        # Get anomalies for specific capture
        response = client.get('/api/anomalies?capture_id=cap_001')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['result']['total'] == 1
        assert data['result']['anomalies'][0]['matched_value'] == '45.33.32.156'

    def test_get_anomaly_by_id(self, client, loaded_manager):
        """Test GET /api/anomalies/{id} returns specific anomaly."""
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

        anomaly_id = collection.anomalies[0].id

        # Call API
        response = client.get(f'/api/anomalies/{anomaly_id}')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['success'] is True
        assert data['anomaly']['id'] == anomaly_id
        assert data['anomaly']['matched_value'] == '45.33.32.156'

    def test_get_anomaly_not_found(self, client):
        """Test GET /api/anomalies/{id} returns 404 for unknown ID."""
        response = client.get('/api/anomalies/nonexistent_id')
        assert response.status_code == 404

        data = json.loads(response.data)
        assert data['success'] is False
        assert data['error']['code'] == 'ANOMALY_NOT_FOUND'

    def test_get_anomalies_summary(self, client, loaded_manager):
        """Test GET /api/anomalies/summary returns statistics."""
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

        # Call API
        response = client.get('/api/anomalies/summary')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['success'] is True
        assert data['summary']['total'] == 2
        assert data['summary']['by_criticality']['critical'] == 2
        assert data['summary']['by_type']['ip'] == 2


class TestAnomalyResponseFormat:
    """Test API response format matches specification (AC5)."""

    def test_anomaly_contains_required_fields(self, client, loaded_manager):
        """Test each anomaly contains: type, value, score, source, criticality."""
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

        response = client.get('/api/anomalies')
        data = json.loads(response.data)

        anomaly = data['result']['anomalies'][0]

        # Required fields per AC5
        assert 'match_type' in anomaly  # type
        assert 'matched_value' in anomaly  # value
        assert 'score' in anomaly  # score
        assert 'source_file' in anomaly  # source blacklist
        assert 'criticality' in anomaly  # criticality

        # Packet info
        assert 'packet_info' in anomaly
        assert anomaly['packet_info'] is not None

    def test_by_criticality_counts(self, client, loaded_manager):
        """Test by_criticality counts in response."""
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

        response = client.get('/api/anomalies')
        data = json.loads(response.data)

        by_criticality = data['result']['by_criticality']
        assert 'critical' in by_criticality
        assert 'warning' in by_criticality
        assert 'normal' in by_criticality
        assert by_criticality['critical'] == 2


class TestCaptureWithIPBlacklisted:
    """Test capture with blacklisted IP generates CRITICAL anomaly (AC1)."""

    def test_blacklisted_ip_is_critical(self, loaded_manager):
        """Test that blacklisted IP detection results in CRITICAL level."""
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
        collection = detector.detect_all(packets)

        assert collection.total == 1
        anomaly = collection.anomalies[0]
        assert anomaly.criticality_level == CriticalityLevel.CRITICAL
        assert anomaly.match.criticality == CriticalityLevel.CRITICAL

    def test_blacklist_source_indicated(self, loaded_manager):
        """Test that blacklist source is indicated in anomaly."""
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
        collection = detector.detect_all(packets)

        assert collection.total == 1
        assert collection.anomalies[0].match.source_file is not None
        assert len(collection.anomalies[0].match.source_file) > 0
