"""Integration tests for scoring flow.

Tests the complete flow: capture -> detect -> score -> API.
Story 2.3: Scoring Cascade Multi-Criteres
"""

import pytest
import time
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
from app.core.analysis.scoring import (
    get_scoring_engine,
    reset_scoring_engine,
)
from app.models.capture import PacketInfo
from app.models.anomaly import CriticalityLevel


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singletons before and after each test."""
    reset_blacklist_manager()
    reset_anomaly_store()
    reset_scoring_engine()
    yield
    reset_blacklist_manager()
    reset_anomaly_store()
    reset_scoring_engine()


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


class TestScoringIntegration:
    """Test scoring integration with detection flow (AC1, AC2, AC3)."""

    def test_detection_uses_scoring_engine(self, loaded_manager):
        """Test that BlacklistDetector uses ScoringEngine for scoring."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",  # Blacklisted + External
                port_src=49832,
                port_dst=4444,  # Suspicious port
                protocol="TCP",
                length=100,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="cap_test")

        assert collection.total == 1
        anomaly = collection.anomalies[0]

        # Should have score_breakdown from ScoringEngine
        assert anomaly.score_breakdown is not None
        assert anomaly.score_breakdown.blacklist_score == 85  # IP base score
        assert anomaly.score_breakdown.heuristic_score > 0  # External IP + suspicious port

    def test_score_includes_heuristic_factors(self, loaded_manager):
        """Test that score includes heuristic bonuses."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",  # External IP
                port_src=49832,
                port_dst=4444,  # Suspicious port (Metasploit)
                protocol="TCP",
                length=100,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="cap_test")
        breakdown = collection.anomalies[0].score_breakdown

        # Check heuristic factors
        assert breakdown.factors.is_external_ip is True
        assert breakdown.factors.is_suspicious_port is True
        assert breakdown.factors.suspicious_port_value == 4444

    def test_score_capped_at_100(self, loaded_manager):
        """Test that total score is capped at 100."""
        detector = create_detector()
        # Create packet with many heuristic triggers
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=4444,
                protocol="UNKNOWN",  # Unknown protocol
                length=100,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="cap_test")
        anomaly = collection.anomalies[0]

        assert anomaly.score <= 100
        assert anomaly.score_breakdown.total_score <= 100


class TestAPIWithScoreBreakdown:
    """Test API returns score breakdown when requested (AC5)."""

    def test_get_anomalies_without_breakdown(self, client, loaded_manager):
        """Test GET /api/anomalies returns anomalies without breakdown by default."""
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

        # Call API without include_breakdown
        response = client.get('/api/anomalies')
        assert response.status_code == 200

        data = json.loads(response.data)
        anomaly = data['result']['anomalies'][0]

        # Should NOT have score_breakdown by default
        assert 'score_breakdown' not in anomaly

    def test_get_anomalies_with_breakdown(self, client, loaded_manager):
        """Test GET /api/anomalies?include_breakdown=true returns breakdown."""
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

        # Call API with include_breakdown=true
        response = client.get('/api/anomalies?include_breakdown=true')
        assert response.status_code == 200

        data = json.loads(response.data)
        anomaly = data['result']['anomalies'][0]

        # Should have score_breakdown
        assert 'score_breakdown' in anomaly
        breakdown = anomaly['score_breakdown']

        assert 'blacklist_score' in breakdown
        assert 'heuristic_score' in breakdown
        assert 'total_score' in breakdown
        assert 'factors' in breakdown
        assert 'criticality' in breakdown

        # Verify values
        assert breakdown['blacklist_score'] == 85
        assert breakdown['total_score'] == anomaly['score']

    def test_breakdown_factors_structure(self, client, loaded_manager):
        """Test score breakdown factors have correct structure."""
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

        response = client.get('/api/anomalies?include_breakdown=true')
        data = json.loads(response.data)

        factors = data['result']['anomalies'][0]['score_breakdown']['factors']

        # Check all factor fields exist
        assert 'is_external_ip' in factors
        assert 'is_suspicious_port' in factors
        assert 'suspicious_port_value' in factors
        assert 'is_high_volume' in factors
        assert 'volume_packets' in factors
        assert 'is_unknown_protocol' in factors
        assert 'protocol' in factors


class TestScoreStatsAPI:
    """Test /api/anomalies/score-stats endpoint (AC5)."""

    def test_score_stats_empty(self, client):
        """Test score stats returns zeros when no anomalies."""
        response = client.get('/api/anomalies/score-stats')
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data['success'] is True
        assert data['stats']['total_anomalies'] == 0
        assert data['stats']['avg_score'] == 0

    def test_score_stats_with_data(self, client, loaded_manager):
        """Test score stats returns correct statistics."""
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

        response = client.get('/api/anomalies/score-stats')
        assert response.status_code == 200

        data = json.loads(response.data)
        stats = data['stats']

        assert stats['total_anomalies'] == 2
        assert stats['avg_score'] > 0
        assert stats['min_score'] > 0
        assert stats['max_score'] <= 100

        # Check score distribution
        assert 'score_distribution' in stats
        assert 'critical' in stats['score_distribution']
        assert stats['score_distribution']['critical']['count'] == 2

        # Check heuristic factors
        assert 'heuristic_factors' in stats
        assert 'external_ip' in stats['heuristic_factors']
        assert 'suspicious_port' in stats['heuristic_factors']


class TestCriticalityFromScore:
    """Test criticality is correctly determined from score (AC3)."""

    def test_ip_blacklist_is_critical(self, loaded_manager):
        """Test IP blacklist with external IP + suspicious port = CRITICAL."""
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
        anomaly = collection.anomalies[0]

        # Score >= 80 should be CRITICAL
        assert anomaly.score >= 80
        assert anomaly.criticality_level == CriticalityLevel.CRITICAL
        assert anomaly.score_breakdown.criticality == CriticalityLevel.CRITICAL

    def test_criticality_matches_score(self, loaded_manager):
        """Test criticality level matches score thresholds."""
        detector = create_detector()
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",
                port_src=49832,
                port_dst=80,  # Normal port
                protocol="TCP",
                length=100,
            ),
        ]

        collection = detector.detect_all(packets)
        anomaly = collection.anomalies[0]

        score = anomaly.score
        criticality = anomaly.criticality_level

        # Verify criticality matches score
        if score >= 80:
            assert criticality == CriticalityLevel.CRITICAL
        elif score >= 50:
            assert criticality == CriticalityLevel.WARNING
        else:
            assert criticality == CriticalityLevel.NORMAL


class TestPerformanceIntegration:
    """Test scoring performance in full detection flow (AC4)."""

    def test_detection_with_scoring_performance(self, loaded_manager):
        """Test detection + scoring for 1000 packets completes quickly."""
        detector = create_detector()

        # Generate 1000 packets (mix of blacklisted and clean)
        packets = []
        for i in range(1000):
            if i % 10 == 0:
                ip_dst = "45.33.32.156"  # Blacklisted
            else:
                ip_dst = f"8.8.{i % 256}.{i % 128}"

            packets.append(
                PacketInfo(
                    timestamp=datetime.now(),
                    ip_src="192.168.1.10",
                    ip_dst=ip_dst,
                    port_src=10000 + i,
                    port_dst=80,
                    protocol="TCP",
                    length=100,
                )
            )

        start = time.time()
        collection = detector.detect_all(packets, capture_id="cap_perf")
        elapsed = time.time() - start

        # Should complete in <1 second for 1000 packets
        assert elapsed < 1.0, f"Detection with scoring took {elapsed:.2f}s"

        # Should have detected the blacklisted IPs
        assert collection.total >= 1


class TestEndToEndScoringFlow:
    """Test complete end-to-end scoring flow."""

    def test_complete_flow_capture_to_api(self, client, loaded_manager):
        """Test complete flow: detect -> score -> store -> API."""
        # Step 1: Create packets with blacklisted IP
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

        # Step 2: Detect (includes scoring)
        detector = create_detector()
        collection = detector.detect_all(packets, capture_id="cap_e2e")

        # Verify scoring was applied
        assert collection.total == 1
        anomaly = collection.anomalies[0]
        assert anomaly.score_breakdown is not None
        assert anomaly.score > 0

        # Step 3: Store
        store = get_anomaly_store()
        store.store(collection)

        # Step 4: Retrieve via API
        response = client.get('/api/anomalies?include_breakdown=true')
        assert response.status_code == 200

        data = json.loads(response.data)
        api_anomaly = data['result']['anomalies'][0]

        # Verify API returns scored data
        assert api_anomaly['score'] == anomaly.score
        assert 'score_breakdown' in api_anomaly
        assert api_anomaly['score_breakdown']['total_score'] == anomaly.score
        assert api_anomaly['criticality'] == anomaly.criticality_level.value
