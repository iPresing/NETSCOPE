"""Unit tests for BlacklistDetector.

Tests blacklist detection for IPs, domains, and suspicious terms.
Story 2.2: Detection Blacklists 3 Types
"""

import pytest
from datetime import datetime
from pathlib import Path
import tempfile

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
from app.models.anomaly import (
    Anomaly,
    AnomalyCollection,
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
    SCORE_IP_BLACKLIST,
)


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset singletons before and after each test."""
    reset_blacklist_manager()
    reset_anomaly_store()
    yield
    reset_blacklist_manager()
    reset_anomaly_store()


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

        # Create domains_phishing.txt
        (defaults_dir / "domains_phishing.txt").write_text(
            "# Test domains\n"
            "malware.com\n"
            "phishing-site.org\n"
        )

        # Create terms_suspect.txt
        (defaults_dir / "terms_suspect.txt").write_text(
            "# Test terms\n"
            "/bin/bash -i\n"
            "nc -e /bin/sh\n"
        )

        yield Path(tmpdir)


@pytest.fixture
def loaded_manager(temp_blacklist_dir):
    """Get BlacklistManager loaded with test data."""
    manager = get_blacklist_manager()
    config = {
        "defaults": {
            "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            "domains_phishing": "data/blacklists_defaults/domains_phishing.txt",
            "terms_suspect": "data/blacklists_defaults/terms_suspect.txt",
        }
    }
    manager.load_blacklists(config, base_path=temp_blacklist_dir)
    return manager


@pytest.fixture
def sample_packets():
    """Create sample packets for testing."""
    now = datetime.now()
    return [
        PacketInfo(
            timestamp=now,
            ip_src="192.168.1.10",
            ip_dst="45.33.32.156",  # Blacklisted IP
            port_src=49832,
            port_dst=4444,
            protocol="TCP",
            length=100,
        ),
        PacketInfo(
            timestamp=now,
            ip_src="192.168.1.10",
            ip_dst="8.8.8.8",  # Clean IP (Google DNS)
            port_src=52100,
            port_dst=53,
            protocol="UDP",
            length=64,
        ),
        PacketInfo(
            timestamp=now,
            ip_src="185.220.101.1",  # Blacklisted IP
            ip_dst="192.168.1.10",
            port_src=443,
            port_dst=61234,
            protocol="TCP",
            length=1500,
        ),
    ]


class TestBlacklistDetectorInit:
    """Test BlacklistDetector initialization."""

    def test_create_detector(self, loaded_manager):
        """Test create_detector function creates detector instance."""
        detector = create_detector()
        assert detector is not None
        assert isinstance(detector, BlacklistDetector)

    def test_detector_init(self, loaded_manager):
        """Test BlacklistDetector initialization."""
        detector = BlacklistDetector()
        assert detector is not None
        assert detector._manager is not None


class TestIPDetection:
    """Test IP blacklist detection (AC1)."""

    def test_detect_blacklisted_ip_destination(self, loaded_manager, sample_packets):
        """Test detection of blacklisted IP as destination."""
        detector = BlacklistDetector()

        # Use only packet with blacklisted destination
        packets = [sample_packets[0]]  # ip_dst = 45.33.32.156
        collection = detector.detect_all(packets, capture_id="test_cap")

        assert collection.total == 1
        anomaly = collection.anomalies[0]
        assert anomaly.match.match_type == MatchType.IP
        assert anomaly.match.matched_value == "45.33.32.156"
        assert anomaly.criticality_level == CriticalityLevel.CRITICAL
        assert anomaly.score == SCORE_IP_BLACKLIST

    def test_detect_blacklisted_ip_source(self, loaded_manager, sample_packets):
        """Test detection of blacklisted IP as source."""
        detector = BlacklistDetector()

        # Use only packet with blacklisted source
        packets = [sample_packets[2]]  # ip_src = 185.220.101.1
        collection = detector.detect_all(packets, capture_id="test_cap")

        assert collection.total == 1
        anomaly = collection.anomalies[0]
        assert anomaly.match.matched_value == "185.220.101.1"
        assert anomaly.criticality_level == CriticalityLevel.CRITICAL

    def test_detect_multiple_blacklisted_ips(self, loaded_manager, sample_packets):
        """Test detection of multiple blacklisted IPs."""
        detector = BlacklistDetector()
        collection = detector.detect_all(sample_packets, capture_id="test_cap")

        # Should detect 45.33.32.156 and 185.220.101.1
        assert collection.total == 2
        matched_ips = {a.match.matched_value for a in collection.anomalies}
        assert "45.33.32.156" in matched_ips
        assert "185.220.101.1" in matched_ips

    def test_no_detection_clean_packets(self, loaded_manager):
        """Test no detection for clean packets."""
        detector = BlacklistDetector()

        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="8.8.8.8",
                port_src=12345,
                port_dst=53,
                protocol="UDP",
                length=64,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="test_cap")
        assert collection.total == 0

    def test_no_duplicate_ip_detection(self, loaded_manager):
        """Test that same IP is not detected multiple times."""
        detector = BlacklistDetector()

        # Multiple packets with same blacklisted IP
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
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",  # Same IP again
                port_src=49833,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]

        collection = detector.detect_all(packets, capture_id="test_cap")

        # Should only detect once
        assert collection.total == 1

    def test_ip_context_destination(self, loaded_manager):
        """Test context string for destination IP match."""
        detector = BlacklistDetector()

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

        context = collection.anomalies[0].match.context
        assert "45.33.32.156" in context
        assert "destination" in context
        assert "TCP" in context


class TestDetectionRate:
    """Test 100% detection rate (AC4)."""

    def test_100_percent_detection_rate(self, loaded_manager):
        """Test that 100% of blacklisted items are detected (no false negatives)."""
        detector = BlacklistDetector()

        # Create packets with ALL blacklisted IPs
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
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="10.0.0.99",
                ip_dst="192.168.1.10",
                port_src=3,
                port_dst=3,
                protocol="TCP",
                length=100,
            ),
        ]

        collection = detector.detect_all(packets)

        # All 3 blacklisted IPs should be detected
        assert collection.total == 3
        matched_ips = {a.match.matched_value for a in collection.anomalies}
        assert "45.33.32.156" in matched_ips
        assert "185.220.101.1" in matched_ips
        assert "10.0.0.99" in matched_ips

    def test_no_false_negatives(self, temp_blacklist_dir):
        """Test zero false negatives - all blacklisted IPs detected."""
        # Load blacklist with specific IPs
        manager = get_blacklist_manager()
        config = {
            "defaults": {
                "ips_malware": "data/blacklists_defaults/ips_malware.txt",
            }
        }
        manager.load_blacklists(config, base_path=temp_blacklist_dir)

        # Get all blacklisted IPs
        blacklisted_ips = list(manager.ips)

        # Create packet for each blacklisted IP
        packets = []
        for i, ip in enumerate(blacklisted_ips):
            packets.append(
                PacketInfo(
                    timestamp=datetime.now(),
                    ip_src="192.168.1.10",
                    ip_dst=ip,
                    port_src=10000 + i,
                    port_dst=80,
                    protocol="TCP",
                    length=100,
                )
            )

        detector = BlacklistDetector()
        collection = detector.detect_all(packets)

        # Every blacklisted IP should be detected
        detected_ips = {a.match.matched_value for a in collection.anomalies}
        for ip in blacklisted_ips:
            assert ip in detected_ips, f"False negative: {ip} not detected"


class TestEmptyInput:
    """Test edge cases with empty input."""

    def test_empty_packet_list(self, loaded_manager):
        """Test detection with empty packet list."""
        detector = BlacklistDetector()
        collection = detector.detect_all([], capture_id="test_cap")

        assert collection.total == 0
        assert collection.anomalies == []
        assert collection.capture_id == "test_cap"


class TestAnomalyModel:
    """Test Anomaly model and serialization."""

    def test_anomaly_to_dict(self, loaded_manager, sample_packets):
        """Test anomaly serialization to dictionary."""
        detector = BlacklistDetector()
        collection = detector.detect_all([sample_packets[0]], capture_id="test_cap")

        assert collection.total == 1
        anomaly_dict = collection.anomalies[0].to_dict()

        assert "id" in anomaly_dict
        assert anomaly_dict["match_type"] == "ip"
        assert anomaly_dict["matched_value"] == "45.33.32.156"
        assert anomaly_dict["criticality"] == "critical"
        assert anomaly_dict["score"] == SCORE_IP_BLACKLIST
        assert "packet_info" in anomaly_dict
        assert anomaly_dict["capture_id"] == "test_cap"

    def test_collection_to_dict(self, loaded_manager, sample_packets):
        """Test collection serialization to dictionary."""
        detector = BlacklistDetector()
        collection = detector.detect_all(sample_packets, capture_id="test_cap")

        collection_dict = collection.to_dict()

        assert "anomalies" in collection_dict
        assert "total" in collection_dict
        assert "by_criticality" in collection_dict
        assert collection_dict["total"] == 2
        assert collection_dict["by_criticality"]["critical"] == 2

    def test_anomaly_id_generation(self):
        """Test that anomaly IDs are unique."""
        ids = set()
        for _ in range(100):
            anomaly_id = Anomaly.generate_id()
            assert anomaly_id not in ids
            assert anomaly_id.startswith("anomaly_")
            ids.add(anomaly_id)


class TestCriticalityLevel:
    """Test criticality assignment."""

    def test_ip_match_is_critical(self, loaded_manager, sample_packets):
        """Test that IP matches are marked as CRITICAL."""
        detector = BlacklistDetector()
        collection = detector.detect_all([sample_packets[0]])

        for anomaly in collection.anomalies:
            assert anomaly.criticality_level == CriticalityLevel.CRITICAL
            assert anomaly.match.criticality == CriticalityLevel.CRITICAL


class TestCollectionSorting:
    """Test anomaly collection sorting."""

    def test_get_sorted_by_criticality(self, loaded_manager):
        """Test that anomalies are sorted by criticality."""
        # Create collection with mixed criticalities
        collection = AnomalyCollection(capture_id="test")

        # Add warning anomaly first
        warning_match = BlacklistMatch(
            match_type=MatchType.TERM,
            matched_value="/bin/bash",
            source_file="terms.txt",
            context="Test context",
            criticality=CriticalityLevel.WARNING,
        )
        warning_anomaly = Anomaly(
            id=Anomaly.generate_id(),
            match=warning_match,
            score=50,
            criticality_level=CriticalityLevel.WARNING,
        )
        collection.add(warning_anomaly)

        # Add critical anomaly second
        critical_match = BlacklistMatch(
            match_type=MatchType.IP,
            matched_value="45.33.32.156",
            source_file="ips.txt",
            context="Test context",
            criticality=CriticalityLevel.CRITICAL,
        )
        critical_anomaly = Anomaly(
            id=Anomaly.generate_id(),
            match=critical_match,
            score=85,
            criticality_level=CriticalityLevel.CRITICAL,
        )
        collection.add(critical_anomaly)

        # Get sorted - critical should be first
        sorted_anomalies = collection.get_sorted()
        assert sorted_anomalies[0].criticality_level == CriticalityLevel.CRITICAL
        assert sorted_anomalies[1].criticality_level == CriticalityLevel.WARNING


class TestBlacklistMatchModel:
    """Test BlacklistMatch dataclass."""

    def test_blacklist_match_to_dict(self):
        """Test BlacklistMatch serialization."""
        match = BlacklistMatch(
            match_type=MatchType.IP,
            matched_value="45.33.32.156",
            source_file="ips_malware.txt",
            context="IP detected in traffic",
            criticality=CriticalityLevel.CRITICAL,
        )

        match_dict = match.to_dict()

        assert match_dict["match_type"] == "ip"
        assert match_dict["matched_value"] == "45.33.32.156"
        assert match_dict["source_file"] == "ips_malware.txt"
        assert match_dict["criticality"] == "critical"
        assert "timestamp" in match_dict


class TestEdgeCases:
    """Test edge cases for robustness (Code Review M4)."""

    def test_packet_with_none_ip_src(self, loaded_manager):
        """Test detection handles packet with None ip_src gracefully."""
        detector = BlacklistDetector()

        # Create packet with None ip_src (edge case)
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src=None,  # Edge case: None IP
                ip_dst="45.33.32.156",  # Blacklisted
                port_src=None,
                port_dst=4444,
                protocol="TCP",
                length=100,
            ),
        ]

        # Should not crash, should detect the blacklisted destination IP
        collection = detector.detect_all(packets, capture_id="test_edge")
        assert collection.total == 1
        assert collection.anomalies[0].match.matched_value == "45.33.32.156"

    def test_packet_with_none_ip_dst(self, loaded_manager):
        """Test detection handles packet with None ip_dst gracefully."""
        detector = BlacklistDetector()

        # Create packet with None ip_dst (edge case)
        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="45.33.32.156",  # Blacklisted
                ip_dst=None,  # Edge case: None IP
                port_src=4444,
                port_dst=None,
                protocol="TCP",
                length=100,
            ),
        ]

        # Should not crash, should detect the blacklisted source IP
        collection = detector.detect_all(packets, capture_id="test_edge")
        assert collection.total == 1
        assert collection.anomalies[0].match.matched_value == "45.33.32.156"

    def test_detection_with_no_blacklists_loaded(self):
        """Test detection when BlacklistManager has no blacklists loaded."""
        # Manager is reset by fixture, so no blacklists are loaded
        manager = get_blacklist_manager()
        # Don't load any blacklists

        detector = BlacklistDetector()

        packets = [
            PacketInfo(
                timestamp=datetime.now(),
                ip_src="192.168.1.10",
                ip_dst="45.33.32.156",  # Would be blacklisted if loaded
                port_src=12345,
                port_dst=80,
                protocol="TCP",
                length=100,
            ),
        ]

        # Should not crash, should return empty collection
        collection = detector.detect_all(packets, capture_id="test_empty")
        assert collection.total == 0

    def test_detection_performance_many_packets(self, loaded_manager):
        """Test detection performance with 1000+ packets."""
        detector = BlacklistDetector()

        # Generate 1000 packets (mix of clean and blacklisted)
        packets = []
        for i in range(1000):
            # 10% chance of blacklisted IP
            if i % 10 == 0:
                ip_dst = "45.33.32.156"  # Blacklisted
            else:
                ip_dst = f"8.8.{i % 256}.{i % 128}"  # Clean

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

        import time
        start = time.time()
        collection = detector.detect_all(packets, capture_id="test_perf")
        elapsed = time.time() - start

        # Should complete in reasonable time (<1 second for 1000 packets)
        assert elapsed < 1.0, f"Detection took too long: {elapsed}s"

        # Should detect exactly 1 unique blacklisted IP (deduplicated)
        assert collection.total == 1
