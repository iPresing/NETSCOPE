"""Unit tests for ScoringEngine.

Tests scoring cascade multi-criteres for anomalies.
Story 2.3: Scoring Cascade Multi-Criteres
"""

import pytest
import time
from datetime import datetime

from app.core.analysis.scoring import (
    ScoringEngine,
    ScoreBreakdown,
    HeuristicFactors,
    get_scoring_engine,
    reset_scoring_engine,
)
from app.models.anomaly import (
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
)
from app.models.capture import PacketInfo


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset ScoringEngine singleton before and after each test."""
    reset_scoring_engine()
    yield
    reset_scoring_engine()


@pytest.fixture
def engine():
    """Get a fresh ScoringEngine instance."""
    return ScoringEngine()


@pytest.fixture
def ip_blacklist_match():
    """Create a sample IP blacklist match."""
    return BlacklistMatch(
        match_type=MatchType.IP,
        matched_value="45.33.32.156",
        source_file="ips_blacklist",
        context="IP 45.33.32.156:4444 (destination)",
        criticality=CriticalityLevel.CRITICAL,
        timestamp=datetime.now(),
    )


@pytest.fixture
def domain_blacklist_match():
    """Create a sample domain blacklist match."""
    return BlacklistMatch(
        match_type=MatchType.DOMAIN,
        matched_value="malware.com",
        source_file="domains_blacklist",
        context="Domain malware.com in DNS query",
        criticality=CriticalityLevel.CRITICAL,
        timestamp=datetime.now(),
    )


@pytest.fixture
def term_blacklist_match():
    """Create a sample term blacklist match."""
    return BlacklistMatch(
        match_type=MatchType.TERM,
        matched_value="/bin/bash -i",
        source_file="terms_suspect",
        context="Suspicious term in payload",
        criticality=CriticalityLevel.WARNING,
        timestamp=datetime.now(),
    )


@pytest.fixture
def external_ip_packet():
    """Create a packet with external IP and suspicious port."""
    return PacketInfo(
        timestamp=datetime.now(),
        ip_src="192.168.1.10",
        ip_dst="45.33.32.156",  # External IP
        port_src=49832,
        port_dst=4444,  # Suspicious port (Metasploit)
        protocol="TCP",
        length=100,
    )


@pytest.fixture
def internal_ip_packet():
    """Create a packet with internal IPs only."""
    return PacketInfo(
        timestamp=datetime.now(),
        ip_src="192.168.1.10",
        ip_dst="192.168.1.20",  # Internal IP
        port_src=49832,
        port_dst=80,  # Normal port
        protocol="TCP",
        length=100,
    )


class TestScoringEngineInit:
    """Test ScoringEngine initialization."""

    def test_engine_init(self, engine):
        """Test ScoringEngine initializes with default values."""
        assert engine is not None
        assert engine._thresholds == {"critical": 80, "warning": 50}
        assert engine._blacklist_base["ip"] == 85
        assert engine._blacklist_base["domain"] == 80
        assert engine._blacklist_base["term"] == 65  # AC1: 60-79 range for WARNING

    def test_get_scoring_engine_singleton(self):
        """Test get_scoring_engine returns singleton."""
        engine1 = get_scoring_engine()
        engine2 = get_scoring_engine()
        assert engine1 is engine2

    def test_reset_scoring_engine(self):
        """Test reset_scoring_engine creates new instance."""
        engine1 = get_scoring_engine()
        reset_scoring_engine()
        engine2 = get_scoring_engine()
        assert engine1 is not engine2


class TestBlacklistScoring:
    """Test blacklist base scoring (AC1, AC3)."""

    def test_score_ip_blacklist_critical(self, engine, ip_blacklist_match):
        """Test IP blacklist gives score 80-100 CRITICAL."""
        breakdown = engine.calculate_score(ip_blacklist_match)

        assert breakdown.blacklist_score == 85
        assert breakdown.total_score >= 80
        assert breakdown.criticality == CriticalityLevel.CRITICAL

    def test_score_domain_blacklist_critical(self, engine, domain_blacklist_match):
        """Test domain blacklist gives score 80-100 CRITICAL."""
        breakdown = engine.calculate_score(domain_blacklist_match)

        assert breakdown.blacklist_score == 80
        assert breakdown.total_score >= 80
        assert breakdown.criticality == CriticalityLevel.CRITICAL

    def test_score_term_suspect_warning(self, engine, term_blacklist_match):
        """Test term suspect gives score 60-79 WARNING."""
        breakdown = engine.calculate_score(term_blacklist_match)

        assert breakdown.blacklist_score == 65
        # Without heuristics, term should be WARNING (65 >= 50, AC1: 60-79)
        assert breakdown.criticality == CriticalityLevel.WARNING

    def test_score_breakdown_structure(self, engine, ip_blacklist_match):
        """Test ScoreBreakdown contains all required fields."""
        breakdown = engine.calculate_score(ip_blacklist_match)

        assert isinstance(breakdown, ScoreBreakdown)
        assert isinstance(breakdown.blacklist_score, int)
        assert isinstance(breakdown.heuristic_score, int)
        assert isinstance(breakdown.total_score, int)
        assert isinstance(breakdown.factors, HeuristicFactors)
        assert isinstance(breakdown.criticality, CriticalityLevel)


class TestHeuristicScoring:
    """Test heuristic bonus scoring (AC2)."""

    def test_external_ip_bonus(self, engine, ip_blacklist_match, external_ip_packet):
        """Test external IP adds bonus points."""
        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=external_ip_packet,
        )

        assert breakdown.factors.is_external_ip is True
        assert breakdown.heuristic_score >= 10  # external_ip bonus

    def test_suspicious_port_bonus(self, engine, ip_blacklist_match, external_ip_packet):
        """Test suspicious port adds bonus points."""
        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=external_ip_packet,
        )

        # Port 4444 is suspicious
        assert breakdown.factors.is_suspicious_port is True
        assert breakdown.factors.suspicious_port_value == 4444
        assert breakdown.heuristic_score >= 15  # suspicious_port bonus

    def test_internal_ip_no_bonus(self, engine, ip_blacklist_match, internal_ip_packet):
        """Test internal IP does not add external_ip bonus."""
        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=internal_ip_packet,
        )

        assert breakdown.factors.is_external_ip is False

    def test_normal_port_no_bonus(self, engine, ip_blacklist_match, internal_ip_packet):
        """Test normal port does not add suspicious_port bonus."""
        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=internal_ip_packet,
        )

        assert breakdown.factors.is_suspicious_port is False
        assert breakdown.factors.suspicious_port_value is None

    def test_high_volume_bonus(self, engine, ip_blacklist_match, external_ip_packet):
        """Test high volume context adds bonus points."""
        context = {"packet_count": 150}  # Above threshold (100)

        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=external_ip_packet,
            context=context,
        )

        assert breakdown.factors.is_high_volume is True
        assert breakdown.factors.volume_packets == 150

    def test_combination_multiplier(self, engine, ip_blacklist_match, external_ip_packet):
        """Test combination multiplier applies when 2+ factors."""
        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=external_ip_packet,
        )

        # External IP + Suspicious port = 2 factors
        factor_count = breakdown.factors.count_positive()
        assert factor_count >= 2

        # Score should be multiplied (1.2x) and capped at 100
        base_plus_bonus = breakdown.blacklist_score + breakdown.heuristic_score
        expected_max = min(int(base_plus_bonus * 1.2), 100)
        assert breakdown.total_score == expected_max


class TestCriticalityLevel:
    """Test criticality level attribution (AC3)."""

    def test_score_80_plus_is_critical(self, engine, ip_blacklist_match, external_ip_packet):
        """Test score >= 80 returns CRITICAL."""
        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=external_ip_packet,
        )

        assert breakdown.total_score >= 80
        assert breakdown.criticality == CriticalityLevel.CRITICAL

    def test_score_50_79_is_warning(self, engine, term_blacklist_match):
        """Test score 50-79 returns WARNING."""
        breakdown = engine.calculate_score(term_blacklist_match)

        assert 50 <= breakdown.total_score < 80
        assert breakdown.criticality == CriticalityLevel.WARNING

    def test_criticality_calculation(self, engine):
        """Test _calculate_criticality method directly."""
        assert engine._calculate_criticality(100) == CriticalityLevel.CRITICAL
        assert engine._calculate_criticality(80) == CriticalityLevel.CRITICAL
        assert engine._calculate_criticality(79) == CriticalityLevel.WARNING
        assert engine._calculate_criticality(50) == CriticalityLevel.WARNING
        assert engine._calculate_criticality(49) == CriticalityLevel.NORMAL
        assert engine._calculate_criticality(0) == CriticalityLevel.NORMAL


class TestExternalIPDetection:
    """Test RFC1918 private IP detection."""

    def test_rfc1918_10_x(self, engine):
        """Test 10.x.x.x is private."""
        assert engine._is_external_ip("10.0.0.1") is False
        assert engine._is_external_ip("10.255.255.255") is False

    def test_rfc1918_172_16_31(self, engine):
        """Test 172.16-31.x.x is private."""
        assert engine._is_external_ip("172.16.0.1") is False
        assert engine._is_external_ip("172.31.255.255") is False
        # 172.15 and 172.32 are public
        assert engine._is_external_ip("172.15.0.1") is True
        assert engine._is_external_ip("172.32.0.1") is True

    def test_rfc1918_192_168(self, engine):
        """Test 192.168.x.x is private."""
        assert engine._is_external_ip("192.168.0.1") is False
        assert engine._is_external_ip("192.168.255.255") is False

    def test_loopback(self, engine):
        """Test 127.x.x.x is private."""
        assert engine._is_external_ip("127.0.0.1") is False
        assert engine._is_external_ip("127.1.2.3") is False

    def test_link_local(self, engine):
        """Test 169.254.x.x is private."""
        assert engine._is_external_ip("169.254.0.1") is False

    def test_public_ips(self, engine):
        """Test public IPs are detected as external."""
        assert engine._is_external_ip("8.8.8.8") is True
        assert engine._is_external_ip("45.33.32.156") is True
        assert engine._is_external_ip("1.1.1.1") is True

    def test_empty_ip(self, engine):
        """Test empty IP returns False."""
        assert engine._is_external_ip("") is False
        assert engine._is_external_ip(None) is False


class TestSuspiciousPortDetection:
    """Test suspicious port detection."""

    def test_metasploit_port(self, engine):
        """Test port 4444 (Metasploit) is suspicious."""
        assert engine._is_suspicious_port(4444) is True

    def test_leet_port(self, engine):
        """Test port 1337 (l33t) is suspicious."""
        assert engine._is_suspicious_port(1337) is True

    def test_elite_backdoor_port(self, engine):
        """Test port 31337 (elite) is suspicious."""
        assert engine._is_suspicious_port(31337) is True

    def test_netbus_port(self, engine):
        """Test port 12345 (NetBus) is suspicious."""
        assert engine._is_suspicious_port(12345) is True

    def test_vnc_ports(self, engine):
        """Test VNC ports are suspicious."""
        assert engine._is_suspicious_port(5900) is True
        assert engine._is_suspicious_port(5901) is True

    def test_rdp_port(self, engine):
        """Test port 3389 (RDP) is suspicious."""
        assert engine._is_suspicious_port(3389) is True

    def test_normal_ports(self, engine):
        """Test normal ports are not suspicious."""
        assert engine._is_suspicious_port(80) is False
        assert engine._is_suspicious_port(443) is False
        assert engine._is_suspicious_port(22) is False
        assert engine._is_suspicious_port(53) is False

    def test_none_port(self, engine):
        """Test None port returns False."""
        assert engine._is_suspicious_port(None) is False


class TestScoreBreakdownSerialization:
    """Test ScoreBreakdown and HeuristicFactors serialization."""

    def test_heuristic_factors_to_dict(self):
        """Test HeuristicFactors serializes correctly."""
        factors = HeuristicFactors(
            is_external_ip=True,
            is_suspicious_port=True,
            suspicious_port_value=4444,
            is_high_volume=False,
            volume_packets=50,
            is_unknown_protocol=False,
            protocol="TCP",
        )

        result = factors.to_dict()

        assert result["is_external_ip"] is True
        assert result["is_suspicious_port"] is True
        assert result["suspicious_port_value"] == 4444
        assert result["is_high_volume"] is False
        assert result["volume_packets"] == 50
        assert result["protocol"] == "TCP"

    def test_score_breakdown_to_dict(self, engine, ip_blacklist_match, external_ip_packet):
        """Test ScoreBreakdown serializes correctly."""
        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=external_ip_packet,
        )

        result = breakdown.to_dict()

        assert "blacklist_score" in result
        assert "heuristic_score" in result
        assert "total_score" in result
        assert "factors" in result
        assert "criticality" in result
        assert isinstance(result["factors"], dict)
        assert result["criticality"] in ["critical", "warning", "normal"]

    def test_heuristic_factors_count_positive(self):
        """Test count_positive counts correctly."""
        factors = HeuristicFactors(
            is_external_ip=True,
            is_suspicious_port=True,
            is_high_volume=False,
            is_unknown_protocol=True,
        )

        assert factors.count_positive() == 3

        factors2 = HeuristicFactors()
        assert factors2.count_positive() == 0


class TestPerformance:
    """Test scoring performance (AC4: <3 seconds for 10K anomalies)."""

    def test_performance_10k_anomalies(self, engine, ip_blacklist_match):
        """Test scoring 10K anomalies completes in <3 seconds."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            ip_src="192.168.1.10",
            ip_dst="45.33.32.156",
            port_src=49832,
            port_dst=4444,
            protocol="TCP",
            length=100,
        )

        start = time.time()

        for _ in range(10000):
            engine.calculate_score(ip_blacklist_match, packet_info=packet)

        elapsed = time.time() - start

        assert elapsed < 3.0, f"Scoring 10K anomalies took {elapsed:.2f}s (>3s)"

    def test_performance_with_context(self, engine, ip_blacklist_match):
        """Test scoring with context still meets performance target."""
        packet = PacketInfo(
            timestamp=datetime.now(),
            ip_src="192.168.1.10",
            ip_dst="45.33.32.156",
            port_src=49832,
            port_dst=4444,
            protocol="TCP",
            length=100,
        )
        context = {"packet_count": 150}

        start = time.time()

        for _ in range(10000):
            engine.calculate_score(
                ip_blacklist_match,
                packet_info=packet,
                context=context,
            )

        elapsed = time.time() - start

        assert elapsed < 3.0, f"Scoring with context took {elapsed:.2f}s (>3s)"


class TestScoreCapping:
    """Test score is properly capped at 100."""

    def test_score_capped_at_100(self, engine, ip_blacklist_match):
        """Test total score never exceeds 100."""
        # Create packet with many heuristic triggers
        packet = PacketInfo(
            timestamp=datetime.now(),
            ip_src="192.168.1.10",
            ip_dst="45.33.32.156",  # External
            port_src=49832,
            port_dst=4444,  # Suspicious
            protocol="UNKNOWN_PROTO",  # Unknown
            length=100,
        )
        context = {"packet_count": 500}  # High volume

        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=packet,
            context=context,
        )

        # All factors active: 85 + 10 + 15 + 10 + 5 = 125 * 1.2 = 150
        # Should be capped at 100
        assert breakdown.total_score <= 100
        assert breakdown.total_score == 100


class TestPacketInfoDict:
    """Test scoring with dict packet info (API use case)."""

    def test_packet_info_as_dict(self, engine, ip_blacklist_match):
        """Test scoring works with dict instead of PacketInfo."""
        packet_dict = {
            "timestamp": datetime.now().isoformat(),
            "ip_src": "192.168.1.10",
            "ip_dst": "45.33.32.156",
            "port_src": 49832,
            "port_dst": 4444,
            "protocol": "TCP",
            "length": 100,
        }

        breakdown = engine.calculate_score(
            ip_blacklist_match,
            packet_info=packet_dict,
        )

        assert breakdown.factors.is_external_ip is True
        assert breakdown.factors.is_suspicious_port is True
        assert breakdown.total_score >= 80
