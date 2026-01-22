"""Unit tests for FourEssentialsAnalyzer.

Tests the 4 essential analyses for dashboard:
- Top IPs analysis (AC1)
- Protocol distribution analysis (AC2)
- Ports used analysis (AC3)
- Data volume analysis (AC4)

Story 2.4: 4 Analyses Essentielles
"""

import pytest
import time
from datetime import datetime

from app.core.analysis.four_essentials import (
    FourEssentialsAnalyzer,
    FourEssentialsResult,
    EssentialAnalysis,
    AnalysisStatus,
    INDICATOR_MAP,
    get_four_essentials_analyzer,
    reset_four_essentials_analyzer,
)
from app.models.capture import (
    CaptureResult,
    CaptureSession,
    CaptureConfig,
    CaptureStatus,
    CaptureSummary,
    PacketInfo,
)
from app.models.anomaly import (
    Anomaly,
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
)


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset FourEssentialsAnalyzer singleton before and after each test."""
    reset_four_essentials_analyzer()
    yield
    reset_four_essentials_analyzer()


@pytest.fixture
def analyzer():
    """Get a fresh FourEssentialsAnalyzer instance."""
    return FourEssentialsAnalyzer()


@pytest.fixture
def capture_session():
    """Create a sample capture session."""
    return CaptureSession(
        id="cap_20260122_150000",
        config=CaptureConfig(duration=120),
        status=CaptureStatus.COMPLETED,
        start_time=datetime.now(),
    )


@pytest.fixture
def normal_packets():
    """Create a list of normal internal traffic packets."""
    base_time = datetime.now()
    packets = []
    for i in range(100):
        packets.append(PacketInfo(
            timestamp=base_time,
            ip_src="192.168.1.10",
            ip_dst="192.168.1.20",
            port_src=49832 + i,
            port_dst=80,
            protocol="TCP",
            length=500,
        ))
    return packets


@pytest.fixture
def external_packets():
    """Create packets with external IPs."""
    base_time = datetime.now()
    packets = []
    # External destination traffic
    for i in range(50):
        packets.append(PacketInfo(
            timestamp=base_time,
            ip_src="192.168.1.10",
            ip_dst="8.8.8.8",  # External
            port_src=49832 + i,
            port_dst=443,
            protocol="TCP",
            length=1000,
        ))
    # External source traffic (incoming)
    for i in range(30):
        packets.append(PacketInfo(
            timestamp=base_time,
            ip_src="1.1.1.1",  # External
            ip_dst="192.168.1.10",
            port_src=443,
            port_dst=49832 + i,
            protocol="TCP",
            length=500,
        ))
    return packets


@pytest.fixture
def suspicious_port_packets():
    """Create packets with suspicious ports."""
    base_time = datetime.now()
    packets = []
    for i in range(20):
        packets.append(PacketInfo(
            timestamp=base_time,
            ip_src="192.168.1.10",
            ip_dst="45.33.32.156",  # External
            port_src=49832,
            port_dst=4444,  # Metasploit/Meterpreter
            protocol="TCP",
            length=100,
        ))
    return packets


@pytest.fixture
def high_icmp_packets():
    """Create packets with high ICMP proportion."""
    base_time = datetime.now()
    packets = []
    # 95% ICMP (critical threshold)
    for i in range(95):
        packets.append(PacketInfo(
            timestamp=base_time,
            ip_src="192.168.1.10",
            ip_dst="192.168.1.1",
            port_src=None,
            port_dst=None,
            protocol="ICMP",
            length=64,
        ))
    # 5% TCP
    for i in range(5):
        packets.append(PacketInfo(
            timestamp=base_time,
            ip_src="192.168.1.10",
            ip_dst="192.168.1.20",
            port_src=49832,
            port_dst=80,
            protocol="TCP",
            length=100,
        ))
    return packets


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
def summary_with_suspicious():
    """Create a summary with suspicious ports."""
    return CaptureSummary(
        total_packets=200,
        total_bytes=100000,
        unique_ips=10,
        unique_ports=15,
        protocols={"TCP": 180, "UDP": 20},
        top_ips=[
            ("45.33.32.156", 100),  # External suspicious
            ("192.168.1.10", 80),
            ("8.8.8.8", 20),
        ],
        top_ports=[
            (4444, 80),  # Metasploit
            (443, 60),
            (80, 40),
            (1337, 20),  # L33t
        ],
        bytes_per_protocol={"TCP": 90000, "UDP": 10000},
        duration_actual=120.0,
    )


@pytest.fixture
def summary_high_icmp():
    """Create a summary with high ICMP (suspicious)."""
    return CaptureSummary(
        total_packets=100,
        total_bytes=6400,
        unique_ips=2,
        unique_ports=0,
        protocols={"ICMP": 95, "TCP": 5},
        top_ips=[
            ("192.168.1.10", 95),
            ("192.168.1.1", 95),
        ],
        top_ports=[],
        bytes_per_protocol={"ICMP": 6080, "TCP": 320},
        duration_actual=30.0,
    )


@pytest.fixture
def capture_result_normal(capture_session, normal_packets, normal_summary):
    """Create a normal capture result."""
    return CaptureResult(
        session=capture_session,
        packets=normal_packets,
        summary=normal_summary,
    )


@pytest.fixture
def capture_result_suspicious(capture_session, suspicious_port_packets, summary_with_suspicious):
    """Create a capture result with suspicious activity."""
    return CaptureResult(
        session=capture_session,
        packets=suspicious_port_packets,
        summary=summary_with_suspicious,
    )


@pytest.fixture
def capture_result_icmp(capture_session, high_icmp_packets, summary_high_icmp):
    """Create a capture result with high ICMP."""
    return CaptureResult(
        session=capture_session,
        packets=high_icmp_packets,
        summary=summary_high_icmp,
    )


@pytest.fixture
def blacklisted_ip_anomaly():
    """Create an anomaly for a blacklisted IP."""
    return Anomaly(
        id="anomaly_12345678",
        match=BlacklistMatch(
            match_type=MatchType.IP,
            matched_value="45.33.32.156",
            source_file="ips_blacklist",
            context="IP 45.33.32.156 detected",
            criticality=CriticalityLevel.CRITICAL,
        ),
        score=85,
        criticality_level=CriticalityLevel.CRITICAL,
        capture_id="cap_20260122_150000",
    )


class TestFourEssentialsAnalyzerInit:
    """Test FourEssentialsAnalyzer initialization."""

    def test_analyzer_init(self, analyzer):
        """Test FourEssentialsAnalyzer initializes correctly."""
        assert analyzer is not None
        assert analyzer._suspicious_ports is not None
        assert analyzer._private_prefixes is not None

    def test_get_singleton(self):
        """Test get_four_essentials_analyzer returns singleton."""
        analyzer1 = get_four_essentials_analyzer()
        analyzer2 = get_four_essentials_analyzer()
        assert analyzer1 is analyzer2

    def test_reset_singleton(self):
        """Test reset_four_essentials_analyzer creates new instance."""
        analyzer1 = get_four_essentials_analyzer()
        reset_four_essentials_analyzer()
        analyzer2 = get_four_essentials_analyzer()
        assert analyzer1 is not analyzer2


class TestAnalyzeTopIPs:
    """Test Top IPs analysis (AC1)."""

    def test_normal_traffic_green(self, analyzer, capture_result_normal):
        """Test internal traffic shows green indicator."""
        result = analyzer.analyze(capture_result_normal)

        assert result.top_ips.status == AnalysisStatus.NORMAL
        assert result.top_ips.indicator == "🟢"
        assert "aucune suspecte" in result.top_ips.message.lower()

    def test_blacklisted_ip_red(self, analyzer, capture_result_suspicious, blacklisted_ip_anomaly):
        """Test blacklisted IP shows red indicator."""
        result = analyzer.analyze(capture_result_suspicious, anomalies=[blacklisted_ip_anomaly])

        assert result.top_ips.status == AnalysisStatus.CRITICAL
        assert result.top_ips.indicator == "🔴"
        assert "blacklistee" in result.top_ips.message.lower()

    def test_external_ip_warning(self, analyzer, capture_result_suspicious):
        """Test high-volume external IP shows warning."""
        # Without blacklist anomaly, external IP with high volume = warning
        result = analyzer.analyze(capture_result_suspicious, anomalies=[])

        # 45.33.32.156 has count=100 (>50) and is external
        assert result.top_ips.status == AnalysisStatus.WARNING
        assert result.top_ips.indicator == "🟡"

    def test_top_ips_enriched_data(self, analyzer, capture_result_normal):
        """Test top IPs data is enriched with type info."""
        result = analyzer.analyze(capture_result_normal)

        ips_data = result.top_ips.data["ips"]
        assert len(ips_data) > 0

        for ip_info in ips_data:
            assert "ip" in ip_info
            assert "count" in ip_info
            assert "is_external" in ip_info
            assert "is_blacklisted" in ip_info
            assert "type" in ip_info
            assert ip_info["type"] in ["interne", "externe"]

    def test_internal_external_distinction(self, analyzer, capture_result_suspicious):
        """Test IPs are correctly classified as internal/external."""
        result = analyzer.analyze(capture_result_suspicious)

        ips_data = result.top_ips.data["ips"]

        # Find specific IPs and check classification
        for ip_info in ips_data:
            if ip_info["ip"] == "45.33.32.156":
                assert ip_info["is_external"] is True
                assert ip_info["type"] == "externe"
            elif ip_info["ip"] == "192.168.1.10":
                assert ip_info["is_external"] is False
                assert ip_info["type"] == "interne"


class TestAnalyzeProtocols:
    """Test Protocol Distribution analysis (AC2)."""

    def test_normal_distribution_green(self, analyzer, capture_result_normal):
        """Test normal protocol distribution shows green."""
        result = analyzer.analyze(capture_result_normal)

        assert result.protocols.status == AnalysisStatus.NORMAL
        assert result.protocols.indicator == "🟢"
        assert "distribution normale" in result.protocols.message.lower()

    def test_high_icmp_critical(self, analyzer, capture_result_icmp):
        """Test >90% ICMP shows critical (possible flood/scan)."""
        result = analyzer.analyze(capture_result_icmp)

        assert result.protocols.status == AnalysisStatus.CRITICAL
        assert result.protocols.indicator == "🔴"
        assert "icmp" in result.protocols.message.lower()
        assert "flood" in result.protocols.message.lower() or "scan" in result.protocols.message.lower()

    def test_moderate_icmp_warning(self, analyzer, capture_session):
        """Test 50-90% ICMP shows warning."""
        summary = CaptureSummary(
            total_packets=100,
            protocols={"ICMP": 60, "TCP": 40},
        )
        capture = CaptureResult(session=capture_session, summary=summary)

        result = analyzer.analyze(capture)

        assert result.protocols.status == AnalysisStatus.WARNING
        assert result.protocols.indicator == "🟡"
        assert "icmp" in result.protocols.message.lower()

    def test_protocol_percentages(self, analyzer, capture_result_normal):
        """Test protocol percentages are calculated correctly."""
        result = analyzer.analyze(capture_result_normal)

        distribution = result.protocols.data["distribution"]

        # Verify percentages sum to ~100
        total_pct = sum(p["percentage"] for p in distribution.values())
        assert 99 <= total_pct <= 101  # Allow rounding


class TestAnalyzePorts:
    """Test Ports Used analysis (AC3)."""

    def test_normal_ports_green(self, analyzer, capture_result_normal):
        """Test normal ports show green indicator."""
        result = analyzer.analyze(capture_result_normal)

        assert result.ports.status == AnalysisStatus.NORMAL
        assert result.ports.indicator == "🟢"
        assert "aucun suspect" in result.ports.message.lower()

    def test_suspicious_ports_red(self, analyzer, capture_result_suspicious):
        """Test suspicious ports show red indicator."""
        result = analyzer.analyze(capture_result_suspicious)

        assert result.ports.status == AnalysisStatus.CRITICAL
        assert result.ports.indicator == "🔴"
        assert "suspect" in result.ports.message.lower()
        # Should mention suspicious ports
        assert "4444" in result.ports.message or "1337" in result.ports.message

    def test_suspicious_ports_in_details(self, analyzer, capture_result_suspicious):
        """Test suspicious ports are listed in details."""
        result = analyzer.analyze(capture_result_suspicious)

        assert len(result.ports.details) > 0
        # Details should contain port descriptions
        details_text = " ".join(result.ports.details)
        assert "4444" in details_text

    def test_port_descriptions(self, analyzer, capture_result_normal):
        """Test ports have descriptions."""
        result = analyzer.analyze(capture_result_normal)

        ports_data = result.ports.data["ports"]

        for port_info in ports_data:
            assert "port" in port_info
            assert "count" in port_info
            assert "is_suspicious" in port_info
            assert "description" in port_info

    def test_known_port_descriptions(self, analyzer):
        """Test well-known ports have correct descriptions."""
        assert analyzer.PORT_DESCRIPTIONS[80] == "HTTP"
        assert analyzer.PORT_DESCRIPTIONS[443] == "HTTPS"
        assert analyzer.PORT_DESCRIPTIONS[22] == "SSH"
        assert analyzer.PORT_DESCRIPTIONS[53] == "DNS"


class TestAnalyzeVolume:
    """Test Data Volume analysis (AC4)."""

    def test_normal_volume_green(self, analyzer, capture_result_normal):
        """Test normal volume shows green indicator."""
        result = analyzer.analyze(capture_result_normal)

        assert result.volume.status == AnalysisStatus.NORMAL
        assert result.volume.indicator == "🟢"
        assert "paquets" in result.volume.message.lower()

    def test_high_volume_warning(self, analyzer, capture_session):
        """Test high packet count shows warning."""
        summary = CaptureSummary(
            total_packets=15000,  # > 10000 threshold
            total_bytes=7500000,
            duration_actual=60.0,
        )
        capture = CaptureResult(session=capture_session, packets=[], summary=summary)

        result = analyzer.analyze(capture)

        assert result.volume.status == AnalysisStatus.WARNING
        assert result.volume.indicator == "🟡"
        assert "eleve" in result.volume.message.lower()

    def test_exfiltration_ratio_warning(self, analyzer, capture_session, external_packets):
        """Test high outbound ratio shows exfiltration warning."""
        # Create summary with high outbound
        summary = CaptureSummary(
            total_packets=len(external_packets),
            total_bytes=sum(p.length for p in external_packets),
            duration_actual=60.0,
        )
        capture = CaptureResult(
            session=capture_session,
            packets=external_packets,
            summary=summary,
        )

        result = analyzer.analyze(capture)

        # With 50 packets out (1000 bytes each) vs 30 in (500 bytes each)
        # Ratio should be significant
        volume_data = result.volume.data
        assert "bytes_in" in volume_data
        assert "bytes_out" in volume_data
        assert "ratio" in volume_data

    def test_volume_statistics(self, analyzer, capture_result_normal):
        """Test volume data includes all statistics."""
        result = analyzer.analyze(capture_result_normal)

        volume_data = result.volume.data
        assert "total_packets" in volume_data
        assert "total_bytes" in volume_data
        assert "bytes_in" in volume_data
        assert "bytes_out" in volume_data
        assert "ratio" in volume_data
        assert "duration_seconds" in volume_data
        assert "packets_per_second" in volume_data

    def test_packets_per_second_calculation(self, analyzer, capture_result_normal):
        """Test packets per second is calculated correctly."""
        result = analyzer.analyze(capture_result_normal)

        pps = result.volume.data["packets_per_second"]
        expected_pps = round(100 / 60.0, 1)  # 100 packets / 60 seconds
        assert pps == expected_pps


class TestOverallStatus:
    """Test overall status calculation."""

    def test_all_normal_green(self, analyzer, capture_result_normal):
        """Test all green analyses result in green overall."""
        result = analyzer.analyze(capture_result_normal)

        assert result.overall_status == AnalysisStatus.NORMAL
        assert result.overall_indicator == "🟢"

    def test_one_critical_makes_overall_critical(self, analyzer, capture_result_suspicious, blacklisted_ip_anomaly):
        """Test any critical analysis makes overall critical."""
        result = analyzer.analyze(capture_result_suspicious, anomalies=[blacklisted_ip_anomaly])

        assert result.overall_status == AnalysisStatus.CRITICAL
        assert result.overall_indicator == "🔴"

    def test_warning_without_critical(self, analyzer, capture_session):
        """Test warning without critical shows overall warning."""
        # Create summary with moderate ICMP (warning) but no critical
        summary = CaptureSummary(
            total_packets=100,
            protocols={"ICMP": 55, "TCP": 45},
            top_ips=[("192.168.1.10", 100)],
            top_ports=[(80, 100)],
            duration_actual=60.0,
        )
        capture = CaptureResult(session=capture_session, packets=[], summary=summary)

        result = analyzer.analyze(capture)

        assert result.overall_status == AnalysisStatus.WARNING
        assert result.overall_indicator == "🟡"


class TestFourEssentialsResult:
    """Test FourEssentialsResult dataclass."""

    def test_to_dict_structure(self, analyzer, capture_result_normal):
        """Test to_dict returns complete structure."""
        result = analyzer.analyze(capture_result_normal)
        result_dict = result.to_dict()

        assert "capture_id" in result_dict
        assert "top_ips" in result_dict
        assert "protocols" in result_dict
        assert "ports" in result_dict
        assert "volume" in result_dict
        assert "overall_status" in result_dict
        assert "overall_indicator" in result_dict

    def test_essential_analysis_to_dict(self, analyzer, capture_result_normal):
        """Test each analysis serializes correctly."""
        result = analyzer.analyze(capture_result_normal)

        for analysis in [result.top_ips, result.protocols, result.ports, result.volume]:
            analysis_dict = analysis.to_dict()

            assert "name" in analysis_dict
            assert "title" in analysis_dict
            assert "status" in analysis_dict
            assert "indicator" in analysis_dict
            assert "data" in analysis_dict
            assert "message" in analysis_dict
            assert "details" in analysis_dict

            # Status should be string value
            assert analysis_dict["status"] in ["critical", "warning", "normal"]


class TestIPClassification:
    """Test IP classification methods."""

    def test_private_ips_internal(self, analyzer):
        """Test RFC1918 IPs are classified as internal."""
        assert analyzer._is_internal_ip("10.0.0.1") is True
        assert analyzer._is_internal_ip("172.16.0.1") is True
        assert analyzer._is_internal_ip("192.168.1.1") is True
        assert analyzer._is_internal_ip("127.0.0.1") is True

    def test_public_ips_external(self, analyzer):
        """Test public IPs are classified as external."""
        assert analyzer._is_external_ip("8.8.8.8") is True
        assert analyzer._is_external_ip("1.1.1.1") is True
        assert analyzer._is_external_ip("45.33.32.156") is True

    def test_empty_ip_handling(self, analyzer):
        """Test empty IP handling."""
        assert analyzer._is_external_ip("") is False
        assert analyzer._is_internal_ip("") is True  # Not external = internal


class TestIndicatorMap:
    """Test indicator emoji mapping."""

    def test_indicator_mapping(self):
        """Test status to indicator mapping."""
        assert INDICATOR_MAP[AnalysisStatus.CRITICAL] == "🔴"
        assert INDICATOR_MAP[AnalysisStatus.WARNING] == "🟡"
        assert INDICATOR_MAP[AnalysisStatus.NORMAL] == "🟢"


class TestPerformance:
    """Test analysis performance."""

    def test_performance_10k_packets(self, analyzer, capture_session):
        """Test analysis of 10K packets completes in <1 second."""
        # Generate 10K packets
        base_time = datetime.now()
        packets = []
        for i in range(10000):
            packets.append(PacketInfo(
                timestamp=base_time,
                ip_src="192.168.1.10",
                ip_dst="192.168.1.20" if i % 2 == 0 else "8.8.8.8",
                port_src=49832 + (i % 1000),
                port_dst=80 if i % 3 == 0 else 443,
                protocol="TCP" if i % 4 != 0 else "UDP",
                length=500,
            ))

        summary = CaptureSummary(
            total_packets=10000,
            total_bytes=5000000,
            unique_ips=3,
            unique_ports=1001,
            protocols={"TCP": 7500, "UDP": 2500},
            top_ips=[
                ("192.168.1.10", 5000),
                ("192.168.1.20", 2500),
                ("8.8.8.8", 2500),
            ],
            top_ports=[(80, 3333), (443, 3333), (53, 3334)],
            duration_actual=120.0,
        )
        capture = CaptureResult(session=capture_session, packets=packets, summary=summary)

        start = time.time()
        result = analyzer.analyze(capture)
        elapsed = time.time() - start

        assert result is not None
        assert elapsed < 1.0, f"Analysis of 10K packets took {elapsed:.2f}s (>1s)"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_packets(self, analyzer, capture_session):
        """Test analysis with empty packets list."""
        summary = CaptureSummary(total_packets=0, duration_actual=0.0)
        capture = CaptureResult(session=capture_session, packets=[], summary=summary)

        result = analyzer.analyze(capture)

        # Should not crash, return normal with empty data
        assert result is not None
        assert result.overall_status == AnalysisStatus.NORMAL

    def test_empty_summary(self, analyzer, capture_session):
        """Test analysis with default empty summary."""
        capture = CaptureResult(session=capture_session)

        result = analyzer.analyze(capture)

        assert result is not None

    def test_no_anomalies(self, analyzer, capture_result_normal):
        """Test analysis without anomalies."""
        result = analyzer.analyze(capture_result_normal, anomalies=None)

        assert result is not None
        assert result.top_ips.data["blacklisted_count"] == 0

    def test_zero_duration(self, analyzer, capture_session):
        """Test packets_per_second with zero duration."""
        summary = CaptureSummary(total_packets=100, duration_actual=0.0)
        capture = CaptureResult(session=capture_session, summary=summary)

        result = analyzer.analyze(capture)

        # Should handle division by zero gracefully
        assert result.volume.data["packets_per_second"] == 0
