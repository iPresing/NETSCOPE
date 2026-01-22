"""Integration tests for Four Essentials API endpoint.

Tests the complete flow: capture -> analyze -> API response.
Story 2.4: 4 Analyses Essentielles (AC5, AC6)
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime
from pathlib import Path

from app.models.capture import (
    CaptureConfig,
    CaptureSession,
    CaptureStatus,
    CaptureResult,
    CaptureSummary,
    PacketInfo,
)
from app.models.anomaly import (
    Anomaly,
    AnomalyCollection,
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
)
from app.core.capture.tcpdump_manager import reset_tcpdump_manager
from app.core.analysis.four_essentials import reset_four_essentials_analyzer
from app.core.detection.anomaly_store import reset_anomaly_store, get_anomaly_store


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset all singletons before and after each test."""
    reset_tcpdump_manager()
    reset_four_essentials_analyzer()
    reset_anomaly_store()
    yield
    reset_tcpdump_manager()
    reset_four_essentials_analyzer()
    reset_anomaly_store()


@pytest.fixture
def capture_session():
    """Create a sample capture session."""
    return CaptureSession(
        id="cap_20260122_150000",
        config=CaptureConfig(duration=120),
        status=CaptureStatus.COMPLETED,
        start_time=datetime.now(),
        capture_path=Path("/tmp/test.pcap"),
    )


@pytest.fixture
def normal_summary():
    """Create a normal capture summary."""
    return CaptureSummary(
        total_packets=500,
        total_bytes=250000,
        unique_ips=10,
        unique_ports=15,
        protocols={"TCP": 350, "UDP": 100, "ICMP": 50},
        top_ips=[
            ("192.168.1.10", 200),
            ("192.168.1.20", 150),
            ("192.168.1.1", 100),
            ("8.8.8.8", 50),
        ],
        top_ports=[
            (443, 200),
            (80, 150),
            (53, 100),
            (22, 50),
        ],
        bytes_per_protocol={"TCP": 175000, "UDP": 50000, "ICMP": 25000},
        duration_actual=60.0,
    )


@pytest.fixture
def suspicious_summary():
    """Create a summary with suspicious activity."""
    return CaptureSummary(
        total_packets=300,
        total_bytes=150000,
        unique_ips=8,
        unique_ports=12,
        protocols={"TCP": 280, "UDP": 20},
        top_ips=[
            ("45.33.32.156", 150),  # External/suspicious
            ("192.168.1.10", 100),
            ("192.168.1.20", 50),
        ],
        top_ports=[
            (4444, 100),  # Metasploit
            (443, 100),
            (80, 50),
            (1337, 50),  # L33t
        ],
        bytes_per_protocol={"TCP": 140000, "UDP": 10000},
        duration_actual=30.0,
    )


@pytest.fixture
def normal_packets():
    """Create normal traffic packets."""
    base_time = datetime.now()
    return [
        PacketInfo(
            timestamp=base_time,
            ip_src="192.168.1.10",
            ip_dst="192.168.1.20",
            port_src=49832,
            port_dst=80,
            protocol="TCP",
            length=500,
        )
        for _ in range(100)
    ]


@pytest.fixture
def normal_capture_result(capture_session, normal_packets, normal_summary):
    """Create a normal capture result."""
    return CaptureResult(
        session=capture_session,
        packets=normal_packets,
        summary=normal_summary,
    )


@pytest.fixture
def suspicious_capture_result(capture_session, suspicious_summary):
    """Create a capture result with suspicious activity."""
    base_time = datetime.now()
    packets = [
        PacketInfo(
            timestamp=base_time,
            ip_src="192.168.1.10",
            ip_dst="45.33.32.156",
            port_src=49832,
            port_dst=4444,
            protocol="TCP",
            length=500,
        )
        for _ in range(50)
    ]
    return CaptureResult(
        session=capture_session,
        packets=packets,
        summary=suspicious_summary,
    )


@pytest.fixture
def blacklist_anomaly():
    """Create a blacklist anomaly."""
    return Anomaly(
        id="anomaly_12345678",
        match=BlacklistMatch(
            match_type=MatchType.IP,
            matched_value="45.33.32.156",
            source_file="ips_blacklist",
            context="Malicious IP detected",
            criticality=CriticalityLevel.CRITICAL,
        ),
        score=85,
        criticality_level=CriticalityLevel.CRITICAL,
        capture_id="cap_20260122_150000",
    )


class TestEssentialsEndpointNoCapture:
    """Tests for /api/captures/essentials when no capture available."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_no_capture_returns_404(self, mock_get_manager, client):
        """Test essentials endpoint returns 404 when no capture."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = None
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")

        assert response.status_code == 404
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "ANALYSIS_NO_CAPTURE"

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_wrong_capture_id_returns_404(self, mock_get_manager, client, normal_capture_result):
        """Test essentials endpoint returns 404 for wrong capture_id."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials?capture_id=wrong_id")

        assert response.status_code == 404
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "CAPTURE_NOT_FOUND"


class TestEssentialsEndpointSuccess:
    """Tests for successful /api/captures/essentials responses."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_returns_all_four_analyses(self, mock_get_manager, client, normal_capture_result):
        """Test essentials endpoint returns all 4 analyses."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "result" in data

        result = data["result"]
        assert "capture_id" in result
        assert "top_ips" in result
        assert "protocols" in result
        assert "ports" in result
        assert "volume" in result
        assert "overall_status" in result
        assert "overall_indicator" in result

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_analysis_structure(self, mock_get_manager, client, normal_capture_result):
        """Test each analysis has correct structure (AC5)."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")
        data = response.get_json()
        result = data["result"]

        # Check each analysis has required fields
        for analysis_name in ["top_ips", "protocols", "ports", "volume"]:
            analysis = result[analysis_name]
            assert "name" in analysis
            assert "title" in analysis
            assert "status" in analysis
            assert "indicator" in analysis
            assert "data" in analysis
            assert "message" in analysis
            assert "details" in analysis

            # Status should be valid value
            assert analysis["status"] in ["critical", "warning", "normal"]

            # Indicator should be emoji
            assert analysis["indicator"] in ["🔴", "🟡", "🟢"]

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_normal_traffic_green(self, mock_get_manager, client, normal_capture_result):
        """Test normal traffic returns green indicators."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")
        data = response.get_json()
        result = data["result"]

        # Normal traffic should have mostly normal status
        assert result["overall_status"] == "normal"
        assert result["overall_indicator"] == "🟢"

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_suspicious_traffic_red(self, mock_get_manager, client, suspicious_capture_result, blacklist_anomaly):
        """Test suspicious traffic with blacklist returns red indicators."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = suspicious_capture_result
        mock_get_manager.return_value = mock_manager

        # Store anomaly
        anomaly_store = get_anomaly_store()
        collection = AnomalyCollection(
            anomalies=[blacklist_anomaly],
            capture_id="cap_20260122_150000",
        )
        anomaly_store.store(collection)

        response = client.get("/api/captures/essentials")
        data = response.get_json()
        result = data["result"]

        # Should have critical status due to blacklist + suspicious ports
        assert result["overall_status"] == "critical"
        assert result["overall_indicator"] == "🔴"

        # Top IPs should be critical (blacklisted IP)
        assert result["top_ips"]["status"] == "critical"

        # Ports should be critical (4444, 1337)
        assert result["ports"]["status"] == "critical"


class TestEssentialsEndpointData:
    """Tests for data content in essentials response (AC5, AC6)."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_top_ips_data_content(self, mock_get_manager, client, normal_capture_result):
        """Test top_ips contains required data for dashboard cards (AC6)."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")
        data = response.get_json()
        top_ips = data["result"]["top_ips"]

        # Data should contain enriched IP list
        assert "ips" in top_ips["data"]
        assert "total_unique" in top_ips["data"]
        assert "blacklisted_count" in top_ips["data"]

        # Each IP should have type info
        for ip_info in top_ips["data"]["ips"]:
            assert "ip" in ip_info
            assert "count" in ip_info
            assert "is_external" in ip_info
            assert "type" in ip_info

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_protocols_data_content(self, mock_get_manager, client, normal_capture_result):
        """Test protocols contains distribution data (AC6)."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")
        data = response.get_json()
        protocols = data["result"]["protocols"]

        assert "distribution" in protocols["data"]
        assert "total_packets" in protocols["data"]

        # Distribution should have protocol breakdown
        distribution = protocols["data"]["distribution"]
        for proto_data in distribution.values():
            assert "count" in proto_data
            assert "percentage" in proto_data

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_ports_data_content(self, mock_get_manager, client, normal_capture_result):
        """Test ports contains enriched port list (AC6)."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")
        data = response.get_json()
        ports = data["result"]["ports"]

        assert "ports" in ports["data"]
        assert "total_unique" in ports["data"]
        assert "suspicious_count" in ports["data"]

        # Each port should have description
        for port_info in ports["data"]["ports"]:
            assert "port" in port_info
            assert "count" in port_info
            assert "is_suspicious" in port_info
            assert "description" in port_info

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_volume_data_content(self, mock_get_manager, client, normal_capture_result):
        """Test volume contains traffic statistics (AC6)."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")
        data = response.get_json()
        volume = data["result"]["volume"]

        assert "total_packets" in volume["data"]
        assert "total_bytes" in volume["data"]
        assert "bytes_in" in volume["data"]
        assert "bytes_out" in volume["data"]
        assert "ratio" in volume["data"]
        assert "duration_seconds" in volume["data"]
        assert "packets_per_second" in volume["data"]


class TestEssentialsEndpointWithCaptureId:
    """Tests for /api/captures/essentials with capture_id parameter."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_with_matching_capture_id(self, mock_get_manager, client, normal_capture_result):
        """Test essentials with matching capture_id returns success."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials?capture_id=cap_20260122_150000")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["capture_id"] == "cap_20260122_150000"


class TestEssentialsEndpointErrorHandling:
    """Tests for error handling in essentials endpoint."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_handles_analysis_error(self, mock_get_manager, client, capture_session):
        """Test essentials handles analysis errors gracefully."""
        # Create a capture result that might cause issues
        mock_result = MagicMock(spec=CaptureResult)
        mock_result.session = capture_session
        mock_result.packets = []
        mock_result.summary = CaptureSummary()

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = mock_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")

        # Should either succeed with empty data or return error
        assert response.status_code in [200, 500]

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_essentials_handles_manager_error(self, mock_get_manager, client):
        """Test essentials handles manager errors."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.side_effect = Exception("Manager error")
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/essentials")

        assert response.status_code == 500
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "ANALYSIS_FAILED"


class TestEssentialsEndpointIntegration:
    """Full integration tests for essentials endpoint."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_full_flow_capture_to_essentials(self, mock_get_manager, client, normal_capture_result, blacklist_anomaly):
        """Test complete flow from capture to essentials analysis."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = normal_capture_result
        mock_get_manager.return_value = mock_manager

        # 1. Store anomalies
        anomaly_store = get_anomaly_store()
        collection = AnomalyCollection(
            anomalies=[blacklist_anomaly],
            capture_id="cap_20260122_150000",
        )
        anomaly_store.store(collection)

        # 2. Get essentials
        response = client.get("/api/captures/essentials")

        assert response.status_code == 200
        data = response.get_json()

        # 3. Verify complete response structure for dashboard
        result = data["result"]

        # Verify data is ready for dashboard cards (AC6)
        # Each analysis should have indicator + message for card display
        for analysis_key in ["top_ips", "protocols", "ports", "volume"]:
            analysis = result[analysis_key]
            # Card needs indicator for status icon
            assert analysis["indicator"] in ["🔴", "🟡", "🟢"]
            # Card needs message for summary
            assert len(analysis["message"]) > 0
            # Card can link to data for details
            assert isinstance(analysis["data"], dict)
