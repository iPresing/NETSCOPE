"""Integration tests for Dashboard Results display (Story 1.6).

Note: Requires 'client' fixture from tests/conftest.py (Flask test client).
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from app.models.capture import (
    CaptureConfig,
    CaptureSession,
    CaptureStatus,
    CaptureResult,
    CaptureSummary,
    PacketInfo,
)
from app.core.capture.tcpdump_manager import reset_tcpdump_manager


@pytest.fixture(autouse=True)
def reset_manager():
    """Reset TcpdumpManager before and after each test."""
    reset_tcpdump_manager()
    yield
    reset_tcpdump_manager()


def create_test_session(capture_id="cap_test"):
    """Helper to create a test CaptureSession."""
    return CaptureSession(
        id=capture_id,
        config=CaptureConfig(),
        status=CaptureStatus.COMPLETED,
    )


class TestLatestCaptureResponse:
    """Tests for /api/captures/latest response format."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_latest_returns_top_ports(self, mock_get_manager, client):
        """Test that latest capture returns top_ports field."""
        summary = CaptureSummary(
            total_packets=100,
            total_bytes=5000,
            unique_ips=10,
            unique_ports=20,
            protocols={"TCP": 80, "UDP": 20},
            top_ips=[("192.168.1.1", 50), ("192.168.1.2", 30)],
            top_ports=[(443, 40), (80, 30), (53, 20)],
            bytes_per_protocol={"TCP": 4000, "UDP": 1000},
            duration_actual=120.5,
        )

        result = CaptureResult(session=create_test_session(), summary=summary)

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"] is not None

        summary_data = data["result"]["summary"]
        assert "top_ports" in summary_data
        assert len(summary_data["top_ports"]) == 3
        assert summary_data["top_ports"][0]["port"] == 443
        assert summary_data["top_ports"][0]["count"] == 40

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_latest_returns_bytes_per_protocol(self, mock_get_manager, client):
        """Test that latest capture returns bytes_per_protocol field."""
        summary = CaptureSummary(
            total_packets=100,
            total_bytes=5000,
            protocols={"TCP": 80, "UDP": 20},
            bytes_per_protocol={"TCP": 4000, "UDP": 1000},
        )

        result = CaptureResult(session=create_test_session(), summary=summary)

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest")

        assert response.status_code == 200
        data = response.get_json()

        summary_data = data["result"]["summary"]
        assert "bytes_per_protocol" in summary_data
        assert summary_data["bytes_per_protocol"]["TCP"] == 4000
        assert summary_data["bytes_per_protocol"]["UDP"] == 1000

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_latest_full_json_format(self, mock_get_manager, client):
        """Test that latest returns all expected fields in correct format."""
        summary = CaptureSummary(
            total_packets=1523,
            total_bytes=567890,
            unique_ips=15,
            unique_ports=42,
            protocols={"TCP": 950, "UDP": 520, "ICMP": 53},
            top_ips=[
                ("192.168.1.1", 450),
                ("10.0.0.1", 380),
                ("8.8.8.8", 120),
            ],
            top_ports=[
                (443, 380),
                (80, 250),
                (53, 120),
            ],
            bytes_per_protocol={"TCP": 450000, "UDP": 100000, "ICMP": 17890},
            duration_actual=120.5,
        )

        result = CaptureResult(
            session=create_test_session("cap_20260115_143001"),
            summary=summary,
        )

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True

        result_data = data["result"]
        summary_data = result_data["summary"]

        # Verify all expected fields exist
        assert summary_data["total_packets"] == 1523
        assert summary_data["total_bytes"] == 567890
        assert summary_data["unique_ips"] == 15
        assert summary_data["unique_ports"] == 42
        assert summary_data["duration_actual_seconds"] == 120.5

        # Verify protocols structure
        assert summary_data["protocols"]["TCP"] == 950
        assert summary_data["protocols"]["UDP"] == 520
        assert summary_data["protocols"]["ICMP"] == 53

        # Verify top_ips structure
        assert len(summary_data["top_ips"]) == 3
        assert summary_data["top_ips"][0] == {"ip": "192.168.1.1", "count": 450}

        # Verify top_ports structure (new field)
        assert len(summary_data["top_ports"]) == 3
        assert summary_data["top_ports"][0] == {"port": 443, "count": 380}
        assert summary_data["top_ports"][1] == {"port": 80, "count": 250}

        # Verify bytes_per_protocol structure (new field)
        assert summary_data["bytes_per_protocol"]["TCP"] == 450000
        assert summary_data["bytes_per_protocol"]["UDP"] == 100000


class TestCaptureResultReplacement:
    """Tests for capture result replacement (AC3)."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_new_capture_replaces_previous(self, mock_get_manager, client):
        """Test that new capture results replace previous ones."""
        # First capture
        first_summary = CaptureSummary(
            total_packets=100,
            top_ports=[(80, 50)],
        )
        first_result = CaptureResult(
            session=create_test_session("cap_first"),
            summary=first_summary,
        )

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = first_result
        mock_get_manager.return_value = mock_manager

        response1 = client.get("/api/captures/latest")
        data1 = response1.get_json()
        assert data1["result"]["summary"]["total_packets"] == 100

        # Second capture (simulating new results)
        second_summary = CaptureSummary(
            total_packets=200,
            top_ports=[(443, 100)],
        )
        second_result = CaptureResult(
            session=create_test_session("cap_second"),
            summary=second_summary,
        )

        mock_manager.get_latest_result.return_value = second_result

        response2 = client.get("/api/captures/latest")
        data2 = response2.get_json()

        # Verify new results replace old ones
        assert data2["result"]["summary"]["total_packets"] == 200
        assert data2["result"]["summary"]["top_ports"][0]["port"] == 443


class TestIncludePacketsParameter:
    """Tests for include_packets parameter."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_include_packets_returns_packet_list(self, mock_get_manager, client):
        """Test that include_packets=true returns packet details."""
        packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 1),
                ip_src="192.168.1.1",
                ip_dst="8.8.8.8",
                port_src=12345,
                port_dst=443,
                protocol="TCP",
                length=100,
            ),
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, 2),
                ip_src="192.168.1.1",
                ip_dst="8.8.4.4",
                port_src=12346,
                port_dst=53,
                protocol="UDP",
                length=80,
            ),
        ]

        result = CaptureResult(
            session=create_test_session(),
            packets=packets,
            summary=CaptureSummary(total_packets=2),
        )

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest?include_packets=true")

        assert response.status_code == 200
        data = response.get_json()

        assert "packets" in data
        assert len(data["packets"]) == 2
        assert data["packets"][0]["ip_src"] == "192.168.1.1"
        assert data["packets"][0]["port_dst"] == 443
        assert data["packets"][0]["protocol"] == "TCP"

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_packets_limited_to_max(self, mock_get_manager, client):
        """Test that packets are limited to prevent huge responses."""
        # Create more than the limit (1000)
        packets = [
            PacketInfo(
                timestamp=datetime(2026, 1, 15, 14, 30, i % 60),
                ip_src="192.168.1.1",
                ip_dst="8.8.8.8",
                port_src=10000 + i,
                port_dst=443,
                protocol="TCP",
                length=100,
            )
            for i in range(1500)
        ]

        result = CaptureResult(
            session=create_test_session(),
            packets=packets,
            summary=CaptureSummary(total_packets=1500),
        )

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest?include_packets=true")

        assert response.status_code == 200
        data = response.get_json()

        assert len(data["packets"]) == 1000  # Limited to 1000
        assert data["packets_truncated"] is True


class TestEmptyCaptureSummary:
    """Tests for edge cases with empty or minimal data."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_empty_top_ports(self, mock_get_manager, client):
        """Test response when no ports detected (e.g., ICMP only)."""
        summary = CaptureSummary(
            total_packets=50,
            protocols={"ICMP": 50},
            top_ips=[("192.168.1.1", 50)],
            top_ports=[],  # No ports for ICMP
            bytes_per_protocol={"ICMP": 5000},
        )

        result = CaptureResult(session=create_test_session(), summary=summary)

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest")

        assert response.status_code == 200
        data = response.get_json()

        summary_data = data["result"]["summary"]
        assert summary_data["top_ports"] == []
        assert summary_data["protocols"]["ICMP"] == 50

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_zero_packets_capture(self, mock_get_manager, client):
        """Test response when capture has zero packets."""
        summary = CaptureSummary(
            total_packets=0,
            total_bytes=0,
            top_ips=[],
            top_ports=[],
            protocols={},
            bytes_per_protocol={},
        )

        result = CaptureResult(session=create_test_session(), summary=summary)

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest")

        assert response.status_code == 200
        data = response.get_json()

        summary_data = data["result"]["summary"]
        assert summary_data["total_packets"] == 0
        assert summary_data["top_ips"] == []
        assert summary_data["top_ports"] == []
        assert summary_data["protocols"] == {}
        assert summary_data["bytes_per_protocol"] == {}
