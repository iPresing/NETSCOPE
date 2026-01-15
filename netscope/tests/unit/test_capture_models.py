"""Unit tests for capture models."""

import pytest
from datetime import datetime
from pathlib import Path

from app.models.capture import (
    CaptureConfig,
    CaptureError,
    CaptureResult,
    CaptureSession,
    CaptureStatus,
    CaptureSummary,
    PacketInfo,
    validate_duration,
    CAPTURE_INVALID_DURATION,
    MIN_CAPTURE_DURATION,
    MAX_CAPTURE_DURATION,
    DEFAULT_CAPTURE_DURATION,
)


class TestCaptureStatus:
    """Tests for CaptureStatus enum."""

    def test_all_statuses_exist(self):
        """Test that all expected statuses exist."""
        assert CaptureStatus.IDLE.value == "idle"
        assert CaptureStatus.RUNNING.value == "running"
        assert CaptureStatus.COMPLETED.value == "completed"
        assert CaptureStatus.STOPPED.value == "stopped"
        assert CaptureStatus.ERROR.value == "error"


class TestCaptureConfig:
    """Tests for CaptureConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = CaptureConfig()
        assert config.duration == 120
        assert config.interface == "auto"
        assert config.bpf_filter == "not port 22"

    def test_custom_values(self):
        """Test custom configuration values."""
        config = CaptureConfig(
            duration=60,
            interface="eth0",
            bpf_filter="tcp",
        )
        assert config.duration == 60
        assert config.interface == "eth0"
        assert config.bpf_filter == "tcp"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = CaptureConfig(duration=90, interface="usb0")
        result = config.to_dict()

        assert result["duration_seconds"] == 90
        assert result["interface"] == "usb0"
        assert "bpf_filter" in result


class TestPacketInfo:
    """Tests for PacketInfo dataclass."""

    def test_creation(self):
        """Test PacketInfo creation."""
        now = datetime.utcnow()
        packet = PacketInfo(
            timestamp=now,
            ip_src="192.168.1.1",
            ip_dst="192.168.1.2",
            port_src=12345,
            port_dst=80,
            protocol="TCP",
            length=100,
        )

        assert packet.timestamp == now
        assert packet.ip_src == "192.168.1.1"
        assert packet.ip_dst == "192.168.1.2"
        assert packet.port_src == 12345
        assert packet.port_dst == 80
        assert packet.protocol == "TCP"
        assert packet.length == 100

    def test_to_dict(self):
        """Test conversion to dictionary."""
        now = datetime.utcnow()
        packet = PacketInfo(
            timestamp=now,
            ip_src="10.0.0.1",
            ip_dst="10.0.0.2",
            port_src=None,
            port_dst=None,
            protocol="ICMP",
        )
        result = packet.to_dict()

        assert result["ip_src"] == "10.0.0.1"
        assert result["ip_dst"] == "10.0.0.2"
        assert result["port_src"] is None
        assert result["protocol"] == "ICMP"
        assert "timestamp" in result


class TestCaptureSummary:
    """Tests for CaptureSummary dataclass."""

    def test_default_values(self):
        """Test default summary values."""
        summary = CaptureSummary()
        assert summary.total_packets == 0
        assert summary.total_bytes == 0
        assert summary.unique_ips == 0
        assert summary.unique_ports == 0
        assert summary.protocols == {}
        assert summary.top_ips == []

    def test_to_dict(self):
        """Test conversion to dictionary."""
        summary = CaptureSummary(
            total_packets=100,
            total_bytes=5000,
            unique_ips=10,
            unique_ports=5,
            protocols={"TCP": 80, "UDP": 20},
            top_ips=[("192.168.1.1", 50), ("192.168.1.2", 30)],
            duration_actual=120.5,
        )
        result = summary.to_dict()

        assert result["total_packets"] == 100
        assert result["total_bytes"] == 5000
        assert result["unique_ips"] == 10
        assert result["protocols"]["TCP"] == 80
        assert len(result["top_ips"]) == 2
        assert result["top_ips"][0]["ip"] == "192.168.1.1"
        assert result["duration_actual_seconds"] == 120.5


class TestCaptureSession:
    """Tests for CaptureSession dataclass."""

    def test_creation(self):
        """Test CaptureSession creation."""
        config = CaptureConfig()
        session = CaptureSession(
            id="cap_20260115_120000",
            config=config,
            status=CaptureStatus.RUNNING,
            start_time=datetime.utcnow(),
        )

        assert session.id == "cap_20260115_120000"
        assert session.status == CaptureStatus.RUNNING
        assert session.is_running is True
        assert session.end_time is None

    def test_is_running_property(self):
        """Test is_running property."""
        config = CaptureConfig()

        running = CaptureSession(
            id="test",
            config=config,
            status=CaptureStatus.RUNNING,
        )
        assert running.is_running is True

        completed = CaptureSession(
            id="test",
            config=config,
            status=CaptureStatus.COMPLETED,
        )
        assert completed.is_running is False

    def test_duration_elapsed(self):
        """Test duration_elapsed property."""
        config = CaptureConfig()
        session = CaptureSession(
            id="test",
            config=config,
            start_time=datetime.utcnow(),
        )

        # Should be very small (just created)
        assert session.duration_elapsed >= 0
        assert session.duration_elapsed < 1

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = CaptureConfig()
        session = CaptureSession(
            id="cap_test",
            config=config,
            status=CaptureStatus.COMPLETED,
            pid=12345,
        )
        result = session.to_dict()

        assert result["capture_id"] == "cap_test"
        assert result["status"] == "completed"
        assert result["pid"] == 12345
        assert "config" in result


class TestCaptureResult:
    """Tests for CaptureResult dataclass."""

    def test_creation(self):
        """Test CaptureResult creation."""
        session = CaptureSession(
            id="test",
            config=CaptureConfig(),
            status=CaptureStatus.COMPLETED,
        )
        result = CaptureResult(session=session)

        assert result.session is session
        assert result.packets == []
        assert result.summary.total_packets == 0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        session = CaptureSession(
            id="test",
            config=CaptureConfig(),
        )
        result = CaptureResult(session=session)
        data = result.to_dict()

        assert "session" in data
        assert "summary" in data
        assert data["packets_count"] == 0


class TestCaptureError:
    """Tests for CaptureError exception."""

    def test_creation(self):
        """Test CaptureError creation."""
        error = CaptureError(
            code="TEST_ERROR",
            message="Test error message",
            details={"key": "value"},
        )

        assert error.code == "TEST_ERROR"
        assert error.message == "Test error message"
        assert error.details == {"key": "value"}
        assert str(error) == "Test error message"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        error = CaptureError(
            code="TEST_ERROR",
            message="Test message",
        )
        result = error.to_dict()

        assert result["code"] == "TEST_ERROR"
        assert result["message"] == "Test message"
        assert result["details"] == {}


class TestValidateDuration:
    """Tests for validate_duration()."""

    def test_valid_minimum(self):
        """Test minimum valid duration."""
        result = validate_duration(MIN_CAPTURE_DURATION)
        assert result == MIN_CAPTURE_DURATION

    def test_valid_maximum(self):
        """Test maximum valid duration."""
        result = validate_duration(MAX_CAPTURE_DURATION)
        assert result == MAX_CAPTURE_DURATION

    def test_valid_default(self):
        """Test default duration."""
        result = validate_duration(DEFAULT_CAPTURE_DURATION)
        assert result == DEFAULT_CAPTURE_DURATION

    def test_too_short(self):
        """Test duration below minimum."""
        with pytest.raises(CaptureError) as exc_info:
            validate_duration(MIN_CAPTURE_DURATION - 1)
        assert exc_info.value.code == CAPTURE_INVALID_DURATION

    def test_too_long(self):
        """Test duration above maximum."""
        with pytest.raises(CaptureError) as exc_info:
            validate_duration(MAX_CAPTURE_DURATION + 1)
        assert exc_info.value.code == CAPTURE_INVALID_DURATION

    def test_converts_string(self):
        """Test that string is converted to int."""
        result = validate_duration("120")
        assert result == 120

    def test_invalid_string(self):
        """Test that invalid string raises error."""
        with pytest.raises(CaptureError) as exc_info:
            validate_duration("not a number")
        assert exc_info.value.code == CAPTURE_INVALID_DURATION
