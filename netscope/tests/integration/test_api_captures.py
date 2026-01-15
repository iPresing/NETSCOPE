"""Integration tests for Capture API endpoints."""

import pytest
from unittest.mock import patch, MagicMock

from app.models.capture import (
    CaptureConfig,
    CaptureSession,
    CaptureStatus,
    CaptureResult,
    CaptureSummary,
)
from app.core.capture.tcpdump_manager import reset_tcpdump_manager


@pytest.fixture(autouse=True)
def reset_manager():
    """Reset TcpdumpManager before and after each test."""
    reset_tcpdump_manager()
    yield
    reset_tcpdump_manager()


class TestCaptureStartEndpoint:
    """Tests for POST /api/captures/start endpoint."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_start_capture_success(self, mock_get_manager, client):
        """Test successful capture start."""
        mock_session = MagicMock(spec=CaptureSession)
        mock_session.id = "cap_test_123"
        mock_session.status = CaptureStatus.RUNNING
        mock_session.to_dict.return_value = {
            "capture_id": "cap_test_123",
            "status": "running",
            "config": {"duration_seconds": 120},
        }

        mock_manager = MagicMock()
        mock_manager.start_capture.return_value = mock_session
        mock_get_manager.return_value = mock_manager

        response = client.post(
            "/api/captures/start",
            json={"duration": 120, "interface": "eth0"},
            content_type="application/json",
        )

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "session" in data
        assert data["session"]["capture_id"] == "cap_test_123"

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_start_capture_default_values(self, mock_get_manager, client):
        """Test capture start with default values."""
        mock_session = MagicMock(spec=CaptureSession)
        mock_session.id = "cap_test"
        mock_session.status = CaptureStatus.RUNNING
        mock_session.to_dict.return_value = {
            "capture_id": "cap_test",
            "status": "running",
            "config": {"duration_seconds": 120},
        }

        mock_manager = MagicMock()
        mock_manager.start_capture.return_value = mock_session
        mock_get_manager.return_value = mock_manager

        response = client.post(
            "/api/captures/start",
            json={},
            content_type="application/json",
        )

        assert response.status_code == 200
        mock_manager.start_capture.assert_called_once()

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_start_capture_already_running(self, mock_get_manager, client):
        """Test error when capture already running."""
        from app.models.capture import CaptureError, CAPTURE_ALREADY_RUNNING

        mock_manager = MagicMock()
        mock_manager.start_capture.side_effect = CaptureError(
            code=CAPTURE_ALREADY_RUNNING,
            message="Une capture est deja en cours",
        )
        mock_get_manager.return_value = mock_manager

        response = client.post(
            "/api/captures/start",
            json={},
            content_type="application/json",
        )

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == CAPTURE_ALREADY_RUNNING

    def test_start_capture_invalid_duration(self, client):
        """Test error with invalid duration."""
        response = client.post(
            "/api/captures/start",
            json={"duration": 10},  # Too short
            content_type="application/json",
        )

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "CAPTURE_INVALID_DURATION"


class TestCaptureStopEndpoint:
    """Tests for POST /api/captures/stop endpoint."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_stop_capture_success(self, mock_get_manager, client):
        """Test successful capture stop."""
        mock_session = MagicMock(spec=CaptureSession)
        mock_session.id = "cap_test_123"
        mock_session.status = CaptureStatus.STOPPED
        mock_session.to_dict.return_value = {
            "capture_id": "cap_test_123",
            "status": "stopped",
        }

        mock_manager = MagicMock()
        mock_manager.stop_capture.return_value = mock_session
        mock_get_manager.return_value = mock_manager

        response = client.post("/api/captures/stop")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["session"]["status"] == "stopped"

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_stop_capture_not_running(self, mock_get_manager, client):
        """Test error when no capture is running."""
        from app.models.capture import CaptureError, CAPTURE_NOT_RUNNING

        mock_manager = MagicMock()
        mock_manager.stop_capture.side_effect = CaptureError(
            code=CAPTURE_NOT_RUNNING,
            message="Aucune capture en cours",
        )
        mock_get_manager.return_value = mock_manager

        response = client.post("/api/captures/stop")

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == CAPTURE_NOT_RUNNING


class TestCaptureStatusEndpoint:
    """Tests for GET /api/captures/status endpoint."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_status_idle(self, mock_get_manager, client):
        """Test status when idle."""
        mock_manager = MagicMock()
        mock_manager.get_status.return_value = None
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/status")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["status"] == "idle"
        assert data["session"] is None

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_status_running(self, mock_get_manager, client):
        """Test status when running."""
        mock_session = MagicMock(spec=CaptureSession)
        mock_session.status = CaptureStatus.RUNNING
        mock_session.to_dict.return_value = {
            "capture_id": "cap_test",
            "status": "running",
        }

        mock_manager = MagicMock()
        mock_manager.get_status.return_value = mock_session
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/status")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["status"] == "running"


class TestCaptureLatestEndpoint:
    """Tests for GET /api/captures/latest endpoint."""

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_latest_no_capture(self, mock_get_manager, client):
        """Test latest when no capture available."""
        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = None
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"] is None

    @patch("app.blueprints.api.captures.get_tcpdump_manager")
    def test_latest_with_result(self, mock_get_manager, client):
        """Test latest with capture result."""
        mock_result = MagicMock(spec=CaptureResult)
        mock_result.packets = []
        mock_result.to_dict.return_value = {
            "session": {"capture_id": "cap_test"},
            "summary": {"total_packets": 100},
            "packets_count": 100,
        }

        mock_manager = MagicMock()
        mock_manager.get_latest_result.return_value = mock_result
        mock_get_manager.return_value = mock_manager

        response = client.get("/api/captures/latest")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"] is not None


class TestCaptureConfigEndpoint:
    """Tests for GET /api/captures/config endpoint."""

    def test_get_config(self, client):
        """Test getting capture configuration options."""
        response = client.get("/api/captures/config")

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert "config" in data
        assert "duration" in data["config"]
        assert data["config"]["duration"]["default"] == 120
        assert data["config"]["duration"]["min"] == 30
        assert data["config"]["duration"]["max"] == 600
