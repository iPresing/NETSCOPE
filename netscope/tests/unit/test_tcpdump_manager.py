"""Unit tests for TcpdumpManager."""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime
from pathlib import Path

from app.core.capture.tcpdump_manager import (
    TcpdumpManager,
    get_tcpdump_manager,
    reset_tcpdump_manager,
    is_windows,
    get_wsl_path,
    get_windows_path_from_wsl,
)
from app.models.capture import (
    CaptureError,
    CaptureStatus,
    CAPTURE_ALREADY_RUNNING,
    CAPTURE_INVALID_DURATION,
)


class TestIsWindows:
    """Tests for is_windows() function."""

    def test_returns_true_on_windows(self, monkeypatch):
        """Test that is_windows returns True on Windows."""
        monkeypatch.setattr("platform.system", lambda: "Windows")
        assert is_windows() is True

    def test_returns_false_on_linux(self, monkeypatch):
        """Test that is_windows returns False on Linux."""
        monkeypatch.setattr("platform.system", lambda: "Linux")
        assert is_windows() is False

    def test_returns_false_on_darwin(self, monkeypatch):
        """Test that is_windows returns False on macOS."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")
        assert is_windows() is False


class TestGetWslPath:
    """Tests for get_wsl_path() function."""

    def test_converts_c_drive(self):
        """Test conversion of C: drive path."""
        result = get_wsl_path("C:\\Users\\timit\\Documents")
        assert result == "/mnt/c/Users/timit/Documents"

    def test_converts_d_drive(self):
        """Test conversion of D: drive path."""
        result = get_wsl_path("D:\\Projects\\netscope")
        assert result == "/mnt/d/Projects/netscope"

    def test_handles_forward_slashes(self):
        """Test that forward slashes are handled."""
        result = get_wsl_path("C:/Users/timit/Documents")
        assert result == "/mnt/c/Users/timit/Documents"

    def test_preserves_non_windows_path(self):
        """Test that non-Windows paths are preserved."""
        result = get_wsl_path("/opt/netscope/data")
        assert result == "/opt/netscope/data"

    def test_handles_empty_path(self):
        """Test handling of empty path."""
        result = get_wsl_path("")
        assert result == ""

    def test_handles_lowercase_drive(self):
        """Test handling of lowercase drive letter."""
        result = get_wsl_path("c:\\Users\\timit")
        assert result == "/mnt/c/Users/timit"


class TestGetWindowsPathFromWsl:
    """Tests for get_windows_path_from_wsl() function."""

    def test_converts_mnt_path(self):
        """Test conversion of /mnt/ path back to Windows."""
        result = get_windows_path_from_wsl("/mnt/c/Users/timit/Documents")
        assert result == "C:\\Users\\timit\\Documents"

    def test_preserves_non_wsl_path(self):
        """Test that non-WSL paths are preserved."""
        result = get_windows_path_from_wsl("/opt/netscope/data")
        assert result == "/opt/netscope/data"


class TestTcpdumpManagerSingleton:
    """Tests for TcpdumpManager singleton pattern."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_tcpdump_manager()

    def teardown_method(self):
        """Clean up after each test."""
        reset_tcpdump_manager()

    def test_singleton_returns_same_instance(self):
        """Test that get_tcpdump_manager returns same instance."""
        manager1 = get_tcpdump_manager()
        manager2 = get_tcpdump_manager()
        assert manager1 is manager2

    def test_reset_creates_new_instance(self):
        """Test that reset creates a new instance."""
        manager1 = get_tcpdump_manager()
        reset_tcpdump_manager()
        manager2 = get_tcpdump_manager()
        assert manager1 is not manager2


class TestTcpdumpManagerBuildCommand:
    """Tests for TcpdumpManager._build_tcpdump_command()."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_tcpdump_manager()

    def teardown_method(self):
        """Clean up after each test."""
        reset_tcpdump_manager()

    @patch("app.core.capture.tcpdump_manager.is_windows")
    def test_build_command_linux(self, mock_is_windows):
        """Test command building on Linux."""
        mock_is_windows.return_value = False

        manager = get_tcpdump_manager()
        cmd = manager._build_tcpdump_command(
            interface="eth0",
            output_path="/opt/netscope/data/captures/test.pcap",
            duration=120,
            bpf_filter="not port 22",
        )

        assert isinstance(cmd, list)
        assert cmd[0] == "sudo"
        assert cmd[1] == "tcpdump"
        assert "-i" in cmd
        assert "eth0" in cmd
        assert "-s" in cmd
        assert "100" in cmd
        assert "-w" in cmd
        assert "/opt/netscope/data/captures/test.pcap" in cmd
        assert "-G" in cmd
        assert "120" in cmd
        assert "-W" in cmd
        assert "1" in cmd
        assert "not port 22" in cmd

    @patch("app.core.capture.tcpdump_manager.is_windows")
    @patch("app.core.capture.tcpdump_manager.Path")
    def test_build_command_windows_wsl(self, mock_path, mock_is_windows):
        """Test command building on Windows with WSL wrapper."""
        mock_is_windows.return_value = True
        mock_cwd = MagicMock()
        mock_cwd.__str__ = MagicMock(return_value="C:\\Users\\timit\\Documents\\NETSCOPE")
        mock_path.cwd.return_value = mock_cwd

        manager = get_tcpdump_manager()
        cmd = manager._build_tcpdump_command(
            interface="eth0",
            output_path="C:\\Users\\timit\\Documents\\NETSCOPE\\data\\captures\\test.pcap",
            duration=120,
            bpf_filter="not port 22",
        )

        # On Windows, should be a list command for shell=False (security)
        assert isinstance(cmd, list)
        assert cmd[0] == "wsl"
        assert "-e" in cmd
        assert "bash" in cmd
        assert "-c" in cmd
        # The bash command string is the last element
        bash_cmd = cmd[-1]
        assert "cd" in bash_cmd
        assert "/mnt/c" in bash_cmd
        assert "sudo" in bash_cmd
        assert "tcpdump" in bash_cmd


class TestTcpdumpManagerStartCapture:
    """Tests for TcpdumpManager.start_capture()."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_tcpdump_manager()

    def teardown_method(self):
        """Clean up after each test."""
        reset_tcpdump_manager()

    @patch("app.core.capture.tcpdump_manager.threading.Thread")
    @patch("app.core.capture.tcpdump_manager.subprocess.Popen")
    @patch("app.core.capture.tcpdump_manager.get_thread_manager")
    @patch("app.core.capture.tcpdump_manager.detect_interfaces")
    @patch("app.core.capture.tcpdump_manager.get_recommended_interface")
    @patch("app.core.capture.tcpdump_manager.is_windows")
    def test_start_capture_success(
        self,
        mock_is_windows,
        mock_get_recommended,
        mock_detect,
        mock_thread_manager,
        mock_popen,
        mock_thread_class,
    ):
        """Test successful capture start returns RUNNING session with correct config."""
        mock_is_windows.return_value = False

        # Mock interface detection
        mock_interface = MagicMock()
        mock_interface.name = "eth0"
        mock_get_recommended.return_value = mock_interface
        mock_detect.return_value = [mock_interface]

        # Mock thread manager
        mock_tm = MagicMock()
        mock_tm.acquire_capture_lock.return_value = True
        mock_thread_manager.return_value = mock_tm

        # Mock subprocess - configure communicate to return proper tuple
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = 0
        mock_process.communicate.return_value = (b"", b"")
        mock_process.poll.return_value = None  # Still running
        mock_popen.return_value = mock_process

        # Mock Thread to prevent monitor from running immediately
        mock_thread = MagicMock()
        mock_thread.name = "capture-tcpdump-test"
        mock_thread_class.return_value = mock_thread

        manager = get_tcpdump_manager()
        session = manager.start_capture(duration=60, interface="auto")

        # Verify session was created correctly
        assert session is not None
        assert session.status == CaptureStatus.RUNNING
        assert session.is_running is True
        assert session.config.duration == 60
        assert session.config.interface == "eth0"
        assert session.pid == 12345
        assert session.start_time is not None
        assert session.capture_path is not None

        # Verify lock was acquired
        mock_tm.acquire_capture_lock.assert_called_once()

        # Verify subprocess was started with correct command
        mock_popen.assert_called_once()

        # Verify monitor thread was created and started
        mock_thread_class.assert_called_once()
        mock_thread.start.assert_called_once()

    @patch("app.core.capture.tcpdump_manager.get_thread_manager")
    def test_start_capture_already_running(self, mock_thread_manager):
        """Test that starting capture when one is running raises error."""
        mock_tm = MagicMock()
        mock_tm.acquire_capture_lock.return_value = False
        mock_thread_manager.return_value = mock_tm

        manager = get_tcpdump_manager()

        with pytest.raises(CaptureError) as exc_info:
            manager.start_capture(duration=60)

        assert exc_info.value.code == CAPTURE_ALREADY_RUNNING

    @patch("app.core.capture.tcpdump_manager.get_thread_manager")
    def test_start_capture_invalid_duration(self, mock_thread_manager):
        """Test that invalid duration raises error."""
        mock_tm = MagicMock()
        mock_tm.acquire_capture_lock.return_value = True
        mock_thread_manager.return_value = mock_tm

        manager = get_tcpdump_manager()

        with pytest.raises(CaptureError) as exc_info:
            manager.start_capture(duration=10)  # Too short

        assert exc_info.value.code == CAPTURE_INVALID_DURATION


class TestTcpdumpManagerStopCapture:
    """Tests for TcpdumpManager.stop_capture()."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_tcpdump_manager()

    def teardown_method(self):
        """Clean up after each test."""
        reset_tcpdump_manager()

    def test_stop_capture_when_not_running(self):
        """Test stop_capture raises error when no capture is running."""
        from app.models.capture import CAPTURE_NOT_RUNNING

        manager = get_tcpdump_manager()

        with pytest.raises(CaptureError) as exc_info:
            manager.stop_capture()

        assert exc_info.value.code == CAPTURE_NOT_RUNNING

    @patch("app.core.capture.tcpdump_manager.threading.Thread")
    @patch("app.core.capture.tcpdump_manager.subprocess.Popen")
    @patch("app.core.capture.tcpdump_manager.get_thread_manager")
    @patch("app.core.capture.tcpdump_manager.detect_interfaces")
    @patch("app.core.capture.tcpdump_manager.get_recommended_interface")
    @patch("app.core.capture.tcpdump_manager.is_windows")
    def test_stop_capture_terminates_process(
        self,
        mock_is_windows,
        mock_get_recommended,
        mock_detect,
        mock_thread_manager,
        mock_popen,
        mock_thread_class,
    ):
        """Test that stop_capture terminates the subprocess."""
        mock_is_windows.return_value = False

        # Mock interface detection
        mock_interface = MagicMock()
        mock_interface.name = "eth0"
        mock_get_recommended.return_value = mock_interface
        mock_detect.return_value = [mock_interface]

        # Mock thread manager
        mock_tm = MagicMock()
        mock_tm.acquire_capture_lock.return_value = True
        mock_thread_manager.return_value = mock_tm

        # Mock subprocess
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = -15  # SIGTERM
        mock_process.communicate.return_value = (b"", b"")
        mock_process.poll.return_value = None
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process

        # Mock Thread to prevent monitor from running
        mock_thread = MagicMock()
        mock_thread.name = "capture-tcpdump-test"
        mock_thread_class.return_value = mock_thread

        manager = get_tcpdump_manager()
        manager.start_capture(duration=60, interface="auto")

        # Stop the capture
        session = manager.stop_capture()

        # Verify terminate was called
        mock_process.terminate.assert_called_once()
        assert session.status == CaptureStatus.STOPPED

    @patch("app.core.capture.tcpdump_manager.threading.Thread")
    @patch("app.core.capture.tcpdump_manager.subprocess.Popen")
    @patch("app.core.capture.tcpdump_manager.get_thread_manager")
    @patch("app.core.capture.tcpdump_manager.detect_interfaces")
    @patch("app.core.capture.tcpdump_manager.get_recommended_interface")
    @patch("app.core.capture.tcpdump_manager.is_windows")
    def test_stop_capture_kills_on_timeout(
        self,
        mock_is_windows,
        mock_get_recommended,
        mock_detect,
        mock_thread_manager,
        mock_popen,
        mock_thread_class,
    ):
        """Test that stop_capture kills the process if terminate times out."""
        import subprocess

        mock_is_windows.return_value = False

        # Mock interface detection
        mock_interface = MagicMock()
        mock_interface.name = "eth0"
        mock_get_recommended.return_value = mock_interface
        mock_detect.return_value = [mock_interface]

        # Mock thread manager
        mock_tm = MagicMock()
        mock_tm.acquire_capture_lock.return_value = True
        mock_thread_manager.return_value = mock_tm

        # Mock subprocess that doesn't terminate gracefully
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_process.returncode = -9  # SIGKILL
        mock_process.communicate.return_value = (b"", b"")
        mock_process.poll.return_value = None
        mock_process.wait.side_effect = subprocess.TimeoutExpired("cmd", 5)
        mock_popen.return_value = mock_process

        # Mock Thread to prevent monitor from running
        mock_thread = MagicMock()
        mock_thread.name = "capture-tcpdump-test"
        mock_thread_class.return_value = mock_thread

        manager = get_tcpdump_manager()
        manager.start_capture(duration=60, interface="auto")

        # Stop the capture
        session = manager.stop_capture()

        # Verify kill was called after terminate timeout
        mock_process.terminate.assert_called_once()
        mock_process.kill.assert_called_once()
        assert session.status == CaptureStatus.STOPPED


class TestTcpdumpManagerGetStatus:
    """Tests for TcpdumpManager.get_status()."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_tcpdump_manager()

    def teardown_method(self):
        """Clean up after each test."""
        reset_tcpdump_manager()

    def test_get_status_when_idle(self):
        """Test get_status returns None when no capture."""
        manager = get_tcpdump_manager()
        status = manager.get_status()
        assert status is None

    def test_is_running_when_idle(self):
        """Test is_running returns False when no capture."""
        manager = get_tcpdump_manager()
        assert manager.is_running() is False
