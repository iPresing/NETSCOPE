"""Unit tests for ResourceMonitor service.

Story 4.7: Graceful Degradation (FR44)
- Task 7.1: Sliding windows, callbacks, thresholds
"""

import threading
from unittest.mock import patch, MagicMock

import pytest

from app.services.resource_monitor import (
    ResourceMonitor,
    get_resource_monitor,
    reset_resource_monitor,
)


@pytest.fixture
def monitor():
    """Create a ResourceMonitor with small windows for testing."""
    return ResourceMonitor(
        degradation_threshold=80,
        recovery_threshold=70,
        critical_threshold=95,
        degradation_samples=3,
        recovery_samples=3,
        critical_samples=6,
        sample_interval=1,
    )


class TestResourceMonitorInit:
    """Test ResourceMonitor initialization."""

    def test_initial_state_not_degraded(self, monitor):
        status = monitor.get_status()
        assert status["is_degraded"] is False
        assert status["is_critical"] is False
        assert status["cpu_percent"] == 0.0
        assert status["degraded_since"] is None
        assert status["reason"] is None

    def test_default_thresholds(self):
        m = ResourceMonitor()
        assert m._degradation_threshold == 80
        assert m._recovery_threshold == 70
        assert m._critical_threshold == 95

    def test_custom_thresholds(self, monitor):
        assert monitor._degradation_samples == 3
        assert monitor._recovery_samples == 3
        assert monitor._critical_samples == 6

    def test_deque_maxlen(self, monitor):
        assert monitor._cpu_samples.maxlen == 6


class TestSlidingWindowDegradation:
    """Test degradation detection via sliding window (AC1)."""

    def test_no_degradation_below_threshold(self, monitor):
        for _ in range(5):
            monitor._add_sample(75.0)
        assert monitor.get_status()["is_degraded"] is False

    def test_degradation_triggers_after_n_samples(self, monitor):
        # 3 consecutive samples > 80%
        monitor._add_sample(85.0)
        monitor._add_sample(85.0)
        assert monitor.get_status()["is_degraded"] is False
        monitor._add_sample(85.0)
        assert monitor.get_status()["is_degraded"] is True

    def test_degradation_not_triggered_with_gap(self, monitor):
        monitor._add_sample(85.0)
        monitor._add_sample(85.0)
        monitor._add_sample(60.0)  # gap breaks consecutive
        monitor._add_sample(85.0)
        assert monitor.get_status()["is_degraded"] is False

    def test_degradation_sets_since_timestamp(self, monitor):
        for _ in range(3):
            monitor._add_sample(85.0)
        status = monitor.get_status()
        assert status["degraded_since"] is not None

    def test_degradation_reason_text(self, monitor):
        for _ in range(3):
            monitor._add_sample(85.0)
        status = monitor.get_status()
        assert "CPU" in status["reason"]
        assert "85" in status["reason"]


class TestSlidingWindowRecovery:
    """Test recovery detection via sliding window (AC3)."""

    def test_recovery_after_sustained_low_cpu(self, monitor):
        # Enter degradation
        for _ in range(3):
            monitor._add_sample(85.0)
        assert monitor.get_status()["is_degraded"] is True

        # Recovery: 3 consecutive samples < 70%
        for _ in range(3):
            monitor._add_sample(60.0)
        assert monitor.get_status()["is_degraded"] is False
        assert monitor.get_status()["degraded_since"] is None

    def test_no_recovery_if_still_high(self, monitor):
        for _ in range(3):
            monitor._add_sample(85.0)
        assert monitor.get_status()["is_degraded"] is True

        # Still above recovery threshold
        for _ in range(3):
            monitor._add_sample(72.0)
        assert monitor.get_status()["is_degraded"] is True


class TestSlidingWindowCritical:
    """Test critical overload detection (AC5)."""

    def test_critical_after_sustained_very_high_cpu(self, monitor):
        # Need 6 consecutive > 95% (also triggers degradation at 3)
        for _ in range(6):
            monitor._add_sample(97.0)
        status = monitor.get_status()
        assert status["is_degraded"] is True
        assert status["is_critical"] is True
        assert "critique" in status["reason"]

    def test_critical_not_triggered_below_threshold(self, monitor):
        for _ in range(6):
            monitor._add_sample(90.0)
        status = monitor.get_status()
        assert status["is_degraded"] is True  # > 80%
        assert status["is_critical"] is False  # < 95%

    def test_recovery_clears_critical(self, monitor):
        for _ in range(6):
            monitor._add_sample(97.0)
        assert monitor.get_status()["is_critical"] is True

        for _ in range(3):
            monitor._add_sample(60.0)
        status = monitor.get_status()
        assert status["is_degraded"] is False
        assert status["is_critical"] is False


class TestCallbacks:
    """Test callback invocation (Task 1.6)."""

    def test_on_degradation_enter_callback(self, monitor):
        cb = MagicMock()
        monitor.set_callbacks(on_degradation_enter=cb)
        for _ in range(3):
            monitor._add_sample(85.0)
        cb.assert_called_once()

    def test_on_degradation_exit_callback(self, monitor):
        cb = MagicMock()
        monitor.set_callbacks(on_degradation_exit=cb)
        for _ in range(3):
            monitor._add_sample(85.0)
        for _ in range(3):
            monitor._add_sample(60.0)
        cb.assert_called_once()

    def test_on_critical_overload_callback(self, monitor):
        cb = MagicMock()
        monitor.set_callbacks(on_critical_overload=cb)
        for _ in range(6):
            monitor._add_sample(97.0)
        cb.assert_called_once()

    def test_callback_error_does_not_crash(self, monitor):
        cb = MagicMock(side_effect=RuntimeError("boom"))
        monitor.set_callbacks(on_degradation_enter=cb)
        for _ in range(3):
            monitor._add_sample(85.0)
        # Should not raise, just log error
        assert monitor.get_status()["is_degraded"] is True

    def test_enter_callback_fires_only_once(self, monitor):
        cb = MagicMock()
        monitor.set_callbacks(on_degradation_enter=cb)
        for _ in range(5):
            monitor._add_sample(85.0)
        cb.assert_called_once()

    def test_all_callbacks_wired(self, monitor):
        enter_cb = MagicMock()
        exit_cb = MagicMock()
        critical_cb = MagicMock()
        monitor.set_callbacks(
            on_degradation_enter=enter_cb,
            on_degradation_exit=exit_cb,
            on_critical_overload=critical_cb,
        )
        # Enter degradation
        for _ in range(3):
            monitor._add_sample(85.0)
        enter_cb.assert_called_once()

        # Continue to critical (need total 6 > 95%)
        # Reset and do 6 consecutive critical samples
        monitor2 = ResourceMonitor(
            degradation_samples=3,
            recovery_samples=3,
            critical_samples=6,
        )
        critical_cb2 = MagicMock()
        monitor2.set_callbacks(on_critical_overload=critical_cb2)
        for _ in range(6):
            monitor2._add_sample(97.0)
        critical_cb2.assert_called_once()


class TestGetStatus:
    """Test get_status() method (Task 1.7)."""

    def test_get_status_normal(self, monitor):
        status = monitor.get_status()
        assert isinstance(status, dict)
        assert "is_degraded" in status
        assert "is_critical" in status
        assert "cpu_percent" in status
        assert "degraded_since" in status
        assert "reason" in status

    def test_get_status_degraded(self, monitor):
        for _ in range(3):
            monitor._add_sample(85.0)
        status = monitor.get_status()
        assert status["is_degraded"] is True
        assert status["cpu_percent"] == 85.0

    def test_get_status_thread_safe(self, monitor):
        """Verify get_status works under concurrent access."""
        results = []

        def worker():
            for _ in range(10):
                monitor._add_sample(50.0)
                results.append(monitor.get_status())

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 30
        for s in results:
            assert isinstance(s, dict)


class TestSingleton:
    """Test singleton pattern (Task 1.8)."""

    def test_get_resource_monitor_returns_same_instance(self):
        reset_resource_monitor()
        m1 = get_resource_monitor()
        m2 = get_resource_monitor()
        assert m1 is m2
        reset_resource_monitor()

    def test_reset_clears_instance(self):
        reset_resource_monitor()
        m1 = get_resource_monitor()
        reset_resource_monitor()
        m2 = get_resource_monitor()
        assert m1 is not m2
        reset_resource_monitor()


class TestMonitoringThread:
    """Test daemon thread behavior (Task 1.2)."""

    def test_start_creates_daemon_thread(self, monitor):
        with patch('app.services.resource_monitor.psutil') as mock_psutil:
            mock_psutil.cpu_percent.return_value = 50.0
            monitor.start()
            assert monitor._running is True
            assert monitor._monitor_thread is not None
            assert monitor._monitor_thread.daemon is True
            assert monitor._monitor_thread.name == "resource-monitor"
            monitor.stop()

    def test_stop_sets_running_false(self, monitor):
        with patch('app.services.resource_monitor.psutil') as mock_psutil:
            mock_psutil.cpu_percent.return_value = 50.0
            monitor.start()
            monitor.stop()
            assert monitor._running is False

    def test_double_start_is_safe(self, monitor):
        with patch('app.services.resource_monitor.psutil') as mock_psutil:
            mock_psutil.cpu_percent.return_value = 50.0
            monitor.start()
            monitor.start()  # Should not raise
            monitor.stop()

    def test_stop_without_start_is_safe(self, monitor):
        monitor.stop()  # Should not raise
