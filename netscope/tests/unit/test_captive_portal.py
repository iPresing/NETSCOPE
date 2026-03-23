"""Unit tests for captive portal manager and detection logic."""

import pytest
from unittest.mock import patch, MagicMock

from app.blueprints.captive.captive_manager import (
    CaptiveManager,
    get_captive_manager,
    reset_captive_manager,
)


class TestCaptiveManagerInit:
    """Tests for CaptiveManager initialization."""

    def test_init_captive_active_by_default(self):
        """CaptiveManager starts with captive mode active."""
        manager = CaptiveManager()
        assert manager.is_captive_active() is True

    def test_init_no_released_ips(self):
        """CaptiveManager starts with empty released IPs set."""
        manager = CaptiveManager()
        status = manager.get_status()
        assert status['released_clients'] == 0


class TestCaptiveManagerRelease:
    """Tests for client release logic."""

    def test_release_client_adds_ip(self):
        """release_client adds client IP to released set."""
        manager = CaptiveManager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('192.168.88.100')
        assert manager.is_released('192.168.88.100') is True

    def test_release_client_disables_captive(self):
        """First release disables captive mode globally."""
        manager = CaptiveManager()
        with patch.object(manager, '_disable_captive') as mock_disable:
            manager.release_client('192.168.88.100')
        mock_disable.assert_called_once()
        assert manager.is_captive_active() is False

    def test_release_client_idempotent(self):
        """Releasing same client twice does not cause errors."""
        manager = CaptiveManager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('192.168.88.100')
            manager.release_client('192.168.88.100')
        assert manager.is_released('192.168.88.100') is True

    def test_release_multiple_clients(self):
        """Multiple clients can be released."""
        manager = CaptiveManager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('192.168.88.100')
            manager.release_client('192.168.88.101')
        status = manager.get_status()
        assert status['released_clients'] == 2

    def test_release_returns_true(self):
        """release_client returns True on success."""
        manager = CaptiveManager()
        with patch.object(manager, '_disable_captive'):
            result = manager.release_client('192.168.88.100')
        assert result is True

    def test_second_release_does_not_call_disable_again(self):
        """Second release does not call _disable_captive again."""
        manager = CaptiveManager()
        with patch.object(manager, '_disable_captive') as mock_disable:
            manager.release_client('192.168.88.100')
            manager.release_client('192.168.88.101')
        mock_disable.assert_called_once()


class TestCaptiveManagerIsReleased:
    """Tests for is_released check."""

    def test_unreleased_ip_returns_false(self):
        """Unknown IP is not released."""
        manager = CaptiveManager()
        assert manager.is_released('192.168.88.200') is False

    def test_released_ip_returns_true(self):
        """Released IP returns True."""
        manager = CaptiveManager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('192.168.88.50')
        assert manager.is_released('192.168.88.50') is True

    def test_localhost_not_released(self):
        """Localhost is not in released set by default."""
        manager = CaptiveManager()
        assert manager.is_released('127.0.0.1') is False


class TestCaptiveManagerGetStatus:
    """Tests for get_status reporting."""

    def test_status_active_initial(self):
        """Initial status shows captive active, zero clients."""
        manager = CaptiveManager()
        status = manager.get_status()
        assert status['captive_active'] is True
        assert status['released_clients'] == 0

    def test_status_after_release(self):
        """Status reflects released client after release."""
        manager = CaptiveManager()
        with patch.object(manager, '_disable_captive'):
            manager.release_client('10.0.0.1')
        status = manager.get_status()
        assert status['captive_active'] is False
        assert status['released_clients'] == 1
        assert 'released_ips' not in status


class TestCaptiveManagerDisable:
    """Tests for _disable_captive system call."""

    def test_disable_calls_toggle_script(self):
        """_disable_captive calls the toggle script with 'disable'."""
        manager = CaptiveManager()
        with patch('app.blueprints.captive.captive_manager.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            manager._disable_captive()
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[1] == 'disable'

    def test_disable_handles_missing_script(self):
        """_disable_captive handles FileNotFoundError gracefully (no crash)."""
        manager = CaptiveManager()
        with patch('app.blueprints.captive.captive_manager.subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError()
            manager._disable_captive()  # Should not raise

    def test_disable_handles_timeout(self):
        """_disable_captive handles subprocess timeout (no crash)."""
        import subprocess
        manager = CaptiveManager()
        with patch('app.blueprints.captive.captive_manager.subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd='test', timeout=10)
            manager._disable_captive()  # Should not raise

    def test_disable_handles_nonzero_return(self):
        """_disable_captive logs warning on non-zero return (no crash)."""
        manager = CaptiveManager()
        with patch('app.blueprints.captive.captive_manager.subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr='error')
            manager._disable_captive()  # Should not raise


class TestCaptiveManagerSingleton:
    """Tests for singleton pattern."""

    def test_get_captive_manager_returns_instance(self):
        """get_captive_manager returns a CaptiveManager instance."""
        reset_captive_manager()
        manager = get_captive_manager()
        assert isinstance(manager, CaptiveManager)

    def test_get_captive_manager_same_instance(self):
        """get_captive_manager returns same instance on repeated calls."""
        reset_captive_manager()
        m1 = get_captive_manager()
        m2 = get_captive_manager()
        assert m1 is m2

    def test_reset_clears_singleton(self):
        """reset_captive_manager clears the singleton."""
        reset_captive_manager()
        m1 = get_captive_manager()
        reset_captive_manager()
        m2 = get_captive_manager()
        assert m1 is not m2
