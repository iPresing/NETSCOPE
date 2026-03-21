"""Unit tests for GracefulDegradationManager.

Story 4.7: Graceful Degradation (FR44)
- Task 7.2: State transitions NORMAL <-> DEGRADED <-> CRITICAL
"""

from unittest.mock import patch, MagicMock

import pytest

from app.services.graceful_degradation import (
    DegradationState,
    GracefulDegradationManager,
    get_degradation_manager,
    reset_degradation_manager,
)


@pytest.fixture
def manager():
    """Create a fresh GracefulDegradationManager."""
    return GracefulDegradationManager()


class TestInitialState:
    def test_starts_normal(self, manager):
        assert manager.state == DegradationState.NORMAL

    def test_can_accept_jobs_initially(self, manager):
        assert manager.can_accept_job() is True

    def test_get_status_normal(self, manager):
        status = manager.get_status()
        assert status["state"] == "normal"
        assert status["is_degraded"] is False
        assert status["can_accept_jobs"] is True


class TestStateTransitions:
    def test_normal_to_degraded(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            manager.on_degradation_enter()
        assert manager.state == DegradationState.DEGRADED
        assert manager.can_accept_job() is False

    def test_degraded_to_normal(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            mock_q.return_value.resume_suspended_jobs.return_value = 0
            manager.on_degradation_enter()
            manager.on_degradation_exit()
        assert manager.state == DegradationState.NORMAL
        assert manager.can_accept_job() is True

    def test_degraded_to_critical(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            mock_q.return_value.cancel_suspended_jobs.return_value = 0
            manager.on_degradation_enter()
            manager.on_critical_overload()
        assert manager.state == DegradationState.CRITICAL
        assert manager.can_accept_job() is False

    def test_critical_to_normal_via_exit(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            mock_q.return_value.cancel_suspended_jobs.return_value = 0
            mock_q.return_value.resume_suspended_jobs.return_value = 0
            manager.on_degradation_enter()
            manager.on_critical_overload()
            manager.on_degradation_exit()
        assert manager.state == DegradationState.NORMAL


class TestJobQueueIntegration:
    def test_enter_calls_suspend(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_queue = MagicMock()
            mock_queue.suspend_pending_jobs.return_value = 3
            mock_q.return_value = mock_queue
            manager.on_degradation_enter()
        mock_queue.suspend_pending_jobs.assert_called_once()

    def test_exit_calls_resume(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_queue = MagicMock()
            mock_queue.suspend_pending_jobs.return_value = 0
            mock_queue.resume_suspended_jobs.return_value = 2
            mock_q.return_value = mock_queue
            manager.on_degradation_enter()
            manager.on_degradation_exit()
        mock_queue.resume_suspended_jobs.assert_called_once()

    def test_critical_calls_cancel(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_queue = MagicMock()
            mock_queue.suspend_pending_jobs.return_value = 0
            mock_queue.cancel_suspended_jobs.return_value = 2
            mock_q.return_value = mock_queue
            manager.on_degradation_enter()
            manager.on_critical_overload()
        mock_queue.cancel_suspended_jobs.assert_called_once()


class TestGetStatus:
    def test_status_degraded(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            manager.on_degradation_enter()
        status = manager.get_status()
        assert status["state"] == "degraded"
        assert status["is_degraded"] is True
        assert status["can_accept_jobs"] is False

    def test_status_critical(self, manager):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            mock_q.return_value.cancel_suspended_jobs.return_value = 0
            manager.on_degradation_enter()
            manager.on_critical_overload()
        status = manager.get_status()
        assert status["state"] == "critical"


class TestSingleton:
    def test_same_instance(self):
        reset_degradation_manager()
        m1 = get_degradation_manager()
        m2 = get_degradation_manager()
        assert m1 is m2
        reset_degradation_manager()

    def test_reset_clears(self):
        reset_degradation_manager()
        m1 = get_degradation_manager()
        reset_degradation_manager()
        m2 = get_degradation_manager()
        assert m1 is not m2
        reset_degradation_manager()
