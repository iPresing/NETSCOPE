"""Unit tests for JobQueue degradation integration.

Story 4.7: Graceful Degradation (FR44)
- Task 7.3: submit in degraded mode, suspend/resume/cancel
"""

import threading
from unittest.mock import patch, MagicMock

import pytest

from app.core.inspection.job_models import Job, JobSpec, JobStatus, create_job
from app.core.inspection.job_queue import JobQueue, reset_job_queue


@pytest.fixture
def queue():
    """Create a fresh JobQueue."""
    reset_job_queue()
    q = JobQueue()
    return q


def _make_job(status=JobStatus.PENDING):
    """Helper to create a test job."""
    job = create_job(target_ip="192.168.1.1", duration=10)
    job.status = status
    return job


class TestSuspendedStatus:
    def test_suspended_in_enum(self):
        assert JobStatus.SUSPENDED.value == "suspended"

    def test_job_serializes_suspended(self):
        job = _make_job()
        job.status = JobStatus.SUSPENDED
        d = job.to_dict()
        assert d["status"] == "suspended"


class TestSubmitDegraded:
    @patch('app.core.inspection.job_queue.get_thread_manager')
    def test_submit_suspended_when_degraded(self, mock_tm, queue):
        with patch(
            'app.services.graceful_degradation.get_degradation_manager'
        ) as mock_dm:
            mock_dm.return_value.can_accept_job.return_value = False
            job = _make_job()
            result = queue.submit(job)
        assert result.status == JobStatus.SUSPENDED

    @patch('app.core.inspection.job_queue.get_thread_manager')
    def test_submit_pending_when_normal(self, mock_tm, queue):
        mock_tm.return_value.acquire_job_slot.return_value = False
        with patch(
            'app.services.graceful_degradation.get_degradation_manager'
        ) as mock_dm:
            mock_dm.return_value.can_accept_job.return_value = True
            job = _make_job()
            result = queue.submit(job)
        # Job stays PENDING (no slot available)
        assert result.status == JobStatus.PENDING


class TestSuspendPendingJobs:
    def test_suspends_pending(self, queue):
        job1 = _make_job()
        job2 = _make_job()
        queue._jobs[job1.spec.id] = job1
        queue._jobs[job2.spec.id] = job2
        count = queue.suspend_pending_jobs()
        assert count == 2
        assert job1.status == JobStatus.SUSPENDED
        assert job2.status == JobStatus.SUSPENDED

    def test_does_not_suspend_running(self, queue):
        job = _make_job(status=JobStatus.RUNNING)
        queue._jobs[job.spec.id] = job
        count = queue.suspend_pending_jobs()
        assert count == 0
        assert job.status == JobStatus.RUNNING

    def test_returns_zero_when_empty(self, queue):
        count = queue.suspend_pending_jobs()
        assert count == 0


class TestResumeSuspendedJobs:
    @patch('app.core.inspection.job_queue.get_thread_manager')
    def test_resumes_suspended_to_pending(self, mock_tm, queue):
        mock_tm.return_value.acquire_job_slot.return_value = False
        job1 = _make_job(status=JobStatus.SUSPENDED)
        job2 = _make_job(status=JobStatus.SUSPENDED)
        queue._jobs[job1.spec.id] = job1
        queue._jobs[job2.spec.id] = job2
        count = queue.resume_suspended_jobs()
        assert count == 2
        assert job1.status == JobStatus.PENDING
        assert job2.status == JobStatus.PENDING

    def test_does_not_resume_cancelled(self, queue):
        job = _make_job(status=JobStatus.CANCELLED)
        queue._jobs[job.spec.id] = job
        count = queue.resume_suspended_jobs()
        assert count == 0
        assert job.status == JobStatus.CANCELLED


class TestCancelSuspendedJobs:
    def test_cancels_all_suspended(self, queue):
        job1 = _make_job(status=JobStatus.SUSPENDED)
        job2 = _make_job(status=JobStatus.SUSPENDED)
        job3 = _make_job(status=JobStatus.RUNNING)
        queue._jobs[job1.spec.id] = job1
        queue._jobs[job2.spec.id] = job2
        queue._jobs[job3.spec.id] = job3
        count = queue.cancel_suspended_jobs()
        assert count == 2
        assert job1.status == JobStatus.CANCELLED
        assert job2.status == JobStatus.CANCELLED
        assert job3.status == JobStatus.RUNNING

    def test_returns_zero_when_none_suspended(self, queue):
        job = _make_job(status=JobStatus.PENDING)
        queue._jobs[job.spec.id] = job
        count = queue.cancel_suspended_jobs()
        assert count == 0


class TestCancelJobSuspended:
    def test_cancel_job_works_for_suspended(self, queue):
        job = _make_job(status=JobStatus.SUSPENDED)
        queue._jobs[job.spec.id] = job
        result = queue.cancel_job(job.spec.id)
        assert result is True
        assert job.status == JobStatus.CANCELLED


class TestQueueStatsSuspended:
    def test_stats_include_suspended_count(self, queue):
        job1 = _make_job(status=JobStatus.SUSPENDED)
        job2 = _make_job(status=JobStatus.PENDING)
        queue._jobs[job1.spec.id] = job1
        queue._jobs[job2.spec.id] = job2
        with patch('app.core.inspection.job_queue.get_thread_manager') as mock_tm:
            mock_tm.return_value.max_concurrent_jobs = 1
            mock_tm.return_value.get_available_job_slots.return_value = 1
            stats = queue.get_queue_stats()
        assert stats["suspended_count"] == 1
        assert stats["pending_count"] == 1


class TestProcessQueueIgnoresSuspended:
    @patch('app.core.inspection.job_queue.get_thread_manager')
    def test_process_queue_skips_suspended(self, mock_tm, queue):
        mock_tm.return_value.acquire_job_slot.return_value = False
        susp = _make_job(status=JobStatus.SUSPENDED)
        queue._jobs[susp.spec.id] = susp
        queue._process_queue()
        # Suspended job should not become RUNNING
        assert susp.status == JobStatus.SUSPENDED
