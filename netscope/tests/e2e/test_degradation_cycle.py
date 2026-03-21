"""E2E test for complete degradation cycle.

Story 4.7: Graceful Degradation (FR44)
- Task 7.5: Full cycle degradation -> suspension -> recovery -> resume
- Task 7.6: At least 1 end-to-end test without mocks (Epic 3 retro rule)
"""

from unittest.mock import patch

import pytest

from app.core.inspection.job_models import create_job, JobStatus
from app.core.inspection.job_queue import JobQueue, reset_job_queue
from app.services.resource_monitor import ResourceMonitor, reset_resource_monitor
from app.services.graceful_degradation import (
    DegradationState,
    GracefulDegradationManager,
    reset_degradation_manager,
)


@pytest.fixture(autouse=True)
def cleanup():
    reset_resource_monitor()
    reset_degradation_manager()
    reset_job_queue()
    yield
    reset_resource_monitor()
    reset_degradation_manager()
    reset_job_queue()


class TestFullDegradationCycle:
    """Complete degradation cycle E2E tests.

    Uses real ResourceMonitor, GracefulDegradationManager, JobQueue
    with _add_sample to simulate CPU readings.
    get_job_queue is patched in queue tests to inject a local instance.
    API tests (test_api_*) use real singletons without any patching.
    """

    def test_full_cycle_degradation_suspension_recovery_resume(self):
        """AC1-AC3: Full cycle test — degradation -> suspend -> recover -> resume."""
        monitor = ResourceMonitor(
            degradation_threshold=80,
            recovery_threshold=70,
            critical_threshold=95,
            degradation_samples=3,
            recovery_samples=3,
            critical_samples=6,
            sample_interval=1,
        )
        degradation = GracefulDegradationManager()
        queue = JobQueue()

        monitor.set_callbacks(
            on_degradation_enter=degradation.on_degradation_enter,
            on_degradation_exit=degradation.on_degradation_exit,
            on_critical_overload=degradation.on_critical_overload,
        )

        with patch(
            'app.core.inspection.job_queue.get_job_queue',
            return_value=queue,
        ):
            # === PHASE 1: Normal operation ===
            assert degradation.state == DegradationState.NORMAL
            assert degradation.can_accept_job() is True

            # Add a pending job
            job1 = create_job(target_ip="192.168.1.1", duration=10)
            job1.status = JobStatus.PENDING
            job1.stop_event = None
            queue._jobs[job1.spec.id] = job1

            # === PHASE 2: CPU rises -> Degradation ===
            for _ in range(3):
                monitor._add_sample(85.0)

            assert monitor.get_status()["is_degraded"] is True
            assert degradation.state == DegradationState.DEGRADED
            assert degradation.can_accept_job() is False
            assert job1.status == JobStatus.SUSPENDED

            # Add another suspended job
            job2 = create_job(target_ip="192.168.1.2", duration=10)
            job2.status = JobStatus.SUSPENDED
            queue._jobs[job2.spec.id] = job2

            # === PHASE 3: CPU drops -> Recovery ===
            for _ in range(3):
                monitor._add_sample(60.0)

            assert monitor.get_status()["is_degraded"] is False
            assert degradation.state == DegradationState.NORMAL
            assert degradation.can_accept_job() is True
            # Jobs resume: PENDING or RUNNING (if slot available, _process_queue executes)
            assert job1.status in (JobStatus.PENDING, JobStatus.RUNNING)
            assert job2.status in (JobStatus.PENDING, JobStatus.RUNNING)

    def test_critical_overload_cancels_jobs(self):
        """AC5: Critical overload cancels suspended jobs."""
        monitor = ResourceMonitor(
            degradation_threshold=80,
            recovery_threshold=70,
            critical_threshold=95,
            degradation_samples=3,
            recovery_samples=3,
            critical_samples=6,
            sample_interval=1,
        )
        degradation = GracefulDegradationManager()
        queue = JobQueue()

        monitor.set_callbacks(
            on_degradation_enter=degradation.on_degradation_enter,
            on_degradation_exit=degradation.on_degradation_exit,
            on_critical_overload=degradation.on_critical_overload,
        )

        with patch(
            'app.core.inspection.job_queue.get_job_queue',
            return_value=queue,
        ):
            job1 = create_job(target_ip="192.168.1.1", duration=10)
            job1.status = JobStatus.PENDING
            job1.stop_event = None
            queue._jobs[job1.spec.id] = job1

            job2 = create_job(target_ip="192.168.1.2", duration=10)
            job2.status = JobStatus.PENDING
            job2.stop_event = None
            queue._jobs[job2.spec.id] = job2

            # CPU goes critical (> 95% for 6 samples)
            for _ in range(6):
                monitor._add_sample(97.0)

            assert degradation.state == DegradationState.CRITICAL
            assert job1.status == JobStatus.CANCELLED
            assert job2.status == JobStatus.CANCELLED

    def test_api_system_status_endpoint_real(self, client):
        """E2E: Real API call to /api/system/status without any mocks."""
        resp = client.get('/api/system/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["result"]["degradation"]["state"] == "normal"
        assert isinstance(data["result"]["resources"]["cpu_percent"], (int, float))

    def test_api_system_status_degraded_real(self, client):
        """E2E: Real API call verifying degraded state without any mocks."""
        from app.services.resource_monitor import get_resource_monitor
        from app.services.graceful_degradation import get_degradation_manager

        monitor = get_resource_monitor()
        degradation = get_degradation_manager()

        # Stop real monitoring to avoid interference
        monitor.stop()

        # Reconfigure with small window for testing
        monitor.configure(degradation_samples=2, critical_samples=4)
        monitor.set_callbacks(
            on_degradation_enter=degradation.on_degradation_enter,
            on_degradation_exit=degradation.on_degradation_exit,
            on_critical_overload=degradation.on_critical_overload,
        )

        # Trigger degradation via real objects
        monitor._add_sample(85.0)
        monitor._add_sample(85.0)

        resp = client.get('/api/system/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["result"]["degradation"]["state"] == "degraded"
        assert data["result"]["degradation"]["is_degraded"] is True
        assert "CPU" in data["result"]["resources"]["reason"]
