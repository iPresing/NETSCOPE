"""Integration tests for degradation API endpoints.

Story 4.7: Graceful Degradation (FR44)
- Task 7.4: GET /api/system/status, POST /api/jobs in degraded mode
"""

from unittest.mock import patch

import pytest

from app.services.graceful_degradation import (
    get_degradation_manager,
    reset_degradation_manager,
)
from app.services.resource_monitor import (
    get_resource_monitor,
    reset_resource_monitor,
)
from app.core.inspection.job_queue import reset_job_queue


@pytest.fixture(autouse=True)
def cleanup():
    reset_resource_monitor()
    reset_degradation_manager()
    reset_job_queue()
    yield
    reset_resource_monitor()
    reset_degradation_manager()
    reset_job_queue()


class TestSystemStatusEndpoint:
    def test_get_system_status_ok(self, client):
        resp = client.get('/api/system/status')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "degradation" in data["result"]
        assert "resources" in data["result"]

    def test_system_status_normal_state(self, client):
        resp = client.get('/api/system/status')
        data = resp.get_json()
        assert data["result"]["degradation"]["state"] == "normal"
        assert data["result"]["degradation"]["can_accept_jobs"] is True

    def test_system_status_degraded_state(self, client):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            dm = get_degradation_manager()
            dm.on_degradation_enter()

        resp = client.get('/api/system/status')
        data = resp.get_json()
        assert data["result"]["degradation"]["state"] == "degraded"
        assert data["result"]["degradation"]["can_accept_jobs"] is False

    def test_system_status_includes_cpu(self, client):
        resp = client.get('/api/system/status')
        data = resp.get_json()
        resources = data["result"]["resources"]
        assert "cpu_percent" in resources
        assert "is_degraded" in resources


class TestJobsApiDegradation:
    def test_post_job_503_when_degraded(self, client):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            dm = get_degradation_manager()
            dm.on_degradation_enter()

        resp = client.post('/api/jobs', json={
            "target_ip": "192.168.1.1",
            "duration": 10,
        })
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["error"]["code"] == "JOB_DEGRADATION_ACTIVE"
        assert "mode économie" in data["error"]["message"]

    @patch('app.core.inspection.job_queue.get_thread_manager')
    def test_post_job_ok_when_normal(self, mock_tm, client):
        mock_tm.return_value.acquire_job_slot.return_value = False
        mock_tm.return_value.get_available_job_slots.return_value = 0
        resp = client.post('/api/jobs', json={
            "target_ip": "192.168.1.1",
            "duration": 10,
        })
        assert resp.status_code == 201

    def test_get_jobs_includes_degradation_active(self, client):
        resp = client.get('/api/jobs')
        assert resp.status_code == 200
        data = resp.get_json()
        assert "degradation_active" in data["result"]["queue_stats"]
        assert data["result"]["queue_stats"]["degradation_active"] is False

    def test_get_jobs_degradation_active_true(self, client):
        with patch(
            'app.core.inspection.job_queue.get_job_queue'
        ) as mock_q:
            mock_q.return_value.suspend_pending_jobs.return_value = 0
            dm = get_degradation_manager()
            dm.on_degradation_enter()

        resp = client.get('/api/jobs')
        data = resp.get_json()
        assert data["result"]["queue_stats"]["degradation_active"] is True
