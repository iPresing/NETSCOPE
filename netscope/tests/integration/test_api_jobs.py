"""Tests integration pour l'API Jobs.

Story 4.1 - Task 8 (8.1-8.8)

Lessons Learned Epic 3:
- Au moins 1 test end-to-end sans mock par story (regle #11)
"""

from unittest.mock import patch

import pytest

from app.core.inspection.job_models import JobStatus
from app.core.inspection.job_queue import reset_job_queue


@pytest.fixture(autouse=True)
def reset_queue():
    """Reset la job queue entre chaque test."""
    reset_job_queue()
    yield
    reset_job_queue()


@pytest.fixture
def mock_no_slots():
    """Mock le ThreadManager pour eviter les vrais threads."""
    with patch("app.core.inspection.job_queue.get_thread_manager") as mock_get_tm:
        from unittest.mock import MagicMock, PropertyMock
        tm = MagicMock()
        tm.acquire_job_slot.return_value = False
        tm.get_available_job_slots.return_value = 1
        tm.max_concurrent_jobs = 2
        mock_get_tm.return_value = tm
        yield tm


class TestPostApiJobs:
    """Tests pour POST /api/jobs."""

    def test_create_job_valid_params(self, client, mock_no_slots):
        """8.2: POST /api/jobs avec parametres valides retourne 201."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.100",
            "target_port": 443,
            "protocol": "TCP",
            "duration": 30,
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["spec"]["target_ip"] == "192.168.1.100"
        assert data["result"]["spec"]["target_port"] == 443
        assert data["result"]["status"] in ("pending", "running")

    def test_create_job_ip_only(self, client, mock_no_slots):
        """POST /api/jobs avec IP seule (parametres optionnels omis)."""
        response = client.post('/api/jobs', json={
            "target_ip": "10.0.0.1",
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["spec"]["target_ip"] == "10.0.0.1"
        assert data["result"]["spec"]["duration"] == 30  # default

    def test_create_job_invalid_ip(self, client):
        """8.3: POST /api/jobs avec IP invalide retourne 400."""
        response = client.post('/api/jobs', json={
            "target_ip": "abc",
        })

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_INVALID_PARAMS"

    def test_create_job_missing_target_ip(self, client):
        """8.4: POST /api/jobs sans target_ip retourne 400."""
        response = client.post('/api/jobs', json={
            "target_port": 443,
        })

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_INVALID_PARAMS"

    def test_create_job_no_body(self, client):
        """POST /api/jobs sans body retourne 400."""
        response = client.post('/api/jobs',
                               content_type='application/json')

        assert response.status_code == 400

    def test_create_job_queue_full(self, client, mock_no_slots):
        """POST /api/jobs retourne 503 quand la queue est saturee."""
        from app.core.inspection.job_queue import get_job_queue, MAX_QUEUED_JOBS
        from app.core.inspection.job_models import create_job

        queue = get_job_queue()
        for i in range(MAX_QUEUED_JOBS):
            job = create_job(target_ip=f"10.0.0.{i + 1}")
            queue.submit(job)

        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.200",
        })

        assert response.status_code == 503
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_QUEUE_FULL"


class TestPostApiJobsDirection:
    """Tests pour POST /api/jobs avec direction du port (Story 4.2 - Task 8.1)."""

    def test_create_job_with_direction_dst(self, client, mock_no_slots):
        """POST /api/jobs avec target_port_direction='dst' retourne 201."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.100",
            "target_port": 4444,
            "target_port_direction": "dst",
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["spec"]["target_port_direction"] == "dst"

    def test_create_job_with_direction_src(self, client, mock_no_slots):
        """POST /api/jobs avec target_port_direction='src' retourne 201."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.100",
            "target_port": 4444,
            "target_port_direction": "src",
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data["result"]["spec"]["target_port_direction"] == "src"

    def test_create_job_with_direction_invalid(self, client, mock_no_slots):
        """POST /api/jobs avec direction invalide retourne 400."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.100",
            "target_port": 4444,
            "target_port_direction": "invalid",
        })

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_INVALID_PARAMS"

    def test_create_job_with_direction_without_port(self, client, mock_no_slots):
        """POST /api/jobs avec direction sans port retourne 400."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.100",
            "target_port_direction": "dst",
        })

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_INVALID_PARAMS"

    def test_create_job_port_without_direction_backward_compat(self, client, mock_no_slots):
        """POST /api/jobs sans direction mais avec port retourne 201 (backward compat)."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.100",
            "target_port": 443,
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data["result"]["spec"]["target_port_direction"] is None

    def test_create_and_get_job_with_direction_e2e(self, client):
        """End-to-end sans mock: creer job avec direction, verifier GET retourne la direction (regle #11)."""
        create_resp = client.post('/api/jobs', json={
            "target_ip": "192.168.1.200",
            "target_port": 8080,
            "target_port_direction": "dst",
            "duration": 5,
        })
        assert create_resp.status_code == 201
        job_id = create_resp.get_json()["result"]["id"]

        get_resp = client.get(f'/api/jobs/{job_id}')
        assert get_resp.status_code == 200
        job_data = get_resp.get_json()["result"]
        assert job_data["spec"]["target_port_direction"] == "dst"
        assert job_data["spec"]["target_port"] == 8080


class TestGetApiJobs:
    """Tests pour GET /api/jobs."""

    def test_list_jobs_empty(self, client):
        """8.5: GET /api/jobs retourne liste vide initialement."""
        response = client.get('/api/jobs')

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["jobs"] == []
        assert data["result"]["count"] == 0

    def test_get_job_not_found(self, client):
        """8.7: GET /api/jobs/<bad_id> retourne 404."""
        response = client.get('/api/jobs/job_nonexistent')

        assert response.status_code == 404
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_NOT_FOUND"


class TestGetApiJobById:
    """Tests pour GET /api/jobs/<job_id>."""

    def test_get_job_after_create(self, client, mock_no_slots):
        """8.6: GET /api/jobs/<id> retourne details du job."""
        # Create a job first
        create_resp = client.post('/api/jobs', json={
            "target_ip": "192.168.1.50",
        })
        assert create_resp.status_code == 201
        job_id = create_resp.get_json()["result"]["id"]

        # Get job details
        response = client.get(f'/api/jobs/{job_id}')

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["id"] == job_id
        assert data["result"]["spec"]["target_ip"] == "192.168.1.50"


class TestQueueStatsApi:
    """Tests pour les stats de queue dans l'API (Story 4.3 - Task 7)."""

    def test_post_api_jobs_returns_queue_position_when_pending(self, client, mock_no_slots):
        """POST retourne queue_position si le job est PENDING."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.100",
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["status"] == "pending"
        assert "queue_position" in data["result"]
        assert data["result"]["queue_position"] == 1

    def test_post_api_jobs_returns_message_when_queued(self, client, mock_no_slots):
        """Message contextuel si mis en attente."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.100",
        })

        assert response.status_code == 201
        data = response.get_json()
        assert "message" in data
        assert "Job en attente" in data["message"]

    def test_get_api_jobs_includes_queue_stats(self, client, mock_no_slots):
        """GET /api/jobs retourne queue_stats."""
        # Create a job first
        client.post('/api/jobs', json={"target_ip": "192.168.1.1"})

        response = client.get('/api/jobs')
        assert response.status_code == 200
        data = response.get_json()
        assert "queue_stats" in data["result"]
        stats = data["result"]["queue_stats"]
        assert "pending_count" in stats
        assert "running_count" in stats
        assert "max_queue_size" in stats
        assert "max_concurrent_jobs" in stats
        assert "available_slots" in stats

    def test_get_api_jobs_includes_queue_position_for_pending(self, client, mock_no_slots):
        """Chaque job PENDING a queue_position dans GET /api/jobs."""
        client.post('/api/jobs', json={"target_ip": "192.168.1.1"})
        client.post('/api/jobs', json={"target_ip": "192.168.1.2"})

        response = client.get('/api/jobs')
        data = response.get_json()

        pending_jobs = [j for j in data["result"]["jobs"] if j["status"] == "pending"]
        assert len(pending_jobs) >= 2
        for job in pending_jobs:
            assert "queue_position" in job

    def test_get_api_job_detail_includes_queue_info(self, client, mock_no_slots):
        """GET /api/jobs/<id> retourne position et jobs_ahead pour PENDING."""
        create_resp = client.post('/api/jobs', json={"target_ip": "192.168.1.1"})
        job_id = create_resp.get_json()["result"]["id"]

        response = client.get(f'/api/jobs/{job_id}')
        assert response.status_code == 200
        data = response.get_json()
        assert "queue_position" in data["result"]
        assert "jobs_ahead" in data["result"]

    def test_queue_full_returns_503_with_stats(self, client, mock_no_slots):
        """503 quand queue saturee, avec statistiques."""
        from app.core.inspection.job_queue import get_job_queue, MAX_QUEUED_JOBS
        from app.core.inspection.job_models import create_job

        queue = get_job_queue()
        for i in range(MAX_QUEUED_JOBS):
            job = create_job(target_ip=f"10.0.0.{i + 1}")
            queue.submit(job)

        response = client.post('/api/jobs', json={"target_ip": "192.168.1.200"})

        assert response.status_code == 503
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_QUEUE_FULL"
        assert "max_queue_size" in data["error"]["details"]
        assert "pending_count" in data["error"]["details"]
        assert "running_count" in data["error"]["details"]


class TestEndToEnd:
    """Tests end-to-end sans mock (regle #11)."""

    def test_create_and_list_job_e2e(self, client):
        """8.8: POST /api/jobs cree le job et GET /api/jobs le contient (end-to-end sans mock)."""
        # Create a job - le ThreadManager reel tentera d'acquerir un slot
        create_resp = client.post('/api/jobs', json={
            "target_ip": "192.168.1.200",
            "duration": 5,
        })
        assert create_resp.status_code == 201
        created = create_resp.get_json()
        job_id = created["result"]["id"]

        # List jobs - should contain the created job
        list_resp = client.get('/api/jobs')
        assert list_resp.status_code == 200
        listed = list_resp.get_json()
        job_ids = [j["id"] for j in listed["result"]["jobs"]]
        assert job_id in job_ids

    def test_end_to_end_queue_flow_without_mock(self, client):
        """Soumettre 2+ jobs, verifier positions et auto-demarrage (regle #11)."""
        # Submit first job - may start immediately
        resp1 = client.post('/api/jobs', json={
            "target_ip": "192.168.1.1",
            "duration": 5,
        })
        assert resp1.status_code == 201
        data1 = resp1.get_json()
        assert "message" in data1

        # Submit second job
        resp2 = client.post('/api/jobs', json={
            "target_ip": "192.168.1.2",
            "duration": 5,
        })
        assert resp2.status_code == 201
        data2 = resp2.get_json()
        assert "message" in data2
        job2_id = data2["result"]["id"]

        # If second job is pending, verify queue position
        if data2["result"]["status"] == "pending":
            assert "queue_position" in data2["result"]
            assert data2["result"]["queue_position"] >= 1

        # Verify both jobs visible in list with queue_stats
        list_resp = client.get('/api/jobs')
        assert list_resp.status_code == 200
        data = list_resp.get_json()
        assert data["result"]["count"] >= 2
        assert "queue_stats" in data["result"]

        stats = data["result"]["queue_stats"]
        assert stats["max_queue_size"] == 10
        assert "pending_count" in stats
        assert "running_count" in stats

        # Verify PENDING jobs in list have queue_position
        for job in data["result"]["jobs"]:
            if job["status"] == "pending":
                assert "queue_position" in job
                assert job["queue_position"] >= 1

        # Verify individual job detail
        detail_resp = client.get(f'/api/jobs/{job2_id}')
        assert detail_resp.status_code == 200
        detail = detail_resp.get_json()
        assert detail["result"]["id"] == job2_id


class TestJobCancelApi:
    """Tests pour POST /api/jobs/<job_id>/cancel (Story 4.6 - Task 7.1)."""

    def test_post_cancel_pending_job_returns_200(self, client, mock_no_slots):
        """POST /api/jobs/{id}/cancel sur PENDING → 200."""
        create_resp = client.post('/api/jobs', json={"target_ip": "192.168.1.1"})
        job_id = create_resp.get_json()["result"]["id"]

        response = client.post(f'/api/jobs/{job_id}/cancel')

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["status"] == "cancelled"
        assert data["result"]["previous_status"] == "pending"

    def test_post_cancel_running_job_returns_200(self, client, mock_no_slots):
        """POST /api/jobs/{id}/cancel sur RUNNING → 200."""
        create_resp = client.post('/api/jobs', json={"target_ip": "192.168.1.1"})
        job_id = create_resp.get_json()["result"]["id"]

        # Mettre manuellement en RUNNING
        from app.core.inspection.job_queue import get_job_queue
        queue = get_job_queue()
        job = queue.get_job(job_id)
        with queue._lock:
            job.status = JobStatus.RUNNING

        response = client.post(f'/api/jobs/{job_id}/cancel')

        assert response.status_code == 200
        data = response.get_json()
        assert data["success"] is True
        assert data["result"]["previous_status"] == "running"

    def test_post_cancel_nonexistent_returns_404(self, client):
        """POST /api/jobs/nonexistent/cancel → 404 JOB_NOT_FOUND."""
        response = client.post('/api/jobs/job_nonexistent/cancel')

        assert response.status_code == 404
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_NOT_FOUND"

    def test_post_cancel_completed_returns_409(self, client, mock_no_slots):
        """POST /api/jobs/{id}/cancel sur COMPLETED → 409."""
        create_resp = client.post('/api/jobs', json={"target_ip": "192.168.1.1"})
        job_id = create_resp.get_json()["result"]["id"]

        from app.core.inspection.job_queue import get_job_queue
        queue = get_job_queue()
        job = queue.get_job(job_id)
        with queue._lock:
            job.status = JobStatus.COMPLETED

        response = client.post(f'/api/jobs/{job_id}/cancel')

        assert response.status_code == 409
        data = response.get_json()
        assert data["success"] is False
        assert data["error"]["code"] == "JOB_ALREADY_COMPLETED"

    def test_cancel_response_includes_message(self, client, mock_no_slots):
        """Reponse cancel contient 'message'."""
        create_resp = client.post('/api/jobs', json={"target_ip": "192.168.1.1"})
        job_id = create_resp.get_json()["result"]["id"]

        response = client.post(f'/api/jobs/{job_id}/cancel')

        assert response.status_code == 200
        data = response.get_json()
        assert "message" in data
        assert "annulé" in data["message"].lower() or "arrêté" in data["message"].lower()

    def test_end_to_end_cancel_flow_without_mock(self, client):
        """E2E sans mock: soumettre job, annuler, verifier statut (regle #11)."""
        create_resp = client.post('/api/jobs', json={
            "target_ip": "192.168.1.200",
            "duration": 5,
        })
        assert create_resp.status_code == 201
        job_id = create_resp.get_json()["result"]["id"]

        # Cancel le job
        cancel_resp = client.post(f'/api/jobs/{job_id}/cancel')
        # Peut etre 200 (pending/running) ou 409 (si deja termine)
        assert cancel_resp.status_code in (200, 409)

        # Verifier le statut du job
        get_resp = client.get(f'/api/jobs/{job_id}')
        assert get_resp.status_code == 200
        job_data = get_resp.get_json()["result"]
        assert job_data["status"] in ("cancelled", "completed", "failed")
