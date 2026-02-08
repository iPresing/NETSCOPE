"""Tests integration pour l'API Jobs.

Story 4.1 - Task 8 (8.1-8.8)

Lessons Learned Epic 3:
- Au moins 1 test end-to-end sans mock par story (regle #11)
"""

from unittest.mock import patch

import pytest

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
        from unittest.mock import MagicMock
        tm = MagicMock()
        tm.acquire_job_slot.return_value = False
        tm.get_available_job_slots.return_value = 1
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
