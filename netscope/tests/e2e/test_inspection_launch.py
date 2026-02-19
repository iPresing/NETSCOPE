"""Tests E2E pour le lancement d'inspection Scapy.

Story 4.1 - Task 9 (9.1-9.4)
"""

import pytest

from app.core.inspection.job_queue import reset_job_queue


@pytest.fixture(autouse=True)
def reset_queue():
    """Reset la job queue entre chaque test."""
    reset_job_queue()
    yield
    reset_job_queue()


class TestJobsPage:
    """Tests E2E pour la page /jobs."""

    def test_jobs_page_accessible(self, client):
        """9.2: page /jobs accessible et affiche le formulaire."""
        response = client.get('/jobs')

        assert response.status_code == 200
        html = response.data.decode('utf-8')
        assert 'Jobs d\'Inspection' in html or 'Jobs d&#39;Inspection' in html
        assert 'job-target-ip' in html
        assert 'btn-create-job' in html

    def test_create_job_and_list(self, client):
        """9.3: creation job via API et apparition dans la liste."""
        # Create job
        create_resp = client.post('/api/jobs', json={
            "target_ip": "192.168.1.42",
            "duration": 10,
        })
        assert create_resp.status_code == 201
        job_id = create_resp.get_json()["result"]["id"]

        # Verify it appears in list
        list_resp = client.get('/api/jobs')
        assert list_resp.status_code == 200
        jobs = list_resp.get_json()["result"]["jobs"]
        assert any(j["id"] == job_id for j in jobs)

    def test_invalid_params_returns_error(self, client):
        """9.4: job avec parametres invalides retourne erreur claire."""
        response = client.post('/api/jobs', json={
            "target_ip": "not-an-ip",
        })

        assert response.status_code == 400
        data = response.get_json()
        assert data["success"] is False
        assert "JOB_INVALID_PARAMS" == data["error"]["code"]
        assert len(data["error"]["message"]) > 0

    def test_invalid_port_returns_error(self, client):
        """Job avec port invalide retourne erreur claire."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.1",
            "target_port": 99999,
        })

        assert response.status_code == 400

    def test_invalid_duration_returns_error(self, client):
        """Job avec duree invalide retourne erreur claire."""
        response = client.post('/api/jobs', json={
            "target_ip": "192.168.1.1",
            "duration": 999,
        })

        assert response.status_code == 400


class TestJobsPageDirection:
    """Tests E2E pour la direction du port (Story 4.2 - Task 9.1)."""

    def test_jobs_page_has_direction_field(self, client):
        """page /jobs affiche le champ direction du port."""
        response = client.get('/jobs')

        assert response.status_code == 200
        html = response.data.decode('utf-8')
        assert 'job-port-direction' in html
        assert 'Direction du port' in html

    def test_create_job_full_params_with_direction(self, client):
        """creation job avec parametres complets (IP + port + direction + protocole + duree) via API."""
        response = client.post('/api/jobs', json={
            "target_ip": "10.0.0.1",
            "target_port": 4444,
            "target_port_direction": "dst",
            "protocol": "TCP",
            "duration": 60,
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data["success"] is True
        spec = data["result"]["spec"]
        assert spec["target_ip"] == "10.0.0.1"
        assert spec["target_port"] == 4444
        assert spec["target_port_direction"] == "dst"
        assert spec["protocol"] == "TCP"
        assert spec["duration"] == 60

    def test_create_job_with_direction_both_explicit(self, client):
        """creation job avec direction 'both' explicite (vs None implicite)."""
        response = client.post('/api/jobs', json={
            "target_ip": "10.0.0.2",
            "target_port": 8080,
            "target_port_direction": "both",
        })

        assert response.status_code == 201
        data = response.get_json()
        assert data["success"] is True
        spec = data["result"]["spec"]
        assert spec["target_port_direction"] == "both"


class TestJobsPageQueue:
    """Tests E2E pour l'affichage queue (Story 4.3 - Task 8)."""

    def test_jobs_page_shows_queue_capacity(self, client):
        """Page /jobs affiche l'indicateur de capacite queue."""
        response = client.get('/jobs')

        assert response.status_code == 200
        html = response.data.decode('utf-8')
        assert 'queue-capacity' in html

    def test_jobs_page_shows_queue_position(self, client):
        """Jobs en attente affichent leur position via l'API.

        Note: mock utilise uniquement pour creer des jobs PENDING (empecher le
        demarrage reel des threads). La verification se fait sans mock via l'API.
        """
        from unittest.mock import patch, MagicMock
        with patch("app.core.inspection.job_queue.get_thread_manager") as mock_get_tm:
            tm = MagicMock()
            tm.acquire_job_slot.return_value = False
            tm.get_available_job_slots.return_value = 0
            tm.max_concurrent_jobs = 2
            mock_get_tm.return_value = tm

            # Create 2 jobs that will be PENDING
            client.post('/api/jobs', json={"target_ip": "192.168.1.1"})
            client.post('/api/jobs', json={"target_ip": "192.168.1.2"})

        # Verify positions via API
        list_resp = client.get('/api/jobs')
        data = list_resp.get_json()
        pending_jobs = [j for j in data["result"]["jobs"] if j["status"] == "pending"]
        assert len(pending_jobs) >= 2
        positions = [j.get("queue_position") for j in pending_jobs]
        assert 1 in positions
        assert 2 in positions

    def test_jobs_page_shows_slots_indicator(self, client):
        """Page /jobs affiche l'indicateur de slots."""
        response = client.get('/jobs')

        assert response.status_code == 200
        html = response.data.decode('utf-8')
        assert 'jobs-slots' in html
