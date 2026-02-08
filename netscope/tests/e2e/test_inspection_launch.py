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
