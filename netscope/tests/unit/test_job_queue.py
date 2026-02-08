"""Tests unitaires pour la JobQueue.

Story 4.1 - Task 2 & Task 7 (7.8-7.12)
"""

from unittest.mock import patch, MagicMock

import pytest

from app.core.inspection.job_models import JobStatus, create_job
from app.core.inspection.job_queue import JobQueue, reset_job_queue


@pytest.fixture(autouse=True)
def clean_queue():
    """Reset la queue avant chaque test."""
    reset_job_queue()
    yield
    reset_job_queue()


@pytest.fixture
def mock_thread_manager():
    """Mock le ThreadManager pour eviter les vrais threads."""
    with patch("app.core.inspection.job_queue.get_thread_manager") as mock_get_tm:
        tm = MagicMock()
        tm.acquire_job_slot.return_value = False  # Par defaut: pas de slot
        mock_get_tm.return_value = tm
        yield tm


class TestJobQueueSubmit:
    """Tests pour JobQueue.submit()."""

    def test_submit_creates_job(self, mock_thread_manager):
        """7.9: submit() cree un job et retourne Job."""
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")

        result = queue.submit(job)

        assert result is not None
        assert result.spec.id == job.spec.id
        assert result.spec.target_ip == "192.168.1.1"

    def test_submit_job_pending_when_no_slot(self, mock_thread_manager):
        """7.12: submit() quand aucun slot disponible met le job en attente."""
        mock_thread_manager.acquire_job_slot.return_value = False

        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")

        result = queue.submit(job)

        assert result.status == JobStatus.PENDING


class TestJobQueueGetJob:
    """Tests pour JobQueue.get_job()."""

    def test_get_job_returns_correct_job(self, mock_thread_manager):
        """7.10: get_job() retourne le bon job."""
        queue = JobQueue()
        job = create_job(target_ip="10.0.0.1")
        submitted = queue.submit(job)

        found = queue.get_job(submitted.spec.id)

        assert found is not None
        assert found.spec.id == submitted.spec.id
        assert found.spec.target_ip == "10.0.0.1"

    def test_get_job_returns_none_for_unknown(self, mock_thread_manager):
        """get_job() retourne None pour un ID inexistant."""
        queue = JobQueue()

        assert queue.get_job("job_nonexistent") is None


class TestJobQueueGetAllJobs:
    """Tests pour JobQueue.get_all_jobs()."""

    def test_get_all_jobs_returns_all(self, mock_thread_manager):
        """7.11: get_all_jobs() retourne la liste complete."""
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        job3 = create_job(target_ip="192.168.1.3")

        queue.submit(job1)
        queue.submit(job2)
        queue.submit(job3)

        all_jobs = queue.get_all_jobs()

        assert len(all_jobs) == 3

    def test_get_all_jobs_empty_initially(self, mock_thread_manager):
        """get_all_jobs() retourne liste vide au debut."""
        queue = JobQueue()

        assert queue.get_all_jobs() == []
