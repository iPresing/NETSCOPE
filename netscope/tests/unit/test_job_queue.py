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


class TestJobQueuePosition:
    """Tests pour get_queue_position(), get_queue_stats(), get_jobs_ahead() (Story 4.3 - Task 1)."""

    def test_submit_when_slot_available_starts_immediately(self, mock_thread_manager):
        """Verifier que le job demarre directement quand un slot est disponible."""
        mock_thread_manager.acquire_job_slot.return_value = True
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")

        result = queue.submit(job)

        assert result.status == JobStatus.RUNNING

    def test_submit_when_no_slot_queues_job(self, mock_thread_manager):
        """Verifier que le job est mis en PENDING quand pas de slot."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")

        result = queue.submit(job)

        assert result.status == JobStatus.PENDING

    def test_get_queue_position_returns_correct_position(self, mock_thread_manager):
        """Soumettre 3 jobs, verifier les positions 1, 2, 3."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        job3 = create_job(target_ip="192.168.1.3")

        queue.submit(job1)
        queue.submit(job2)
        queue.submit(job3)

        assert queue.get_queue_position(job1.spec.id) == 1
        assert queue.get_queue_position(job2.spec.id) == 2
        assert queue.get_queue_position(job3.spec.id) == 3

    def test_get_queue_position_returns_none_for_running(self, mock_thread_manager):
        """Position None si le job est RUNNING."""
        mock_thread_manager.acquire_job_slot.return_value = True
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")

        queue.submit(job)

        assert queue.get_queue_position(job.spec.id) is None

    def test_get_queue_position_returns_none_for_completed(self, mock_thread_manager):
        """Position None si le job est COMPLETED."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")
        queue.submit(job)
        with queue._lock:
            job.status = JobStatus.COMPLETED

        assert queue.get_queue_position(job.spec.id) is None

    def test_get_queue_stats_returns_all_counts(self, mock_thread_manager):
        """Verifier que get_queue_stats() retourne toutes les statistiques."""
        mock_thread_manager.acquire_job_slot.return_value = False
        mock_thread_manager.get_available_job_slots.return_value = 0
        mock_thread_manager.max_concurrent_jobs = 2
        queue = JobQueue()

        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        job3 = create_job(target_ip="192.168.1.3")
        queue.submit(job1)
        queue.submit(job2)
        queue.submit(job3)

        # Simuler des statuts differents
        with queue._lock:
            job2.status = JobStatus.RUNNING
            job3.status = JobStatus.COMPLETED

        stats = queue.get_queue_stats()

        assert stats["pending_count"] == 1
        assert stats["running_count"] == 1
        assert stats["completed_count"] == 1
        assert stats["failed_count"] == 0
        assert stats["cancelled_count"] == 0
        assert stats["max_queue_size"] == 10
        assert stats["max_concurrent_jobs"] == 2
        assert stats["available_slots"] == 0

    def test_get_jobs_ahead_returns_correct_count(self, mock_thread_manager):
        """Verifier le nombre de jobs devant dans la queue."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        job3 = create_job(target_ip="192.168.1.3")

        queue.submit(job1)
        queue.submit(job2)
        queue.submit(job3)

        assert queue.get_jobs_ahead(job1.spec.id) == 0
        assert queue.get_jobs_ahead(job2.spec.id) == 1
        assert queue.get_jobs_ahead(job3.spec.id) == 2

    def test_process_queue_starts_next_after_completion(self, mock_thread_manager):
        """Verifier l'auto-demarrage FIFO apres completion d'un job."""
        # Phase 1: pas de slot, jobs en PENDING
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        queue.submit(job1)
        queue.submit(job2)

        assert job1.status == JobStatus.PENDING
        assert job2.status == JobStatus.PENDING

        # Phase 2: slot disponible, process_queue lance le premier
        mock_thread_manager.acquire_job_slot.return_value = True
        queue._process_queue()

        assert job1.status == JobStatus.RUNNING

    def test_process_queue_starts_next_after_failure(self, mock_thread_manager):
        """Echec d'un job -> prochain job demarre."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        queue.submit(job1)
        queue.submit(job2)

        # job1 echoue
        with queue._lock:
            job1.status = JobStatus.FAILED

        # Slot libere
        mock_thread_manager.acquire_job_slot.return_value = True
        queue._process_queue()

        assert job2.status == JobStatus.RUNNING

    def test_failed_job_does_not_crash_queue(self, mock_thread_manager):
        """Isolation des erreurs (NFR21): echec n'affecte pas la queue."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        job3 = create_job(target_ip="192.168.1.3")
        queue.submit(job1)
        queue.submit(job2)
        queue.submit(job3)

        # job1 echoue
        with queue._lock:
            job1.status = JobStatus.FAILED

        # Verify queue is still functional
        assert queue.get_queue_position(job2.spec.id) == 1
        assert queue.get_queue_position(job3.spec.id) == 2

        stats = queue.get_queue_stats()
        assert stats["pending_count"] == 2
        assert stats["failed_count"] == 1

    def test_queue_respects_fifo_order(self, mock_thread_manager):
        """Verifier l'ordre chronologique FIFO."""
        import time
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        time.sleep(0.01)
        job2 = create_job(target_ip="192.168.1.2")
        time.sleep(0.01)
        job3 = create_job(target_ip="192.168.1.3")

        queue.submit(job1)
        queue.submit(job2)
        queue.submit(job3)

        assert queue.get_queue_position(job1.spec.id) == 1
        assert queue.get_queue_position(job2.spec.id) == 2
        assert queue.get_queue_position(job3.spec.id) == 3

    def test_max_concurrent_jobs_respected(self, mock_thread_manager):
        """Jamais plus de max_concurrent_jobs RUNNING simultanément."""
        call_count = [0]

        def limited_acquire(blocking=True):
            call_count[0] += 1
            return call_count[0] <= 2  # Only 2 slots

        mock_thread_manager.acquire_job_slot.side_effect = limited_acquire
        queue = JobQueue()

        jobs = [create_job(target_ip=f"192.168.1.{i}") for i in range(1, 5)]
        for j in jobs:
            queue.submit(j)

        running = [j for j in queue.get_all_jobs() if j.status == JobStatus.RUNNING]
        pending = [j for j in queue.get_all_jobs() if j.status == JobStatus.PENDING]

        assert len(running) == 2
        assert len(pending) == 2

    def test_is_full_when_max_queued_reached(self, mock_thread_manager):
        """is_full() retourne True quand MAX_QUEUED_JOBS atteint."""
        from app.core.inspection.job_queue import MAX_QUEUED_JOBS
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()

        for i in range(MAX_QUEUED_JOBS):
            job = create_job(target_ip=f"10.0.0.{i + 1}")
            queue.submit(job)

        assert queue.is_full() is True

    def test_is_full_false_when_under_limit(self, mock_thread_manager):
        """is_full() retourne False quand la queue n'est pas pleine."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()

        job = create_job(target_ip="10.0.0.1")
        queue.submit(job)

        assert queue.is_full() is False


class TestJobCancellation:
    """Tests pour cancel_job() et stop_job() (Story 4.6 - Task 6.1)."""

    def test_cancel_pending_job_sets_cancelled(self, mock_thread_manager):
        """cancel_job() sur un PENDING → statut CANCELLED."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")
        queue.submit(job)

        queue.cancel_job(job.spec.id)

        assert job.status == JobStatus.CANCELLED

    def test_cancel_pending_job_returns_true(self, mock_thread_manager):
        """cancel_job() retourne True pour PENDING."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")
        queue.submit(job)

        assert queue.cancel_job(job.spec.id) is True

    def test_cancel_running_job_sets_stop_event(self, mock_thread_manager):
        """cancel_job() sur un RUNNING → stop_event.is_set()."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")
        queue.submit(job)
        # Mettre manuellement en RUNNING (pas de vrai thread)
        with queue._lock:
            job.status = JobStatus.RUNNING

        queue.cancel_job(job.spec.id)

        assert job.stop_event.is_set()

    def test_cancel_running_job_returns_true(self, mock_thread_manager):
        """cancel_job() retourne True pour RUNNING."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")
        queue.submit(job)
        with queue._lock:
            job.status = JobStatus.RUNNING

        assert queue.cancel_job(job.spec.id) is True

    def test_cancel_completed_job_returns_false(self, mock_thread_manager):
        """cancel_job() retourne False pour COMPLETED."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")
        queue.submit(job)
        with queue._lock:
            job.status = JobStatus.COMPLETED

        assert queue.cancel_job(job.spec.id) is False

    def test_cancel_nonexistent_job_returns_false(self, mock_thread_manager):
        """cancel_job() retourne False pour job_id inexistant."""
        queue = JobQueue()

        assert queue.cancel_job("job_nonexistent") is False

    def test_cancel_pending_frees_queue_position(self, mock_thread_manager):
        """cancel d'un PENDING → positions recalculees."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        job3 = create_job(target_ip="192.168.1.3")
        queue.submit(job1)
        queue.submit(job2)
        queue.submit(job3)

        queue.cancel_job(job1.spec.id)

        assert queue.get_queue_position(job2.spec.id) == 1
        assert queue.get_queue_position(job3.spec.id) == 2

    def test_stop_job_only_works_on_running(self, mock_thread_manager):
        """stop_job() sur PENDING/COMPLETED → False."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job = create_job(target_ip="192.168.1.1")
        queue.submit(job)

        # PENDING
        assert queue.stop_job(job.spec.id) is False

        # COMPLETED
        with queue._lock:
            job.status = JobStatus.COMPLETED
        assert queue.stop_job(job.spec.id) is False

    def test_process_queue_after_cancel(self, mock_thread_manager):
        """cancel RUNNING → prochain PENDING demarre via _process_queue."""
        mock_thread_manager.acquire_job_slot.return_value = False
        queue = JobQueue()
        job1 = create_job(target_ip="192.168.1.1")
        job2 = create_job(target_ip="192.168.1.2")
        queue.submit(job1)
        queue.submit(job2)

        # Mettre job1 en RUNNING
        with queue._lock:
            job1.status = JobStatus.RUNNING

        queue.cancel_job(job1.spec.id)

        # Simuler le finally de _execute_job: _process_queue
        mock_thread_manager.acquire_job_slot.return_value = True
        queue._process_queue()

        assert job2.status == JobStatus.RUNNING
