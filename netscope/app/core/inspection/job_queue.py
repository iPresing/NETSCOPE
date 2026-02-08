"""Job Queue singleton pour les inspections Scapy.

Story 4.1: Lancement Inspection Scapy (FR22)
- Singleton pattern identique a WhitelistManager/BlacklistManager
- Thread safety via threading.Lock (regle #12)
- Integration ThreadManager pour les slots job

Lessons Learned Epic 1/2/3:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Singleton pattern with get_*/reset_* functions
- Thread safety: lock sur les operations CRUD concurrentes (regle #12)
"""

from __future__ import annotations

import logging
import threading

from app.core.inspection.job_models import Job, JobSpec, JobStatus, JobResult
from app.services.thread_manager import get_thread_manager

logger = logging.getLogger(__name__)

MAX_QUEUED_JOBS = 10


class JobQueue:
    """Queue singleton pour les jobs d'inspection Scapy.

    Gere la soumission, l'execution et le suivi des jobs d'inspection.
    Utilise ThreadManager pour les slots de concurrence.
    """

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        logger.info("JobQueue initialisee")

    def submit(self, job: Job) -> Job:
        """Soumet un job d'inspection a la queue.

        Ajoute le job a la queue et lance l'execution
        si un slot est disponible.

        Args:
            job: Job a soumettre

        Returns:
            Job avec status PENDING ou RUNNING
        """
        with self._lock:
            self._jobs[job.spec.id] = job

        logger.info(f"Job soumis (job_id={job.spec.id}, target={job.spec.target_ip})")

        self._try_execute(job)
        return job

    def get_job(self, job_id: str) -> Job | None:
        """Recupere un job par son ID.

        Args:
            job_id: Identifiant du job

        Returns:
            Job ou None si non trouve
        """
        with self._lock:
            return self._jobs.get(job_id)

    def get_all_jobs(self) -> list[Job]:
        """Retourne tous les jobs (en cours + termines + en attente).

        Returns:
            Liste de tous les jobs
        """
        with self._lock:
            return list(self._jobs.values())

    def is_full(self) -> bool:
        """Verifie si la queue de jobs en attente est saturee."""
        with self._lock:
            pending_count = sum(
                1 for j in self._jobs.values()
                if j.status == JobStatus.PENDING
            )
        return pending_count >= MAX_QUEUED_JOBS

    def _try_execute(self, job: Job) -> None:
        """Tente de lancer l'execution d'un job si un slot est disponible."""
        tm = get_thread_manager()

        # Tenter d'acquerir un slot sans bloquer
        acquired = tm.acquire_job_slot(blocking=False)
        if not acquired:
            logger.info(f"Pas de slot disponible, job en attente (job_id={job.spec.id})")
            return

        with self._lock:
            job.status = JobStatus.RUNNING

        thread_name = f"job-scapy-{job.spec.id}"
        thread = threading.Thread(
            target=self._execute_job,
            args=(job,),
            name=thread_name,
            daemon=True,
        )
        tm.register_thread(thread_name, thread)
        thread.start()

    def _execute_job(self, job: Job) -> None:
        """Worker thread qui execute un job d'inspection.

        Acquiert un slot ThreadManager, execute ScapyInspector,
        met a jour le statut et lance le prochain job en attente.
        """
        thread_name = f"job-scapy-{job.spec.id}"
        tm = get_thread_manager()

        try:
            logger.info(f"Job started (job_id={job.spec.id})")

            from app.core.inspection.scapy_inspector import ScapyInspector

            inspector = ScapyInspector()

            def progress_callback(percent: int) -> None:
                with self._lock:
                    job.progress_percent = percent

            result = inspector.run(job.spec, progress_callback=progress_callback)

            with self._lock:
                job.result = result
                job.status = result.status
                job.progress_percent = 100

            logger.info(
                f"Job completed "
                f"(job_id={job.spec.id}, packets={result.packets_captured})"
            )

        except Exception as exc:
            with self._lock:
                job.status = JobStatus.FAILED
                job.result = JobResult(
                    job_id=job.spec.id,
                    status=JobStatus.FAILED,
                    error_message=str(exc),
                )

            logger.error(
                f"Job failed "
                f"(job_id={job.spec.id}, error={exc})"
            )

        finally:
            tm.release_job_slot()
            tm.unregister_thread(thread_name)
            self._process_queue()

    def _process_queue(self) -> None:
        """Lance le prochain job en attente si un slot est disponible."""
        with self._lock:
            pending_jobs = [
                j for j in self._jobs.values()
                if j.status == JobStatus.PENDING
            ]

        if not pending_jobs:
            return

        # Trier par date de creation (premier arrive, premier servi)
        pending_jobs.sort(key=lambda j: j.spec.created_at)

        for job in pending_jobs:
            self._try_execute(job)
            # On ne lance qu'un seul job a la fois via _try_execute
            # qui verifie le slot disponible
            break


# Global singleton instance
_job_queue: JobQueue | None = None
_job_queue_lock = threading.Lock()


def get_job_queue() -> JobQueue:
    """Get the global JobQueue instance (thread-safe).

    Creates the instance on first call using double-checked locking.

    Returns:
        JobQueue singleton instance
    """
    global _job_queue

    if _job_queue is None:
        with _job_queue_lock:
            if _job_queue is None:
                _job_queue = JobQueue()

    return _job_queue


def reset_job_queue() -> None:
    """Reset the global JobQueue instance (for testing)."""
    global _job_queue
    _job_queue = None
