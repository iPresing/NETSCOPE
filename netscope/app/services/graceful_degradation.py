"""Graceful Degradation coordinator.

Story 4.7: Graceful Degradation (FR44)
- Coordinates between ResourceMonitor and JobQueue
- States: NORMAL, DEGRADED, CRITICAL (enum)
- Suspends/resumes/cancels jobs based on resource state

Rules:
- Python 3.10+ type hints (X | None, not Optional[X])
- module-level logger
- Singleton with get_*/reset_* functions
- Thread safety: lock on state mutations (rule #12)
"""

from __future__ import annotations

import logging
import threading
from enum import Enum

logger = logging.getLogger(__name__)


class DegradationState(Enum):
    """System degradation state."""

    NORMAL = "normal"
    DEGRADED = "degraded"
    CRITICAL = "critical"


class GracefulDegradationManager:
    """Coordinates graceful degradation responses.

    Integrates with ResourceMonitor via callbacks.
    Controls JobQueue behavior based on system state.
    """

    def __init__(self) -> None:
        self._state = DegradationState.NORMAL
        self._lock = threading.Lock()
        logger.info("GracefulDegradationManager initialized")

    @property
    def state(self) -> DegradationState:
        """Current degradation state."""
        with self._lock:
            return self._state

    def can_accept_job(self) -> bool:
        """Check if new jobs can be accepted.

        Returns False if system is in DEGRADED or CRITICAL state.
        """
        with self._lock:
            return self._state == DegradationState.NORMAL

    def on_degradation_enter(self) -> None:
        """Callback when degradation is detected.

        Transitions to DEGRADED state and suspends pending jobs.
        """
        with self._lock:
            self._state = DegradationState.DEGRADED

        logger.warning(
            "[degradation] State -> DEGRADED, suspending pending jobs"
        )
        self._suspend_pending_jobs()

    def on_degradation_exit(self) -> None:
        """Callback when system recovers.

        Transitions to NORMAL state and resumes suspended jobs.
        """
        with self._lock:
            self._state = DegradationState.NORMAL

        logger.info(
            "[degradation] State -> NORMAL, resuming suspended jobs"
        )
        self._resume_suspended_jobs()

    def on_critical_overload(self) -> None:
        """Callback when critical overload is detected.

        Transitions to CRITICAL state and cancels suspended jobs.
        """
        with self._lock:
            self._state = DegradationState.CRITICAL

        logger.warning(
            "[degradation] State -> CRITICAL, cancelling suspended jobs"
        )
        self._cancel_suspended_jobs()

    def _suspend_pending_jobs(self) -> None:
        """Suspend all pending jobs in the queue."""
        from app.core.inspection.job_queue import get_job_queue

        queue = get_job_queue()
        count = queue.suspend_pending_jobs()
        if count > 0:
            logger.warning(
                "[degradation] %d job(s) suspended", count
            )

    def _resume_suspended_jobs(self) -> None:
        """Resume all suspended jobs in the queue."""
        from app.core.inspection.job_queue import get_job_queue

        queue = get_job_queue()
        count = queue.resume_suspended_jobs()
        if count > 0:
            logger.info(
                "[degradation] %d job(s) resumed", count
            )

    def _cancel_suspended_jobs(self) -> None:
        """Cancel all suspended jobs in the queue."""
        from app.core.inspection.job_queue import get_job_queue

        queue = get_job_queue()
        count = queue.cancel_suspended_jobs()
        if count > 0:
            logger.warning(
                "[degradation] %d job(s) cancelled (critical)", count
            )

    def get_status(self) -> dict:
        """Get current degradation manager status."""
        with self._lock:
            return {
                "state": self._state.value,
                "is_degraded": self._state != DegradationState.NORMAL,
                "can_accept_jobs": self._state == DegradationState.NORMAL,
            }


# Singleton
_instance: GracefulDegradationManager | None = None
_instance_lock = threading.Lock()


def get_degradation_manager() -> GracefulDegradationManager:
    """Get the global GracefulDegradationManager instance (thread-safe)."""
    global _instance

    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = GracefulDegradationManager()

    return _instance


def reset_degradation_manager() -> None:
    """Reset the global GracefulDegradationManager instance (for testing)."""
    global _instance
    _instance = None
