"""Centralized thread management for NETSCOPE.

Provides thread-safe management of concurrent operations with
dynamic limits based on detected hardware performance targets.
"""

import logging
import threading
from typing import Dict, Optional

from .performance_config import get_current_targets

logger = logging.getLogger(__name__)


class ThreadManager:
    """Centralized thread manager with dynamic limits.

    Manages:
    - Capture operations (exclusive lock - 1 capture at a time)
    - Inspection jobs (semaphore - max based on hardware)
    - Active thread tracking

    Thread naming convention:
    - capture-tcpdump-{timestamp}
    - job-scapy-{job_id}
    - service-log-flush
    - service-resource-monitor
    """

    def __init__(self, max_concurrent_jobs: Optional[int] = None):
        """Initialize ThreadManager with optional custom job limit.

        Args:
            max_concurrent_jobs: Override for max concurrent jobs.
                                If None, uses detected hardware targets.
        """
        self._capture_lock = threading.Lock()
        self._active_threads: Dict[str, threading.Thread] = {}
        self._threads_lock = threading.Lock()

        # Get max jobs from performance targets if not specified
        if max_concurrent_jobs is None:
            try:
                targets = get_current_targets()
                max_concurrent_jobs = targets.max_concurrent_jobs
            except Exception:
                # Default to conservative limit if detection fails
                max_concurrent_jobs = 1

        self._max_concurrent_jobs = max_concurrent_jobs
        self._job_semaphore = threading.Semaphore(max_concurrent_jobs)

        logger.info(
            f' ThreadManager initialized '
            f'(max_concurrent_jobs={max_concurrent_jobs})'
        )

    @property
    def max_concurrent_jobs(self) -> int:
        """Get the maximum number of concurrent jobs."""
        return self._max_concurrent_jobs

    def acquire_capture_lock(self, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire exclusive lock for capture operations.

        Args:
            blocking: If True, block until lock is available
            timeout: Timeout in seconds (-1 for no timeout)

        Returns:
            True if lock acquired, False otherwise
        """
        result = self._capture_lock.acquire(blocking=blocking, timeout=timeout)
        if result:
            logger.debug(' Capture lock acquired')
        else:
            logger.debug(' Failed to acquire capture lock')
        return result

    def release_capture_lock(self) -> None:
        """Release the capture lock."""
        try:
            self._capture_lock.release()
            logger.debug(' Capture lock released')
        except RuntimeError:
            logger.warning(' Attempted to release unacquired lock')

    def is_capture_locked(self) -> bool:
        """Check if capture lock is currently held.

        Returns:
            True if lock is held, False otherwise
        """
        locked = self._capture_lock.locked()
        return locked

    def acquire_job_slot(self, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire a job slot for Scapy inspection.

        Args:
            blocking: If True, block until slot is available
            timeout: Timeout in seconds (-1 for no timeout)

        Returns:
            True if slot acquired, False otherwise
        """
        if timeout < 0:
            result = self._job_semaphore.acquire(blocking=blocking)
        else:
            result = self._job_semaphore.acquire(blocking=blocking, timeout=timeout)

        if result:
            logger.debug(' Job slot acquired')
        else:
            logger.debug(' Failed to acquire job slot')
        return result

    def release_job_slot(self) -> None:
        """Release a job slot."""
        self._job_semaphore.release()
        logger.debug(' Job slot released')

    def get_available_job_slots(self) -> int:
        """Get approximate number of available job slots.

        Warning: This is an APPROXIMATE value based on registered threads.
        The actual semaphore state may differ if:
        - Jobs acquire slots without registering threads
        - Threads are registered with names not starting with 'job-'
        - Race conditions occur between checking and using the value

        For accurate blocking behavior, use acquire_job_slot() directly.

        Returns:
            Approximate number of available slots (0 to max_concurrent_jobs)
        """
        # Semaphore doesn't expose internal counter directly
        # We track this indirectly through active threads
        with self._threads_lock:
            job_threads = [
                name for name in self._active_threads.keys()
                if name.startswith('job-')
            ]
            return max(0, self._max_concurrent_jobs - len(job_threads))

    def register_thread(self, name: str, thread: threading.Thread) -> None:
        """Register an active thread for tracking.

        Args:
            name: Unique thread name
            thread: Thread object to track
        """
        with self._threads_lock:
            self._active_threads[name] = thread
            logger.debug(f' Thread registered (name={name})')

    def unregister_thread(self, name: str) -> Optional[threading.Thread]:
        """Unregister a thread.

        Args:
            name: Thread name to unregister

        Returns:
            The unregistered thread or None if not found
        """
        with self._threads_lock:
            thread = self._active_threads.pop(name, None)
            if thread:
                logger.debug(f' Thread unregistered (name={name})')
            return thread

    def get_active_threads(self) -> Dict[str, threading.Thread]:
        """Get a copy of active threads dictionary.

        Returns:
            Dictionary of thread name to thread object
        """
        with self._threads_lock:
            return dict(self._active_threads)

    def get_active_thread_count(self) -> int:
        """Get count of active tracked threads.

        Returns:
            Number of active threads
        """
        with self._threads_lock:
            return len(self._active_threads)

    def update_job_limit(self, new_limit: int) -> None:
        """Update the maximum concurrent jobs limit.

        Warning: This creates a new semaphore and should only be called
        when no jobs are running.

        Args:
            new_limit: New maximum number of concurrent jobs (must be integer >= 1)

        Raises:
            TypeError: If new_limit is not an integer
            ValueError: If new_limit is less than 1
        """
        if not isinstance(new_limit, int):
            raise TypeError(f"Job limit must be an integer, got {type(new_limit).__name__}")
        if new_limit < 1:
            raise ValueError("Job limit must be at least 1")

        old_limit = self._max_concurrent_jobs
        self._max_concurrent_jobs = new_limit
        self._job_semaphore = threading.Semaphore(new_limit)

        logger.info(
            f' Job limit updated '
            f'(old={old_limit}, new={new_limit})'
        )

    def cleanup_dead_threads(self) -> int:
        """Remove threads that are no longer alive.

        Returns:
            Number of threads cleaned up
        """
        cleaned = 0
        with self._threads_lock:
            dead_threads = [
                name for name, thread in self._active_threads.items()
                if not thread.is_alive()
            ]
            for name in dead_threads:
                del self._active_threads[name]
                cleaned += 1
                logger.debug(f' Dead thread cleaned (name={name})')

        if cleaned > 0:
            logger.info(f' Cleaned {cleaned} dead threads')

        return cleaned


# Global singleton instance
_thread_manager: Optional[ThreadManager] = None


def get_thread_manager() -> ThreadManager:
    """Get the global ThreadManager instance.

    Creates the instance on first call.

    Returns:
        ThreadManager singleton instance
    """
    global _thread_manager

    if _thread_manager is None:
        _thread_manager = ThreadManager()

    return _thread_manager


def reset_thread_manager() -> None:
    """Reset the global ThreadManager instance (for testing)."""
    global _thread_manager
    _thread_manager = None
