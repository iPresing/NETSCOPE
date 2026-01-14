"""Unit tests for thread_manager service."""

import pytest
import threading
import time
from unittest.mock import patch, MagicMock

from app.services.thread_manager import (
    ThreadManager,
    get_thread_manager,
    reset_thread_manager,
)
from app.services.performance_config import (
    PerformanceTargets,
    reset_performance_targets,
)
from app.services.hardware_detection import reset_hardware_info


class TestThreadManagerInit:
    """Tests for ThreadManager initialization."""

    def setup_method(self):
        """Reset singletons before each test."""
        reset_thread_manager()
        reset_performance_targets()
        reset_hardware_info()

    def teardown_method(self):
        """Reset singletons after each test."""
        reset_thread_manager()
        reset_performance_targets()
        reset_hardware_info()

    def test_init_with_explicit_job_limit(self):
        """Test initialization with explicit job limit."""
        manager = ThreadManager(max_concurrent_jobs=3)

        assert manager.max_concurrent_jobs == 3

    def test_init_uses_performance_targets_when_no_limit(self):
        """Test initialization uses performance targets when no limit specified."""
        mock_targets = PerformanceTargets(
            cpu_threshold_percent=20,
            ram_threshold_percent=25,
            max_concurrent_jobs=2,
        )

        with patch(
            "app.services.thread_manager.get_current_targets",
            return_value=mock_targets
        ):
            manager = ThreadManager()

        assert manager.max_concurrent_jobs == 2

    def test_init_defaults_to_one_on_exception(self):
        """Test initialization defaults to 1 job on exception."""
        with patch(
            "app.services.thread_manager.get_current_targets",
            side_effect=Exception("Detection failed")
        ):
            manager = ThreadManager()

        assert manager.max_concurrent_jobs == 1


class TestCaptureLock:
    """Tests for capture lock functionality."""

    def setup_method(self):
        """Create fresh ThreadManager for each test."""
        self.manager = ThreadManager(max_concurrent_jobs=2)

    def test_acquire_capture_lock_success(self):
        """Test successful capture lock acquisition."""
        result = self.manager.acquire_capture_lock()

        assert result is True
        assert self.manager.is_capture_locked() is True

        self.manager.release_capture_lock()

    def test_acquire_capture_lock_non_blocking_when_held(self):
        """Test non-blocking acquire returns False when lock is held."""
        self.manager.acquire_capture_lock()

        result = self.manager.acquire_capture_lock(blocking=False)

        assert result is False

        self.manager.release_capture_lock()

    def test_release_capture_lock(self):
        """Test releasing capture lock."""
        self.manager.acquire_capture_lock()
        self.manager.release_capture_lock()

        assert self.manager.is_capture_locked() is False

    def test_release_unacquired_lock_warns(self):
        """Test releasing unacquired lock doesn't raise but warns."""
        # Should not raise
        self.manager.release_capture_lock()

    def test_is_capture_locked(self):
        """Test is_capture_locked returns correct state."""
        assert self.manager.is_capture_locked() is False

        self.manager.acquire_capture_lock()
        assert self.manager.is_capture_locked() is True

        self.manager.release_capture_lock()
        assert self.manager.is_capture_locked() is False


class TestJobSemaphore:
    """Tests for job semaphore functionality."""

    def setup_method(self):
        """Create fresh ThreadManager with 2 job slots."""
        self.manager = ThreadManager(max_concurrent_jobs=2)

    def test_acquire_job_slot_success(self):
        """Test successful job slot acquisition."""
        result = self.manager.acquire_job_slot()

        assert result is True

        self.manager.release_job_slot()

    def test_acquire_multiple_job_slots(self):
        """Test acquiring multiple job slots up to limit."""
        result1 = self.manager.acquire_job_slot()
        result2 = self.manager.acquire_job_slot()

        assert result1 is True
        assert result2 is True

        self.manager.release_job_slot()
        self.manager.release_job_slot()

    def test_acquire_job_slot_non_blocking_when_full(self):
        """Test non-blocking acquire returns False when slots are full."""
        self.manager.acquire_job_slot()
        self.manager.acquire_job_slot()

        result = self.manager.acquire_job_slot(blocking=False)

        assert result is False

        self.manager.release_job_slot()
        self.manager.release_job_slot()

    def test_acquire_job_slot_with_timeout(self):
        """Test acquire with timeout returns False when slots are full."""
        self.manager.acquire_job_slot()
        self.manager.acquire_job_slot()

        start = time.time()
        result = self.manager.acquire_job_slot(blocking=True, timeout=0.1)
        elapsed = time.time() - start

        assert result is False
        assert elapsed >= 0.1

        self.manager.release_job_slot()
        self.manager.release_job_slot()

    def test_release_job_slot(self):
        """Test releasing job slot makes it available."""
        self.manager.acquire_job_slot()
        self.manager.acquire_job_slot()
        self.manager.release_job_slot()

        # Should now be able to acquire one more
        result = self.manager.acquire_job_slot(blocking=False)
        assert result is True

        self.manager.release_job_slot()
        self.manager.release_job_slot()


class TestThreadTracking:
    """Tests for thread registration and tracking."""

    def setup_method(self):
        """Create fresh ThreadManager for each test."""
        self.manager = ThreadManager(max_concurrent_jobs=2)

    def test_register_thread(self):
        """Test registering a thread."""
        thread = threading.Thread(target=lambda: None)
        self.manager.register_thread("test-thread-1", thread)

        active = self.manager.get_active_threads()
        assert "test-thread-1" in active
        assert active["test-thread-1"] is thread

    def test_unregister_thread(self):
        """Test unregistering a thread."""
        thread = threading.Thread(target=lambda: None)
        self.manager.register_thread("test-thread-1", thread)

        removed = self.manager.unregister_thread("test-thread-1")

        assert removed is thread
        assert "test-thread-1" not in self.manager.get_active_threads()

    def test_unregister_nonexistent_thread(self):
        """Test unregistering nonexistent thread returns None."""
        result = self.manager.unregister_thread("nonexistent")

        assert result is None

    def test_get_active_thread_count(self):
        """Test getting active thread count."""
        assert self.manager.get_active_thread_count() == 0

        thread1 = threading.Thread(target=lambda: None)
        thread2 = threading.Thread(target=lambda: None)
        self.manager.register_thread("thread-1", thread1)
        self.manager.register_thread("thread-2", thread2)

        assert self.manager.get_active_thread_count() == 2

    def test_cleanup_dead_threads(self):
        """Test cleaning up dead threads."""
        # Create and start a thread that finishes immediately
        def quick_task():
            pass

        thread = threading.Thread(target=quick_task)
        thread.start()
        thread.join()  # Wait for it to finish

        self.manager.register_thread("dead-thread", thread)
        assert self.manager.get_active_thread_count() == 1

        cleaned = self.manager.cleanup_dead_threads()

        assert cleaned == 1
        assert self.manager.get_active_thread_count() == 0

    def test_get_available_job_slots(self):
        """Test getting available job slots estimate."""
        # Initially all slots available
        assert self.manager.get_available_job_slots() == 2

        # Register a job thread
        thread = threading.Thread(target=lambda: None, name="job-test-1")
        self.manager.register_thread("job-test-1", thread)

        assert self.manager.get_available_job_slots() == 1


class TestUpdateJobLimit:
    """Tests for updating job limit."""

    def setup_method(self):
        """Create fresh ThreadManager for each test."""
        self.manager = ThreadManager(max_concurrent_jobs=2)

    def test_update_job_limit(self):
        """Test updating job limit."""
        self.manager.update_job_limit(4)

        assert self.manager.max_concurrent_jobs == 4

    def test_update_job_limit_to_one(self):
        """Test updating job limit to 1."""
        self.manager.update_job_limit(1)

        assert self.manager.max_concurrent_jobs == 1

    def test_update_job_limit_invalid_raises(self):
        """Test updating job limit to invalid value raises."""
        with pytest.raises(ValueError):
            self.manager.update_job_limit(0)

        with pytest.raises(ValueError):
            self.manager.update_job_limit(-1)

    def test_update_job_limit_non_integer_raises_type_error(self):
        """Test updating job limit with non-integer raises TypeError."""
        with pytest.raises(TypeError):
            self.manager.update_job_limit(2.5)

        with pytest.raises(TypeError):
            self.manager.update_job_limit("2")


class TestGetThreadManager:
    """Tests for get_thread_manager singleton."""

    def setup_method(self):
        """Reset singleton before each test."""
        reset_thread_manager()
        reset_performance_targets()
        reset_hardware_info()

    def teardown_method(self):
        """Reset singleton after each test."""
        reset_thread_manager()
        reset_performance_targets()
        reset_hardware_info()

    def test_get_thread_manager_returns_singleton(self):
        """Test get_thread_manager returns same instance."""
        mock_targets = PerformanceTargets(
            cpu_threshold_percent=20,
            ram_threshold_percent=25,
            max_concurrent_jobs=2,
        )

        with patch(
            "app.services.thread_manager.get_current_targets",
            return_value=mock_targets
        ):
            first = get_thread_manager()
            second = get_thread_manager()

        assert first is second

    def test_reset_clears_singleton(self):
        """Test reset_thread_manager clears singleton."""
        mock_targets = PerformanceTargets(
            cpu_threshold_percent=20,
            ram_threshold_percent=25,
            max_concurrent_jobs=2,
        )

        with patch(
            "app.services.thread_manager.get_current_targets",
            return_value=mock_targets
        ):
            first = get_thread_manager()
            reset_thread_manager()
            second = get_thread_manager()

        assert first is not second


class TestConcurrency:
    """Tests for concurrent access patterns."""

    def setup_method(self):
        """Create fresh ThreadManager for each test."""
        self.manager = ThreadManager(max_concurrent_jobs=2)

    def test_capture_lock_thread_safety(self):
        """Test capture lock is thread-safe."""
        acquired_count = [0]
        lock = threading.Lock()

        def try_acquire():
            if self.manager.acquire_capture_lock(blocking=False):
                with lock:
                    acquired_count[0] += 1
                time.sleep(0.01)
                self.manager.release_capture_lock()

        threads = [threading.Thread(target=try_acquire) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Only threads that acquired should count
        # Due to timing, at least some should have acquired
        assert acquired_count[0] >= 1

    def test_job_semaphore_thread_safety(self):
        """Test job semaphore is thread-safe."""
        acquired_count = [0]
        max_concurrent = [0]
        current_concurrent = [0]
        lock = threading.Lock()

        def try_acquire():
            if self.manager.acquire_job_slot(blocking=True, timeout=1):
                with lock:
                    acquired_count[0] += 1
                    current_concurrent[0] += 1
                    max_concurrent[0] = max(max_concurrent[0], current_concurrent[0])

                time.sleep(0.01)

                with lock:
                    current_concurrent[0] -= 1
                self.manager.release_job_slot()

        threads = [threading.Thread(target=try_acquire) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should have acquired eventually
        assert acquired_count[0] == 10
        # Never more than max_concurrent_jobs at once
        assert max_concurrent[0] <= 2
