"""Resource monitor service for CPU monitoring.

Story 4.7: Graceful Degradation (FR44)
- Singleton ResourceMonitor with daemon thread
- Sliding window CPU monitoring via psutil
- Callbacks for degradation/recovery/critical states

Rules:
- Python 3.10+ type hints (X | None, not Optional[X])
- module-level logger
- Singleton with get_*/reset_* functions
- Thread safety: lock on state mutations (rule #12)
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone

import psutil

logger = logging.getLogger(__name__)


class ResourceMonitor:
    """Monitor CPU resources with sliding window detection.

    Detects sustained CPU overload conditions:
    - Degradation: CPU > threshold for N consecutive samples
    - Recovery: CPU < threshold for M consecutive samples
    - Critical: CPU > threshold for P consecutive samples

    Uses daemon thread for background monitoring.
    """

    def __init__(
        self,
        degradation_threshold: int = 80,
        recovery_threshold: int = 70,
        critical_threshold: int = 95,
        degradation_samples: int = 6,
        recovery_samples: int = 12,
        critical_samples: int = 24,
        sample_interval: int = 5,
    ) -> None:
        self._degradation_threshold = degradation_threshold
        self._recovery_threshold = recovery_threshold
        self._critical_threshold = critical_threshold
        self._degradation_samples = degradation_samples
        self._recovery_samples = recovery_samples
        self._critical_samples = critical_samples
        self._sample_interval = sample_interval

        self._cpu_samples: deque[float] = deque(maxlen=critical_samples)
        self._lock = threading.Lock()
        self._is_degraded = False
        self._is_critical = False
        self._degraded_since: datetime | None = None
        self._current_cpu: float = 0.0
        self._running = False
        self._monitor_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        self._on_degradation_enter: Callable[[], None] | None = None
        self._on_degradation_exit: Callable[[], None] | None = None
        self._on_critical_overload: Callable[[], None] | None = None

        logger.info("ResourceMonitor initialized")

    def configure(
        self,
        degradation_threshold: int | None = None,
        recovery_threshold: int | None = None,
        critical_threshold: int | None = None,
        degradation_samples: int | None = None,
        recovery_samples: int | None = None,
        critical_samples: int | None = None,
    ) -> None:
        """Reconfigure thresholds and window sizes.

        Updates deque maxlen if critical_samples changes.
        Should be called before start().
        """
        with self._lock:
            if degradation_threshold is not None:
                self._degradation_threshold = degradation_threshold
            if recovery_threshold is not None:
                self._recovery_threshold = recovery_threshold
            if critical_threshold is not None:
                self._critical_threshold = critical_threshold
            if degradation_samples is not None:
                self._degradation_samples = degradation_samples
            if recovery_samples is not None:
                self._recovery_samples = recovery_samples
            if critical_samples is not None:
                self._critical_samples = critical_samples
                self._cpu_samples = deque(maxlen=critical_samples)

    def set_callbacks(
        self,
        on_degradation_enter: Callable[[], None] | None = None,
        on_degradation_exit: Callable[[], None] | None = None,
        on_critical_overload: Callable[[], None] | None = None,
    ) -> None:
        """Set callback functions for state transitions."""
        with self._lock:
            self._on_degradation_enter = on_degradation_enter
            self._on_degradation_exit = on_degradation_exit
            self._on_critical_overload = on_critical_overload

    def start(self) -> None:
        """Start the monitoring daemon thread."""
        with self._lock:
            if self._running:
                logger.warning("ResourceMonitor already running")
                return

            self._stop_event.clear()
            self._running = True
            self._monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                name="resource-monitor",
                daemon=True,
            )

        self._monitor_thread.start()
        logger.info(
            "ResourceMonitor started (interval=%ds)", self._sample_interval
        )

    def stop(self) -> None:
        """Stop the monitoring thread."""
        with self._lock:
            if not self._running:
                return

            self._stop_event.set()
            self._running = False
            thread = self._monitor_thread
            self._monitor_thread = None

        # Join outside lock to avoid deadlock with monitoring loop
        if thread and thread.is_alive():
            thread.join(timeout=self._sample_interval + 2)
        logger.info("ResourceMonitor stopped")

    def get_status(self) -> dict:
        """Get current monitoring status.

        Returns:
            Dict with is_degraded, is_critical, cpu_percent,
            degraded_since, reason
        """
        with self._lock:
            reason = None
            if self._is_critical:
                reason = f"CPU critique ({self._current_cpu:.0f}%)"
            elif self._is_degraded:
                reason = f"CPU élevé ({self._current_cpu:.0f}%)"

            return {
                "is_degraded": self._is_degraded,
                "is_critical": self._is_critical,
                "cpu_percent": self._current_cpu,
                "degraded_since": (
                    self._degraded_since.isoformat()
                    if self._degraded_since
                    else None
                ),
                "reason": reason,
            }

    def _add_sample(self, cpu: float) -> None:
        """Add a CPU sample and check conditions.

        Called by monitoring loop. Also usable directly for testing.
        """
        with self._lock:
            self._current_cpu = cpu
            self._cpu_samples.append(cpu)
        self._check_conditions()

    def _monitoring_loop(self) -> None:
        """Main monitoring loop running in daemon thread."""
        logger.debug("ResourceMonitor loop started")

        while not self._stop_event.is_set():
            try:
                cpu = psutil.cpu_percent(interval=1)
                self._add_sample(cpu)
            except Exception as exc:
                logger.error("[resource-monitor] Error reading CPU: %s", exc)

            remaining = max(0, self._sample_interval - 1)
            if self._stop_event.wait(timeout=remaining):
                break

    def _check_conditions(self) -> None:
        """Check CPU conditions and fire callbacks."""
        callbacks_to_fire: list[Callable[[], None]] = []

        with self._lock:
            samples = list(self._cpu_samples)
            was_degraded = self._is_degraded
            was_critical = self._is_critical

            # Check degradation entry (NORMAL -> DEGRADED)
            if (
                not was_degraded
                and len(samples) >= self._degradation_samples
                and all(
                    s > self._degradation_threshold
                    for s in samples[-self._degradation_samples:]
                )
            ):
                self._is_degraded = True
                self._degraded_since = datetime.now(timezone.utc)
                logger.warning(
                    "[degradation] Mode entered "
                    "(CPU > %d%% for %ds)",
                    self._degradation_threshold,
                    self._degradation_samples * self._sample_interval,
                )
                if self._on_degradation_enter:
                    callbacks_to_fire.append(self._on_degradation_enter)

            # Check critical (DEGRADED -> CRITICAL)
            if (
                self._is_degraded
                and not was_critical
                and len(samples) >= self._critical_samples
                and all(
                    s > self._critical_threshold
                    for s in samples[-self._critical_samples:]
                )
            ):
                self._is_critical = True
                logger.warning(
                    "[degradation] Critical overload "
                    "(CPU > %d%% for %ds)",
                    self._critical_threshold,
                    self._critical_samples * self._sample_interval,
                )
                if self._on_critical_overload:
                    callbacks_to_fire.append(self._on_critical_overload)

            # Check recovery (DEGRADED/CRITICAL -> NORMAL)
            if (
                was_degraded
                and len(samples) >= self._recovery_samples
                and all(
                    s < self._recovery_threshold
                    for s in samples[-self._recovery_samples:]
                )
            ):
                self._is_degraded = False
                self._is_critical = False
                self._degraded_since = None
                logger.info(
                    "[degradation] Recovery "
                    "(CPU < %d%% for %ds)",
                    self._recovery_threshold,
                    self._recovery_samples * self._sample_interval,
                )
                if self._on_degradation_exit:
                    callbacks_to_fire.append(self._on_degradation_exit)

        # Fire callbacks outside lock to avoid deadlocks
        for cb in callbacks_to_fire:
            try:
                cb()
            except Exception as exc:
                logger.error("[resource-monitor] Callback error: %s", exc)


# Singleton
_instance: ResourceMonitor | None = None
_instance_lock = threading.Lock()


def get_resource_monitor() -> ResourceMonitor:
    """Get the global ResourceMonitor instance (thread-safe)."""
    global _instance

    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = ResourceMonitor()

    return _instance


def reset_resource_monitor() -> None:
    """Reset the global ResourceMonitor instance (for testing)."""
    global _instance
    if _instance is not None:
        _instance.stop()
    _instance = None
