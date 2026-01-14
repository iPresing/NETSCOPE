"""Performance configuration service based on detected hardware.

Provides performance targets adapted to the Raspberry Pi model,
ensuring optimal resource usage across different Pi variants.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from .hardware_detection import PiModel, get_hardware_info

logger = logging.getLogger(__name__)


@dataclass
class PerformanceTargets:
    """Performance targets for resource management.

    Attributes:
        cpu_threshold_percent: Maximum CPU usage percentage target
        ram_threshold_percent: Maximum RAM usage percentage target
        max_concurrent_jobs: Maximum number of concurrent Scapy jobs
    """
    cpu_threshold_percent: int
    ram_threshold_percent: int
    max_concurrent_jobs: int

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "cpu_threshold_percent": self.cpu_threshold_percent,
            "ram_threshold_percent": self.ram_threshold_percent,
            "max_concurrent_jobs": self.max_concurrent_jobs,
        }


# Performance targets per Pi model
# Based on PRD NFR1-NFR14 requirements
PERFORMANCE_TARGETS_MAP = {
    # Pi Zero 2 W: Conservative - baseline target from PRD
    # 512MB RAM, quad 1GHz - must stay under 30% CPU/RAM
    PiModel.PI_ZERO_2_W: PerformanceTargets(
        cpu_threshold_percent=30,
        ram_threshold_percent=30,
        max_concurrent_jobs=1,
    ),
    # Pi 3 B/B+: Moderate - 50% more headroom
    # 1GB RAM, quad 1.4GHz
    PiModel.PI_3_B: PerformanceTargets(
        cpu_threshold_percent=20,
        ram_threshold_percent=25,
        max_concurrent_jobs=2,
    ),
    # Pi 4 B: Comfortable resources
    # 2-8GB RAM, quad 1.8GHz
    PiModel.PI_4_B: PerformanceTargets(
        cpu_threshold_percent=15,
        ram_threshold_percent=20,
        max_concurrent_jobs=2,
    ),
    # Pi 5: Excellent resources
    # 4-8GB RAM, quad 2.4GHz
    PiModel.PI_5: PerformanceTargets(
        cpu_threshold_percent=10,
        ram_threshold_percent=15,
        max_concurrent_jobs=2,
    ),
    # Unknown: Use conservative Pi Zero settings
    PiModel.UNKNOWN: PerformanceTargets(
        cpu_threshold_percent=30,
        ram_threshold_percent=30,
        max_concurrent_jobs=1,
    ),
}

# Cached targets
_performance_targets: Optional[PerformanceTargets] = None


def get_performance_targets(pi_model: Optional[PiModel] = None, _log: bool = False) -> PerformanceTargets:
    """Get performance targets for a specific Pi model.

    Args:
        pi_model: Optional PiModel enum. If None, uses detected hardware.
        _log: Internal flag to control logging (avoid duplicate logs).

    Returns:
        PerformanceTargets for the specified or detected model
    """
    if pi_model is None:
        hardware_info = get_hardware_info()
        pi_model = hardware_info.model

    targets = PERFORMANCE_TARGETS_MAP.get(
        pi_model,
        PERFORMANCE_TARGETS_MAP[PiModel.UNKNOWN]
    )

    if _log:
        logger.info(
            f"Performance targets retrieved "
            f"(model={pi_model.value}, cpu_threshold={targets.cpu_threshold_percent}%, "
            f"ram_threshold={targets.ram_threshold_percent}%, "
            f"max_jobs={targets.max_concurrent_jobs})"
        )

    return targets


def get_current_targets() -> PerformanceTargets:
    """Get cached performance targets for current hardware.

    Uses singleton pattern to avoid repeated lookups.
    Only logs on first access when caching the result.

    Returns:
        PerformanceTargets for current hardware
    """
    global _performance_targets

    if _performance_targets is None:
        _performance_targets = get_performance_targets(_log=False)
        logger.info(
            f"Performance targets cached "
            f"(cpu_threshold={_performance_targets.cpu_threshold_percent}%, "
            f"max_jobs={_performance_targets.max_concurrent_jobs})"
        )

    return _performance_targets


def reset_performance_targets() -> None:
    """Reset the cached performance targets (useful for testing)."""
    global _performance_targets
    _performance_targets = None
