# Cross-cutting services package

from .hardware_detection import (
    PiModel,
    HardwareInfo,
    detect_pi_model,
    get_hardware_info,
    reset_hardware_info,
)
from .performance_config import (
    PerformanceTargets,
    get_performance_targets,
    get_current_targets,
    reset_performance_targets,
)
from .thread_manager import (
    ThreadManager,
    get_thread_manager,
    reset_thread_manager,
)
from .health_score_history import (
    HealthScoreHistoryStore,
    get_health_score_history,
    reset_health_score_history,
)

__all__ = [
    # Hardware detection
    "PiModel",
    "HardwareInfo",
    "detect_pi_model",
    "get_hardware_info",
    "reset_hardware_info",
    # Performance config
    "PerformanceTargets",
    "get_performance_targets",
    "get_current_targets",
    "reset_performance_targets",
    # Thread manager
    "ThreadManager",
    "get_thread_manager",
    "reset_thread_manager",
    # Health score history (Story 3.5)
    "HealthScoreHistoryStore",
    "get_health_score_history",
    "reset_health_score_history",
]
