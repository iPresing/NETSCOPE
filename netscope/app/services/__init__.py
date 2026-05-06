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
from .whitelist_manager import (
    WhitelistManager,
    get_whitelist_manager,
    reset_whitelist_manager,
)
from .resource_monitor import (
    ResourceMonitor,
    get_resource_monitor,
    reset_resource_monitor,
)
from .graceful_degradation import (
    DegradationState,
    GracefulDegradationManager,
    get_degradation_manager,
    reset_degradation_manager,
)
from .blacklist_user_manager import (
    BlacklistUserManager,
    get_blacklist_user_manager,
    reset_blacklist_user_manager,
)
from .version_service import (
    VersionService,
    SystemInfo,
    SystemInfoKey,
    get_version_service,
    reset_version_service,
)
from .update_service import (
    UpdateService,
    UpdateCheckResult,
    UpdateErrorCode,
    get_update_service,
    reset_update_service,
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
    # Whitelist manager (Story 3.6)
    "WhitelistManager",
    "get_whitelist_manager",
    "reset_whitelist_manager",
    # Resource monitor (Story 4.7)
    "ResourceMonitor",
    "get_resource_monitor",
    "reset_resource_monitor",
    # Graceful degradation (Story 4.7)
    "DegradationState",
    "GracefulDegradationManager",
    "get_degradation_manager",
    "reset_degradation_manager",
    # Blacklist user manager (Story 4b.6)
    "BlacklistUserManager",
    "get_blacklist_user_manager",
    "reset_blacklist_user_manager",
    # Version service (Story 5.4)
    "VersionService",
    "SystemInfo",
    "SystemInfoKey",
    "get_version_service",
    "reset_version_service",
    # Update service (Story 5.5)
    "UpdateService",
    "UpdateCheckResult",
    "UpdateErrorCode",
    "get_update_service",
    "reset_update_service",
]
