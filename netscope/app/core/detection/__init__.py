"""Threat detection module for NETSCOPE.

Provides blacklist management and threat detection capabilities.
"""

from app.core.detection.blacklist_manager import (
    BlacklistManager,
    get_blacklist_manager,
    reset_blacklist_manager,
    BlacklistFileWatcher,
    start_blacklist_watcher,
    stop_blacklist_watcher,
    get_blacklist_watcher,
)
from app.core.detection.blacklist_detector import (
    BlacklistDetector,
    create_detector,
)
from app.core.detection.anomaly_store import (
    AnomalyStore,
    get_anomaly_store,
    reset_anomaly_store,
)
from app.core.detection.human_context import (
    HumanContext,
    HumanContextProvider,
    RiskLevel,
    get_human_context_provider,
    reset_human_context_provider,
)

__all__ = [
    "BlacklistManager",
    "get_blacklist_manager",
    "reset_blacklist_manager",
    "BlacklistFileWatcher",
    "start_blacklist_watcher",
    "stop_blacklist_watcher",
    "get_blacklist_watcher",
    "BlacklistDetector",
    "create_detector",
    "AnomalyStore",
    "get_anomaly_store",
    "reset_anomaly_store",
    "HumanContext",
    "HumanContextProvider",
    "RiskLevel",
    "get_human_context_provider",
    "reset_human_context_provider",
]
