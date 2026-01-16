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

__all__ = [
    "BlacklistManager",
    "get_blacklist_manager",
    "reset_blacklist_manager",
    "BlacklistFileWatcher",
    "start_blacklist_watcher",
    "stop_blacklist_watcher",
    "get_blacklist_watcher",
]
