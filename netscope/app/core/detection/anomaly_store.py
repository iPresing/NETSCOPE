"""In-memory anomaly store for NETSCOPE.

Stores detected anomalies from capture analysis for API access.
Simple singleton pattern for MVP - can be enhanced with persistence later.

Lessons Learned Epic 1:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
"""

from __future__ import annotations

import logging
from datetime import datetime

from app.models.anomaly import Anomaly, AnomalyCollection

# CRITICAL: Logger module-level (Lesson Learned Epic 1 - A4)
logger = logging.getLogger(__name__)


class AnomalyStore:
    """In-memory storage for detected anomalies.

    Singleton pattern for global access. Stores anomalies indexed
    by capture_id and provides query methods for the API.
    """

    _instance: AnomalyStore | None = None

    def __new__(cls) -> AnomalyStore:
        """Singleton pattern implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize the anomaly store."""
        if self._initialized:
            return

        self._initialized = True
        self._collections: dict[str, AnomalyCollection] = {}
        self._latest_capture_id: str | None = None
        logger.debug("AnomalyStore initialized")

    def store(self, collection: AnomalyCollection) -> None:
        """Store an anomaly collection.

        Args:
            collection: AnomalyCollection to store
        """
        if collection.capture_id is None:
            logger.warning("Cannot store collection without capture_id")
            return

        self._collections[collection.capture_id] = collection
        self._latest_capture_id = collection.capture_id

        logger.info(
            f"Stored anomalies "
            f"(capture_id={collection.capture_id}, count={collection.total})"
        )

    def get_by_capture(self, capture_id: str) -> AnomalyCollection | None:
        """Get anomalies for a specific capture.

        Args:
            capture_id: Capture session ID

        Returns:
            AnomalyCollection or None if not found
        """
        return self._collections.get(capture_id)

    def get_latest(self) -> AnomalyCollection | None:
        """Get the most recent anomaly collection.

        Returns:
            AnomalyCollection or None if no collections
        """
        if self._latest_capture_id is None:
            return None
        return self._collections.get(self._latest_capture_id)

    def get_anomaly(self, anomaly_id: str) -> Anomaly | None:
        """Get a specific anomaly by ID.

        Searches all collections for the anomaly.

        Args:
            anomaly_id: Anomaly ID

        Returns:
            Anomaly or None if not found
        """
        for collection in self._collections.values():
            for anomaly in collection.anomalies:
                if anomaly.id == anomaly_id:
                    return anomaly
        return None

    def get_all_anomalies(self) -> list[Anomaly]:
        """Get all anomalies from all collections.

        Returns:
            List of all anomalies, sorted by criticality
        """
        all_anomalies: list[Anomaly] = []
        for collection in self._collections.values():
            all_anomalies.extend(collection.anomalies)

        # Sort by criticality (critical first)
        from app.models.anomaly import CriticalityLevel

        priority = {
            CriticalityLevel.CRITICAL: 0,
            CriticalityLevel.WARNING: 1,
            CriticalityLevel.NORMAL: 2,
        }
        return sorted(all_anomalies, key=lambda a: priority[a.criticality_level])

    @property
    def total_anomalies(self) -> int:
        """Total number of stored anomalies."""
        return sum(c.total for c in self._collections.values())

    def clear(self) -> None:
        """Clear all stored anomalies."""
        self._collections.clear()
        self._latest_capture_id = None
        logger.info("AnomalyStore cleared")


# Global singleton accessor
_anomaly_store: AnomalyStore | None = None


def get_anomaly_store() -> AnomalyStore:
    """Get the global AnomalyStore instance.

    Returns:
        AnomalyStore singleton instance
    """
    global _anomaly_store

    if _anomaly_store is None:
        _anomaly_store = AnomalyStore()

    return _anomaly_store


def reset_anomaly_store() -> None:
    """Reset the global AnomalyStore (for testing)."""
    global _anomaly_store
    if _anomaly_store is not None:
        _anomaly_store.clear()
        _anomaly_store._initialized = False
    _anomaly_store = None
    AnomalyStore._instance = None
