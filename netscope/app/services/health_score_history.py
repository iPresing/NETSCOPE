"""Health Score History Store for NETSCOPE.

Stores and manages health score history across captures.

Story 3.5: Evolution Score Entre Captures (FR20)
- In-memory storage with FIFO limit (10 entries max)
- Singleton pattern matching other services
- Calculate evolution between captures

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Singleton pattern like ScoringEngine
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.models.health_score import HealthScoreResult
from app.models.health_score_history import HealthScoreEntry, ScoreEvolution

logger = logging.getLogger(__name__)


class HealthScoreHistoryStore:
    """Store for health score history across captures.

    Maintains an in-memory list of recent health scores with FIFO eviction.
    Provides methods to record scores and calculate evolution.

    Usage:
        store = get_health_score_history()
        store.record(capture_id, health_result)
        evolution = store.get_evolution()
    """

    MAX_ENTRIES = 10

    def __init__(self) -> None:
        """Initialize the health score history store."""
        self._history: list[HealthScoreEntry] = []
        logger.debug("HealthScoreHistoryStore initialized")

    def record(self, capture_id: str, result: HealthScoreResult) -> None:
        """Record a health score in the history.

        Skips duplicate entries for the same capture_id to avoid
        polluting history during polling.

        Args:
            capture_id: Unique identifier for the capture session
            result: HealthScoreResult from the calculator
        """
        # Deduplicate: skip if last entry is the same capture
        if self._history and self._history[-1].capture_id == capture_id:
            return

        entry = HealthScoreEntry(
            capture_id=capture_id,
            displayed_score=result.displayed_score,
            real_score=result.real_score,
            critical_count=result.critical_count,
            warning_count=result.warning_count,
            whitelist_hits=result.whitelist_hits,
            timestamp=datetime.now(timezone.utc),
        )

        self._history.append(entry)

        # FIFO - keep only MAX_ENTRIES most recent
        if len(self._history) > self.MAX_ENTRIES:
            self._history = self._history[-self.MAX_ENTRIES:]

        logger.debug(
            f"Health score recorded (capture={capture_id}, "
            f"score={result.displayed_score}, history_size={len(self._history)})"
        )

    def get_latest(self, count: int = 2) -> list[HealthScoreEntry]:
        """Get the N most recent entries.

        Args:
            count: Number of entries to return (default 2)

        Returns:
            List of entries, most recent first
        """
        if not self._history:
            return []

        # Return last N entries in reverse order (most recent first)
        return self._history[-count:][::-1]

    def get_evolution(self) -> ScoreEvolution | None:
        """Calculate evolution between the last two captures.

        Returns:
            ScoreEvolution with delta and direction, or None if no history
        """
        latest = self.get_latest(2)

        if not latest:
            return None

        current = latest[0]

        if len(latest) < 2:
            # First capture - no previous score
            return ScoreEvolution(
                current_score=current.displayed_score,
                previous_score=None,
                delta=0,
                direction="stable",
                message="Premiere capture",
            )

        previous = latest[1]
        delta = current.displayed_score - previous.displayed_score

        if delta > 0:
            direction = "up"
            message = f"Amelioration de {delta} pts"
        elif delta < 0:
            direction = "down"
            message = f"Degradation de {abs(delta)} pts"
        else:
            direction = "stable"
            message = "Score stable"

        return ScoreEvolution(
            current_score=current.displayed_score,
            previous_score=previous.displayed_score,
            delta=delta,
            direction=direction,
            message=message,
        )

    def get_history_count(self) -> int:
        """Get the number of entries in history.

        Returns:
            Number of stored entries
        """
        return len(self._history)

    def clear(self) -> None:
        """Clear all history entries."""
        self._history.clear()
        logger.debug("Health score history cleared")


# Singleton instance
_health_score_history: HealthScoreHistoryStore | None = None


def get_health_score_history() -> HealthScoreHistoryStore:
    """Return the singleton health score history store instance.

    Returns:
        HealthScoreHistoryStore singleton instance
    """
    global _health_score_history
    if _health_score_history is None:
        _health_score_history = HealthScoreHistoryStore()
    return _health_score_history


def reset_health_score_history() -> None:
    """Reset the singleton (useful for tests).

    Reinitializes the global instance to None.
    """
    global _health_score_history
    _health_score_history = None
    logger.debug("Health score history singleton reset")
