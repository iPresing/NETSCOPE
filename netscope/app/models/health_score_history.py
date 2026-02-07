"""Health Score History models for NETSCOPE.

Defines dataclasses for tracking health score evolution between captures.

Story 3.5: Evolution Score Entre Captures (FR20)
- Track score history across captures
- Calculate evolution (delta, direction) between captures
- Support first capture detection (no previous score)

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Dataclasses with to_dict() for JSON serialization
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class HealthScoreEntry:
    """Entry in health score history for a single capture.

    Attributes:
        capture_id: Unique ID of the capture session
        displayed_score: Score shown to user (excludes whitelisted items)
        real_score: Actual score including all anomalies
        critical_count: Number of non-whitelisted critical anomalies
        warning_count: Number of non-whitelisted warning anomalies
        whitelist_hits: Number of whitelisted items
        timestamp: When this score was recorded
    """

    capture_id: str
    displayed_score: int
    real_score: int
    critical_count: int
    warning_count: int
    whitelist_hits: int
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON response.

        Returns:
            Dictionary representation of the health score entry
        """
        return {
            "capture_id": self.capture_id,
            "displayed_score": self.displayed_score,
            "real_score": self.real_score,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "whitelist_hits": self.whitelist_hits,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScoreEvolution:
    """Evolution of score between two captures.

    Attributes:
        current_score: The most recent score
        previous_score: The score from the previous capture (None if first capture)
        delta: Difference (current - previous), 0 if first capture
        direction: "up", "down", or "stable"
        message: Human-readable evolution message
    """

    current_score: int
    previous_score: int | None
    delta: int
    direction: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON response.

        Returns:
            Dictionary representation of the score evolution
        """
        return {
            "current_score": self.current_score,
            "previous_score": self.previous_score,
            "delta": self.delta,
            "direction": self.direction,
            "message": self.message,
        }
