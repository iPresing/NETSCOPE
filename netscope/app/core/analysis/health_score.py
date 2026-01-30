"""Health Score calculator for NETSCOPE.

Calculates network health score (0-100) based on detected anomalies.

Story 3.1: Calcul Score Santé Réseau (FR16, NFR11)
Formula: score = 100 - (critical_count * 15) - (warning_count * 5)
- Score minimum capped at 0
- Whitelist items excluded from displayed_score
- real_score includes all anomalies

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Singleton pattern like ScoringEngine
"""

from __future__ import annotations

import logging
from typing import Any

from app.models.anomaly import AnomalyCollection, CriticalityLevel
from app.models.health_score import HealthScoreResult

logger = logging.getLogger(__name__)


class HealthScoreCalculator:
    """Calculator for network health score.

    Calculates a 0-100 health score based on anomaly counts by criticality.
    Supports whitelist exclusion for displayed score vs real score.

    Usage:
        calculator = get_health_calculator()
        result = calculator.calculate(anomaly_collection, whitelisted_ids={"id1", "id2"})
    """

    # Default configuration (matching architecture.md Appendix A)
    DEFAULT_CONFIG = {
        "base_score": 100,
        "decay_per_critical": 15,
        "decay_per_warning": 5,
    }

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialize the health score calculator.

        Args:
            config: Optional configuration dict. If None, uses defaults.
                    Keys: base_score, decay_per_critical, decay_per_warning
        """
        self._base_score = self.DEFAULT_CONFIG["base_score"]
        self._decay_critical = self.DEFAULT_CONFIG["decay_per_critical"]
        self._decay_warning = self.DEFAULT_CONFIG["decay_per_warning"]

        if config:
            self._apply_config(config)

        logger.debug("HealthScoreCalculator initialized")

    def _apply_config(self, config: dict[str, Any]) -> None:
        """Apply configuration overrides.

        Args:
            config: Configuration dictionary with optional keys.
        """
        if "base_score" in config:
            self._base_score = config["base_score"]
        if "decay_per_critical" in config:
            self._decay_critical = config["decay_per_critical"]
        if "decay_per_warning" in config:
            self._decay_warning = config["decay_per_warning"]

        logger.debug(
            f"HealthScoreCalculator config applied "
            f"(base={self._base_score}, critical=-{self._decay_critical}, warning=-{self._decay_warning})"
        )

    def calculate(
        self,
        anomaly_collection: AnomalyCollection,
        whitelisted_ids: set[str] | None = None,
    ) -> HealthScoreResult:
        """Calculate health score from anomaly collection.

        Args:
            anomaly_collection: Collection of detected anomalies
            whitelisted_ids: Optional set of anomaly IDs to exclude from displayed score

        Returns:
            HealthScoreResult with displayed and real scores
        """
        whitelisted_ids = whitelisted_ids or set()

        # Count ALL anomalies by criticality (for real_score)
        total_critical = 0
        total_warning = 0

        # Count NON-whitelisted anomalies (for displayed_score)
        display_critical = 0
        display_warning = 0

        whitelist_hits = 0

        for anomaly in anomaly_collection.anomalies:
            is_whitelisted = anomaly.id in whitelisted_ids

            if is_whitelisted:
                whitelist_hits += 1

            if anomaly.criticality_level == CriticalityLevel.CRITICAL:
                total_critical += 1
                if not is_whitelisted:
                    display_critical += 1
            elif anomaly.criticality_level == CriticalityLevel.WARNING:
                total_warning += 1
                if not is_whitelisted:
                    display_warning += 1

        # Calculate scores using formula
        displayed_score = self._compute_score(display_critical, display_warning)
        real_score = self._compute_score(total_critical, total_warning)

        # Whitelist impact: difference between real and displayed
        # Negative means whitelist is improving displayed score (hiding bad stuff)
        # Per story 3.1: whitelist_impact = real_score - displayed_score
        whitelist_impact = real_score - displayed_score

        result = HealthScoreResult(
            displayed_score=displayed_score,
            real_score=real_score,
            base_score=self._base_score,
            critical_count=display_critical,
            warning_count=display_warning,
            whitelist_hits=whitelist_hits,
            whitelist_impact=whitelist_impact,
        )

        logger.debug(
            f"Health score calculated: displayed={displayed_score}, real={real_score}, "
            f"critical={display_critical}, warning={display_warning}, "
            f"whitelist_hits={whitelist_hits}"
        )

        return result

    def _compute_score(self, critical_count: int, warning_count: int) -> int:
        """Compute score using the decay formula.

        Args:
            critical_count: Number of critical anomalies
            warning_count: Number of warning anomalies

        Returns:
            Score (0-100, capped at minimum 0)
        """
        score = (
            self._base_score
            - (critical_count * self._decay_critical)
            - (warning_count * self._decay_warning)
        )
        return max(0, score)


# Singleton instance
_health_calculator: HealthScoreCalculator | None = None


def get_health_calculator(config: dict[str, Any] | None = None) -> HealthScoreCalculator:
    """Return the singleton health score calculator instance.

    Args:
        config: Optional configuration (only used on first call)

    Returns:
        HealthScoreCalculator singleton instance
    """
    global _health_calculator
    if _health_calculator is None:
        _health_calculator = HealthScoreCalculator(config)
    return _health_calculator


def reset_health_calculator() -> None:
    """Reset the singleton (useful for tests).

    Reinitializes the global instance to None.
    """
    global _health_calculator
    _health_calculator = None
