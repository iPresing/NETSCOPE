"""Health Score models for NETSCOPE.

Defines dataclasses for network health score calculation results.

Story 3.1: Calcul Score Santé Réseau (FR16, NFR11)
- Score global 0-100 basé sur anomalies détectées
- Gestion séparée score affiché vs score réel (whitelist)
- Seuils couleur pour indicateur visuel

Story 3.4: Details Score Reel vs Affiche (FR19, NFR37)
- WhitelistHitDetail dataclass for individual hit information
- whitelist_details list in HealthScoreResult

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Dataclasses with to_dict() for JSON serialization
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class WhitelistHitDetail:
    """Detail of a single whitelist hit (Story 3.4).

    Attributes:
        anomaly_id: Unique ID of the whitelisted anomaly
        ip: IP address if available
        port: Port number if available
        anomaly_type: Type of anomaly (ip, domain, term, heuristic)
        criticality: Criticality level (critical, warning)
        impact: Points hidden by this hit (negative value)
        reason: Original detection reason
    """

    anomaly_id: str
    ip: str | None
    port: int | None
    anomaly_type: str
    criticality: str
    impact: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON response."""
        return {
            "anomaly_id": self.anomaly_id,
            "ip": self.ip,
            "port": self.port,
            "anomaly_type": self.anomaly_type,
            "criticality": self.criticality,
            "impact": self.impact,
            "reason": self.reason,
        }


@dataclass
class HealthScoreResult:
    """Result of network health score calculation.

    Attributes:
        displayed_score: Score shown to user (excludes whitelisted items)
        real_score: Actual score including all anomalies
        base_score: Starting score (default 100)
        critical_count: Number of non-whitelisted critical anomalies
        warning_count: Number of non-whitelisted warning anomalies
        whitelist_hits: Number of whitelisted items
        whitelist_impact: Points hidden by whitelist (real - displayed)
        whitelist_details: List of detailed whitelist hit info (Story 3.4)
    """

    displayed_score: int
    real_score: int
    base_score: int = 100
    critical_count: int = 0
    warning_count: int = 0
    whitelist_hits: int = 0
    whitelist_impact: int = 0
    whitelist_details: list[WhitelistHitDetail] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate score values are within expected range."""
        if not 0 <= self.displayed_score <= 100:
            raise ValueError(f"displayed_score must be 0-100, got {self.displayed_score}")
        if not 0 <= self.real_score <= 100:
            raise ValueError(f"real_score must be 0-100, got {self.real_score}")
        if self.critical_count < 0:
            raise ValueError(f"critical_count must be >= 0, got {self.critical_count}")
        if self.warning_count < 0:
            raise ValueError(f"warning_count must be >= 0, got {self.warning_count}")
        if self.whitelist_hits < 0:
            raise ValueError(f"whitelist_hits must be >= 0, got {self.whitelist_hits}")

    def get_status_color(self) -> str:
        """Return status color based on displayed_score.

        Returns:
            "normal" (green) for score >= 80
            "warning" (orange) for score 50-79
            "critical" (red) for score < 50
        """
        if self.displayed_score >= 80:
            return "normal"
        elif self.displayed_score >= 50:
            return "warning"
        return "critical"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON response.

        Returns:
            Dictionary representation of the health score result
        """
        return {
            "displayed_score": self.displayed_score,
            "real_score": self.real_score,
            "base_score": self.base_score,
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "whitelist_hits": self.whitelist_hits,
            "whitelist_impact": self.whitelist_impact,
            "status_color": self.get_status_color(),
            "whitelist_details": [d.to_dict() for d in self.whitelist_details],
        }
