"""Anomaly detection models for NETSCOPE.

Defines dataclasses for blacklist matches and anomalies detected during
network capture analysis.

Lessons Learned Epic 1:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Dataclasses with to_dict() for JSON serialization
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import uuid


class CriticalityLevel(Enum):
    """Criticality level for anomalies.

    CRITICAL (red): IPs and domains on blacklists - high threat
    WARNING (yellow): Suspicious terms detected - medium threat
    NORMAL (green): No anomaly - baseline
    """

    CRITICAL = "critical"  # IPs/Domaines blacklistés
    WARNING = "warning"    # Termes suspects
    NORMAL = "normal"      # Aucune anomalie


class MatchType(Enum):
    """Type of blacklist match."""

    IP = "ip"
    DOMAIN = "domain"
    TERM = "term"


@dataclass
class BlacklistMatch:
    """Result of a blacklist match detection.

    Attributes:
        match_type: Type of match (ip, domain, term)
        matched_value: The value that matched the blacklist
        source_file: Source blacklist file name
        context: Human-readable context of the match
        criticality: Criticality level of the match
        timestamp: When the match was detected
    """

    match_type: MatchType
    matched_value: str
    source_file: str
    context: str
    criticality: CriticalityLevel
    timestamp: datetime = field(default_factory=lambda: datetime.now())

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON response."""
        return {
            "match_type": self.match_type.value,
            "matched_value": self.matched_value,
            "source_file": self.source_file,
            "context": self.context,
            "criticality": self.criticality.value,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Anomaly:
    """Detected anomaly with full context.

    Attributes:
        id: Unique anomaly identifier
        match: The blacklist match that triggered this anomaly
        score: Anomaly score (0-100, higher = more suspicious)
        packet_info: Associated packet information dict
        criticality_level: Overall criticality level
        capture_id: ID of the capture session
        created_at: When the anomaly was created
    """

    id: str
    match: BlacklistMatch
    score: int
    packet_info: dict[str, Any] | None = None
    criticality_level: CriticalityLevel = CriticalityLevel.NORMAL
    capture_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now())

    @staticmethod
    def generate_id() -> str:
        """Generate a unique anomaly ID."""
        return f"anomaly_{uuid.uuid4().hex[:8]}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON response."""
        return {
            "id": self.id,
            "match_type": self.match.match_type.value,
            "matched_value": self.match.matched_value,
            "source_file": self.match.source_file,
            "context": self.match.context,
            "criticality": self.criticality_level.value,
            "score": self.score,
            "packet_info": self.packet_info,
            "capture_id": self.capture_id,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class AnomalyCollection:
    """Collection of anomalies from a capture analysis.

    Attributes:
        anomalies: List of detected anomalies
        capture_id: Associated capture session ID
        analyzed_at: When the analysis was performed
    """

    anomalies: list[Anomaly] = field(default_factory=list)
    capture_id: str | None = None
    analyzed_at: datetime = field(default_factory=lambda: datetime.now())

    @property
    def total(self) -> int:
        """Total number of anomalies."""
        return len(self.anomalies)

    @property
    def by_criticality(self) -> dict[str, int]:
        """Count anomalies by criticality level."""
        counts = {
            "critical": 0,
            "warning": 0,
            "normal": 0,
        }
        for anomaly in self.anomalies:
            counts[anomaly.criticality_level.value] += 1
        return counts

    def add(self, anomaly: Anomaly) -> None:
        """Add an anomaly to the collection."""
        self.anomalies.append(anomaly)

    def get_sorted(self) -> list[Anomaly]:
        """Get anomalies sorted by criticality (critical first)."""
        priority = {
            CriticalityLevel.CRITICAL: 0,
            CriticalityLevel.WARNING: 1,
            CriticalityLevel.NORMAL: 2,
        }
        return sorted(self.anomalies, key=lambda a: priority[a.criticality_level])

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON response."""
        return {
            "anomalies": [a.to_dict() for a in self.get_sorted()],
            "total": self.total,
            "by_criticality": self.by_criticality,
            "capture_id": self.capture_id,
            "analyzed_at": self.analyzed_at.isoformat(),
        }


# Score constants for different match types
SCORE_IP_BLACKLIST = 85      # Critical - IP on blacklist
SCORE_DOMAIN_BLACKLIST = 80  # Critical - Domain on blacklist
SCORE_TERM_SUSPECT = 50      # Warning - Suspicious term
