"""Scoring models for NETSCOPE.

Defines dataclasses for score breakdown and heuristic factors.
Separated from core/analysis/scoring.py to follow architecture pattern
where models belong in models/ directory.

Story 2.3: Scoring Cascade Multi-Criteres
Code Review Fix: H2 - Architecture compliance
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.anomaly import CriticalityLevel


@dataclass
class HeuristicFactors:
    """Facteurs heuristiques analyses pour scoring.

    Attributes:
        is_external_ip: True si IP externe (hors RFC1918)
        is_suspicious_port: True si port dans liste suspecte
        suspicious_port_value: Valeur du port suspect detecte
        is_high_volume: True si volume > seuil
        volume_packets: Nombre de paquets
        is_unknown_protocol: True si protocole non standard
        protocol: Nom du protocole
    """

    is_external_ip: bool = False
    is_suspicious_port: bool = False
    suspicious_port_value: int | None = None
    is_high_volume: bool = False
    volume_packets: int = 0
    is_unknown_protocol: bool = False
    protocol: str = ""

    def count_positive(self) -> int:
        """Compte le nombre de facteurs positifs.

        Returns:
            Nombre de facteurs actifs (0-4)
        """
        count = 0
        if self.is_external_ip:
            count += 1
        if self.is_suspicious_port:
            count += 1
        if self.is_high_volume:
            count += 1
        if self.is_unknown_protocol:
            count += 1
        return count

    def to_dict(self) -> dict[str, Any]:
        """Serialisation JSON.

        Returns:
            Dictionnaire des facteurs
        """
        return {
            "is_external_ip": self.is_external_ip,
            "is_suspicious_port": self.is_suspicious_port,
            "suspicious_port_value": self.suspicious_port_value,
            "is_high_volume": self.is_high_volume,
            "volume_packets": self.volume_packets,
            "is_unknown_protocol": self.is_unknown_protocol,
            "protocol": self.protocol,
        }


@dataclass
class ScoreBreakdown:
    """Decomposition du score calcule.

    Attributes:
        blacklist_score: Score de base blacklist (0-100)
        heuristic_score: Bonus heuristique (0-40)
        total_score: Score final (0-100, cappe)
        factors: Facteurs heuristiques analyses
        criticality: Niveau de criticite determine
    """

    blacklist_score: int = 0
    heuristic_score: int = 0
    total_score: int = 0
    factors: HeuristicFactors = field(default_factory=HeuristicFactors)
    criticality: CriticalityLevel = CriticalityLevel.NORMAL

    def to_dict(self) -> dict[str, Any]:
        """Serialisation JSON.

        Returns:
            Dictionnaire du breakdown
        """
        return {
            "blacklist_score": self.blacklist_score,
            "heuristic_score": self.heuristic_score,
            "total_score": self.total_score,
            "factors": self.factors.to_dict(),
            "criticality": self.criticality.value,
        }
