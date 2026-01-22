"""Scoring cascade multi-criteres pour anomalies NETSCOPE.

Implemente un systeme de scoring en deux priorites:
1. Blacklists: Score de base selon type de match
2. Heuristiques: Bonus contextuels additionnels

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Use config YAML for thresholds, NOT hardcoded values

Code Review Fix H2: Models moved to app/models/scoring.py for architecture compliance.
"""

from __future__ import annotations

import logging
from typing import Any

from app.models.anomaly import CriticalityLevel, MatchType, BlacklistMatch
from app.models.capture import PacketInfo
from app.models.scoring import ScoreBreakdown, HeuristicFactors

logger = logging.getLogger(__name__)


class ScoringEngine:
    """Moteur de scoring cascade multi-criteres.

    Calcule un score 0-100 pour chaque anomalie en deux etapes:
    1. Score de base blacklist (selon type: IP, domain, term)
    2. Bonus heuristiques (IP externe, port suspect, volume)

    Usage:
        engine = ScoringEngine()
        breakdown = engine.calculate_score(match, packet_info, context)
    """

    # Ports suspects connus (constantes)
    SUSPICIOUS_PORTS: set[int] = {
        4444,   # Metasploit/Meterpreter default
        8080,   # HTTP alt/proxy
        1337,   # L33t / backdoor
        6666,   # IRC / backdoor
        6667,   # IRC
        31337,  # Elite backdoor
        12345,  # NetBus
        27374,  # SubSeven
        5555,   # Android ADB
        4443,   # HTTPS alt
        8443,   # HTTPS alt
        3389,   # RDP (si externe)
        5900,   # VNC
        5901,   # VNC
    }

    # Plages IP privees RFC1918
    PRIVATE_IP_PREFIXES: tuple[str, ...] = (
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "127.",     # Loopback
        "169.254.", # Link-local
    )

    # Protocoles standards connus
    KNOWN_PROTOCOLS: set[str] = {"TCP", "UDP", "ICMP", "ARP", "DNS"}

    # Default configuration values (can be overridden via load_config)
    # These defaults match architecture.md Appendix A: Configuration Schema
    DEFAULT_THRESHOLDS = {"critical": 80, "warning": 50}
    DEFAULT_BLACKLIST_BASE = {"ip": 85, "domain": 80, "term": 65}
    DEFAULT_HEURISTIC_BONUS = {
        "external_ip": 10,
        "suspicious_port": 15,
        "high_volume": 10,
        "unknown_protocol": 5,
    }
    DEFAULT_COMBINATION_MULTIPLIER = 1.2
    DEFAULT_VOLUME_THRESHOLD = 100

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """Initialise le moteur de scoring.

        Args:
            config: Optional configuration dict. If None, uses defaults.
                    Can be loaded from netscope.yaml via load_config().

        Configuration keys (matching architecture.md):
            thresholds: {"critical": 80, "warning": 50}
            blacklist_base: {"ip": 85, "domain": 80, "term": 65}
            heuristic_bonus: {"external_ip": 10, "suspicious_port": 15, ...}
            combination_multiplier: 1.2
            volume_threshold: 100
        """
        # Initialize with defaults
        self._thresholds = self.DEFAULT_THRESHOLDS.copy()
        self._blacklist_base = self.DEFAULT_BLACKLIST_BASE.copy()
        self._heuristic_bonus = self.DEFAULT_HEURISTIC_BONUS.copy()
        self._combination_multiplier = self.DEFAULT_COMBINATION_MULTIPLIER
        self._volume_threshold = self.DEFAULT_VOLUME_THRESHOLD

        # Apply config if provided
        if config:
            self._apply_config(config)

        logger.debug("ScoringEngine initialized")

    def _apply_config(self, config: dict[str, Any]) -> None:
        """Apply configuration overrides.

        Args:
            config: Configuration dictionary with optional keys.

        Note:
            Future enhancement: Load from netscope.yaml via app config.
            For now, config can be passed directly to __init__ or via load_config().
        """
        if "thresholds" in config:
            self._thresholds.update(config["thresholds"])
        if "blacklist_base" in config:
            self._blacklist_base.update(config["blacklist_base"])
        if "heuristic_bonus" in config:
            self._heuristic_bonus.update(config["heuristic_bonus"])
        if "combination_multiplier" in config:
            self._combination_multiplier = config["combination_multiplier"]
        if "volume_threshold" in config:
            self._volume_threshold = config["volume_threshold"]

        logger.debug(f"ScoringEngine config applied (thresholds={self._thresholds})")

    def calculate_score(
        self,
        match: BlacklistMatch,
        packet_info: PacketInfo | dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ScoreBreakdown:
        """Calcule le score d'une anomalie.

        Args:
            match: Le match blacklist detecte
            packet_info: Informations du paquet associe
            context: Contexte additionnel (volume, etc.)

        Returns:
            ScoreBreakdown avec score total et details
        """
        breakdown = ScoreBreakdown()

        # Etape 1: Score de base blacklist
        breakdown.blacklist_score = self._score_blacklist_match(match.match_type)

        # Etape 2: Bonus heuristiques
        if packet_info:
            breakdown.factors = self._analyze_heuristics(packet_info, context)
            breakdown.heuristic_score = self._score_heuristics(breakdown.factors)

        # Etape 3: Combiner scores
        breakdown.total_score = self._combine_scores(
            breakdown.blacklist_score,
            breakdown.heuristic_score,
            breakdown.factors.count_positive(),
        )

        # Etape 4: Determiner criticite
        breakdown.criticality = self._calculate_criticality(breakdown.total_score)

        logger.debug(
            f"Score calculated (blacklist={breakdown.blacklist_score}, "
            f"heuristic={breakdown.heuristic_score}, "
            f"total={breakdown.total_score}, "
            f"criticality={breakdown.criticality.value})"
        )

        return breakdown

    def _score_blacklist_match(self, match_type: MatchType) -> int:
        """Score de base selon type de match blacklist.

        Args:
            match_type: Type de match (IP, DOMAIN, TERM)

        Returns:
            Score de base (0-100)
        """
        if match_type == MatchType.IP:
            return self._blacklist_base["ip"]
        elif match_type == MatchType.DOMAIN:
            return self._blacklist_base["domain"]
        elif match_type == MatchType.TERM:
            return self._blacklist_base["term"]
        return 0

    def _analyze_heuristics(
        self,
        packet_info: PacketInfo | dict[str, Any],
        context: dict[str, Any] | None,
    ) -> HeuristicFactors:
        """Analyse les facteurs heuristiques d'un paquet.

        Args:
            packet_info: Informations du paquet (PacketInfo ou dict)
            context: Contexte additionnel (volume, etc.)

        Returns:
            HeuristicFactors avec tous les facteurs analyses
        """
        factors = HeuristicFactors()

        # Convertir PacketInfo en dict si necessaire
        if hasattr(packet_info, "to_dict"):
            info = packet_info.to_dict()
        else:
            info = packet_info

        # Analyser IP externe
        ip_dst = info.get("ip_dst", "")
        ip_src = info.get("ip_src", "")
        factors.is_external_ip = (
            self._is_external_ip(ip_dst) or
            self._is_external_ip(ip_src)
        )

        # Analyser ports suspects
        port_dst = info.get("port_dst")
        port_src = info.get("port_src")
        if port_dst and self._is_suspicious_port(port_dst):
            factors.is_suspicious_port = True
            factors.suspicious_port_value = port_dst
        elif port_src and self._is_suspicious_port(port_src):
            factors.is_suspicious_port = True
            factors.suspicious_port_value = port_src

        # Analyser protocole
        protocol = info.get("protocol", "").upper()
        factors.protocol = protocol
        factors.is_unknown_protocol = protocol not in self.KNOWN_PROTOCOLS and protocol != ""

        # Analyser volume si contexte disponible
        if context:
            factors.volume_packets = context.get("packet_count", 0)
            factors.is_high_volume = factors.volume_packets > self._volume_threshold

        return factors

    def _score_heuristics(self, factors: HeuristicFactors) -> int:
        """Calcule le bonus heuristique total.

        Args:
            factors: Facteurs heuristiques analyses

        Returns:
            Bonus total (0-40)
        """
        bonus = 0

        if factors.is_external_ip:
            bonus += self._heuristic_bonus["external_ip"]

        if factors.is_suspicious_port:
            bonus += self._heuristic_bonus["suspicious_port"]

        if factors.is_high_volume:
            bonus += self._heuristic_bonus["high_volume"]

        if factors.is_unknown_protocol:
            bonus += self._heuristic_bonus["unknown_protocol"]

        return bonus

    def _combine_scores(
        self,
        blacklist_score: int,
        heuristic_score: int,
        factor_count: int,
    ) -> int:
        """Combine les scores avec multiplicateur si multiples facteurs.

        Args:
            blacklist_score: Score de base blacklist
            heuristic_score: Bonus heuristique
            factor_count: Nombre de facteurs actifs

        Returns:
            Score total (0-100, cappe)
        """
        total = blacklist_score + heuristic_score

        # Appliquer multiplicateur si 2+ facteurs heuristiques
        if factor_count >= 2:
            total = int(total * self._combination_multiplier)

        # Cap a 100
        return min(total, 100)

    def _calculate_criticality(self, score: int) -> CriticalityLevel:
        """Determine le niveau de criticite selon le score.

        Args:
            score: Score total (0-100)

        Returns:
            CriticalityLevel correspondant
        """
        if score >= self._thresholds["critical"]:
            return CriticalityLevel.CRITICAL
        elif score >= self._thresholds["warning"]:
            return CriticalityLevel.WARNING
        return CriticalityLevel.NORMAL

    def _is_external_ip(self, ip: str) -> bool:
        """Verifie si une IP est externe (hors RFC1918).

        Args:
            ip: Adresse IP a verifier

        Returns:
            True si IP externe, False sinon
        """
        if not ip:
            return False
        return not any(ip.startswith(prefix) for prefix in self.PRIVATE_IP_PREFIXES)

    def _is_suspicious_port(self, port: int | None) -> bool:
        """Verifie si un port est dans la liste suspecte.

        Args:
            port: Numero de port a verifier

        Returns:
            True si port suspect, False sinon
        """
        if not port:
            return False
        return port in self.SUSPICIOUS_PORTS


# Singleton instance
_scoring_engine: ScoringEngine | None = None


def get_scoring_engine() -> ScoringEngine:
    """Retourne l'instance singleton du moteur de scoring.

    Returns:
        Instance ScoringEngine
    """
    global _scoring_engine
    if _scoring_engine is None:
        _scoring_engine = ScoringEngine()
    return _scoring_engine


def reset_scoring_engine() -> None:
    """Reset le singleton (utile pour les tests).

    Reinitialise l'instance globale a None.
    """
    global _scoring_engine
    _scoring_engine = None
