"""Blacklist-based anomaly detector for NETSCOPE.

Detects IPs, domains, and suspicious terms in captured network packets
using the centralized BlacklistManager and ScoringEngine.

Lessons Learned Epic 1/2:
- Use Python 3.10+ type hints (X | None, not Optional[X])
- Use module-level logger, NOT current_app.logger
- Integrate immediately with capture flow
- Use ScoringEngine for dynamic scoring (Story 2.3)

Story 2.5: Added HumanContextProvider integration for accessible explanations (FR14, NFR27)
"""

from __future__ import annotations

import logging

from app.models.capture import PacketInfo
from app.models.anomaly import (
    Anomaly,
    AnomalyCollection,
    BlacklistMatch,
    CriticalityLevel,
    MatchType,
)
from app.core.detection.blacklist_manager import get_blacklist_manager
from app.core.analysis.scoring import get_scoring_engine
from app.core.detection.human_context import get_human_context_provider

# CRITICAL: Logger module-level (Lesson Learned Epic 1 - A4)
logger = logging.getLogger(__name__)


class BlacklistDetector:
    """Detector for blacklisted IPs, domains, and suspicious terms.

    Uses BlacklistManager singleton to perform lookups against loaded
    blacklists and ScoringEngine for dynamic score calculation.
    Produces Anomaly objects for each match found.

    Usage:
        detector = BlacklistDetector()
        collection = detector.detect_all(packets, capture_id="cap_123")
    """

    def __init__(self) -> None:
        """Initialize the detector with BlacklistManager, ScoringEngine, and HumanContextProvider."""
        self._manager = get_blacklist_manager()
        self._scoring = get_scoring_engine()
        self._human_context = get_human_context_provider()
        logger.debug("BlacklistDetector initialized (with ScoringEngine and HumanContextProvider)")

    def detect_all(
        self,
        packets: list[PacketInfo],
        capture_id: str | None = None,
    ) -> AnomalyCollection:
        """Detect all blacklist matches in a list of packets.

        Performs IP, domain, and term detection on all packets.
        Returns an AnomalyCollection with all detected anomalies.

        Args:
            packets: List of PacketInfo objects to analyze
            capture_id: Optional capture session ID for tracking

        Returns:
            AnomalyCollection with all detected anomalies
        """
        logger.info(f"Detection started (packets={len(packets)})")

        collection = AnomalyCollection(capture_id=capture_id)

        if not packets:
            logger.info("Detection complete (matches=0, no packets)")
            return collection

        # Detect IPs (exact match) - AC1
        ip_anomalies = self._detect_ips(packets, capture_id)
        for anomaly in ip_anomalies:
            collection.add(anomaly)

        # Detect Domains (exact match lowercase) - AC2
        domain_anomalies = self._detect_domains(packets, capture_id)
        for anomaly in domain_anomalies:
            collection.add(anomaly)

        # Detect Terms (substring match) - AC3
        term_anomalies = self._detect_terms(packets, capture_id)
        for anomaly in term_anomalies:
            collection.add(anomaly)

        logger.info(f"Detection complete (matches={collection.total})")
        return collection

    def _detect_ips(
        self,
        packets: list[PacketInfo],
        capture_id: str | None,
    ) -> list[Anomaly]:
        """Detect blacklisted IPs in packets.

        Checks both source and destination IPs against the blacklist.
        Uses set to avoid checking the same IP multiple times.
        Uses ScoringEngine for dynamic score calculation (Story 2.3).

        Args:
            packets: List of packets to analyze
            capture_id: Capture session ID

        Returns:
            List of Anomaly objects for IP matches
        """
        anomalies: list[Anomaly] = []
        checked_ips: set[str] = set()

        for packet in packets:
            for ip in [packet.ip_src, packet.ip_dst]:
                if not ip or ip in checked_ips:
                    continue

                checked_ips.add(ip)

                if self._manager.check_ip(ip):
                    # Create match
                    # NOTE: MVP limitation - source_file is generic because BlacklistManager
                    # doesn't track which file each IP came from. Full source tracking
                    # would require refactoring BlacklistManager (future enhancement).
                    match = BlacklistMatch(
                        match_type=MatchType.IP,
                        matched_value=ip,
                        source_file="ips_blacklist",  # Generic source for MVP
                        context=self._build_ip_context(ip, packet),
                        criticality=CriticalityLevel.CRITICAL,
                        timestamp=packet.timestamp,
                    )

                    # Use ScoringEngine for dynamic score calculation (Story 2.3)
                    breakdown = self._scoring.calculate_score(
                        match=match,
                        packet_info=packet,
                        context=None,  # Volume context not available at packet level
                    )

                    # Story 2.5: Generate human-readable context (AC2, FR14, NFR27)
                    human_ctx = self._human_context.get_ip_context(
                        ip=ip,
                        source_file=match.source_file,
                        category=None,  # Auto-infer from source_file
                    )

                    anomaly = Anomaly(
                        id=Anomaly.generate_id(),
                        match=match,
                        score=breakdown.total_score,
                        packet_info=packet.to_dict(),
                        criticality_level=breakdown.criticality,
                        capture_id=capture_id,
                        score_breakdown=breakdown,
                        human_context=human_ctx,
                    )

                    anomalies.append(anomaly)
                    logger.warning(
                        f"Blacklisted IP detected (ip={ip}, "
                        f"score={breakdown.total_score}, "
                        f"criticality={breakdown.criticality.value})"
                    )

        return anomalies

    def _detect_domains(
        self,
        packets: list[PacketInfo],
        capture_id: str | None,
    ) -> list[Anomaly]:
        """Detect blacklisted domains in packets.

        Note: In MVP without deep packet inspection, domain detection
        is limited. DNS queries or HTTP headers would need to be parsed
        from packet payload. This will be enhanced in Story 2.4.

        Args:
            packets: List of packets to analyze
            capture_id: Capture session ID

        Returns:
            List of Anomaly objects for domain matches (empty for MVP)

        IMPORTANT (Code Review M3): When implementing, use self._scoring.calculate_score()
        with MatchType.DOMAIN to get dynamic scoring. See _detect_ips() for example.
        """
        # MVP: No deep packet inspection available
        # Domain detection requires DNS query parsing or HTTP header analysis
        # This will be implemented in Story 2.4 (4 analyses essentielles)
        # TODO: Use self._scoring.calculate_score(match, packet_info) when implemented
        return []

    def _detect_terms(
        self,
        packets: list[PacketInfo],
        capture_id: str | None,
    ) -> list[Anomaly]:
        """Detect suspicious terms in packets.

        Note: In MVP with headers-only capture (100 bytes), payload
        inspection is limited. Term detection in actual payload
        will be enhanced in Story 2.4.

        Args:
            packets: List of packets to analyze
            capture_id: Capture session ID

        Returns:
            List of Anomaly objects for term matches (empty for MVP)

        IMPORTANT (Code Review M3): When implementing, use self._scoring.calculate_score()
        with MatchType.TERM to get dynamic scoring. Term base score is 65 (AC1: 60-79 WARNING).
        See _detect_ips() for example implementation pattern.
        """
        # MVP: Limited payload available (100 bytes headers-only)
        # Term detection in full payload requires Scapy inspection (Epic 4)
        # TODO: Use self._scoring.calculate_score(match, packet_info) when implemented
        return []

    def _build_ip_context(self, ip: str, packet: PacketInfo) -> str:
        """Build human-readable context for an IP match.

        Args:
            ip: The matched IP address
            packet: The packet containing the match

        Returns:
            Context string describing the match location
        """
        direction = "source" if ip == packet.ip_src else "destination"
        port_info = ""

        if direction == "source" and packet.port_src:
            port_info = f":{packet.port_src}"
        elif direction == "destination" and packet.port_dst:
            port_info = f":{packet.port_dst}"

        return (
            f"IP {ip}{port_info} ({direction}) - "
            f"{packet.ip_src} -> {packet.ip_dst} ({packet.protocol})"
        )


# Global detector instance (not singleton - new instance per analysis)
def create_detector() -> BlacklistDetector:
    """Create a new BlacklistDetector instance.

    Returns:
        New BlacklistDetector instance
    """
    return BlacklistDetector()
