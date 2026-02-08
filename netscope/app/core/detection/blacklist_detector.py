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
        matched_domains: set[str] = set()
        for anomaly in domain_anomalies:
            collection.add(anomaly)
            matched_domains.add(anomaly.match.matched_value.lower())

        # Detect Terms (substring match in payload + DNS/HTTP) - AC3
        term_anomalies = self._detect_terms(packets, capture_id, matched_domains)
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

        Checks DNS queries and HTTP Host headers against domain blacklist.
        Story 2.2 AC2: Exact match detection for blacklisted domains.

        Args:
            packets: List of packets to analyze
            capture_id: Capture session ID

        Returns:
            List of Anomaly objects for domain matches
        """
        anomalies: list[Anomaly] = []
        checked_domains: set[str] = set()

        for packet in packets:
            # Check DNS queries
            for domain in packet.dns_queries:
                domain_lower = domain.lower()
                if domain_lower in checked_domains:
                    continue
                checked_domains.add(domain_lower)

                if self._manager.check_domain(domain_lower):
                    match = BlacklistMatch(
                        match_type=MatchType.DOMAIN,
                        matched_value=domain,
                        source_file="domains_blacklist",
                        context=self._build_domain_context(domain, packet, "DNS query"),
                        criticality=CriticalityLevel.CRITICAL,
                        timestamp=packet.timestamp,
                    )

                    breakdown = self._scoring.calculate_score(
                        match=match,
                        packet_info=packet,
                        context=None,
                    )

                    human_ctx = self._human_context.get_domain_context(
                        domain=domain,
                        source_file=match.source_file,
                        category=None,
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
                        f"Blacklisted domain detected (domain={domain}, "
                        f"score={breakdown.total_score}, "
                        f"criticality={breakdown.criticality.value})"
                    )

            # Check HTTP Host header
            if packet.http_host:
                host_lower = packet.http_host.lower()
                if host_lower not in checked_domains:
                    checked_domains.add(host_lower)

                    if self._manager.check_domain(host_lower):
                        match = BlacklistMatch(
                            match_type=MatchType.DOMAIN,
                            matched_value=packet.http_host,
                            source_file="domains_blacklist",
                            context=self._build_domain_context(packet.http_host, packet, "HTTP Host"),
                            criticality=CriticalityLevel.CRITICAL,
                            timestamp=packet.timestamp,
                        )

                        breakdown = self._scoring.calculate_score(
                            match=match,
                            packet_info=packet,
                            context=None,
                        )

                        human_ctx = self._human_context.get_domain_context(
                            domain=packet.http_host,
                            source_file=match.source_file,
                            category=None,
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
                            f"Blacklisted domain detected (domain={packet.http_host}, "
                            f"score={breakdown.total_score}, via=HTTP Host)"
                        )

        return anomalies

    def _build_domain_context(self, domain: str, packet: PacketInfo, source: str) -> str:
        """Build human-readable context for a domain match.

        Args:
            domain: The matched domain
            packet: The packet containing the match
            source: How the domain was detected (DNS query, HTTP Host)

        Returns:
            Context string describing the match
        """
        return (
            f"Domain {domain} ({source}) - "
            f"{packet.ip_src} -> {packet.ip_dst} ({packet.protocol})"
        )

    def _detect_terms(
        self,
        packets: list[PacketInfo],
        capture_id: str | None,
        matched_domains: set[str] | None = None,
    ) -> list[Anomaly]:
        """Detect suspicious terms in packet payloads, DNS queries and HTTP Host.

        Story 2.2 AC3: Substring match detection for suspicious terms.
        Terms are detected with WARNING criticality level.
        Skips domains already matched by _detect_domains (higher criticality).

        Args:
            packets: List of packets to analyze
            capture_id: Capture session ID
            matched_domains: Domains already detected (to avoid duplicates)

        Returns:
            List of Anomaly objects for term matches
        """
        anomalies: list[Anomaly] = []
        matched_domains = matched_domains or set()
        # Track (term, source_text) to avoid duplicates
        detected_term_sources: set[tuple[str, str]] = set()

        for packet in packets:
            # Build list of (text_to_check, source_label) pairs
            texts_to_check: list[tuple[str, str]] = []

            if packet.payload_preview:
                texts_to_check.append((packet.payload_preview, "payload"))

            for domain in packet.dns_queries:
                if domain.lower() not in matched_domains:
                    texts_to_check.append((domain, "DNS query"))

            if packet.http_host:
                if packet.http_host.lower() not in matched_domains:
                    texts_to_check.append((packet.http_host, "HTTP Host"))

            for text, source_label in texts_to_check:
                found_terms = self._manager.check_term(text)

                for term in found_terms:
                    term_lower = term.lower()
                    dedup_key = (term_lower, text.lower())
                    if dedup_key in detected_term_sources:
                        continue
                    detected_term_sources.add(dedup_key)

                    # Build context snippet around the term
                    context_snippet = self._build_term_context_snippet(term, text)

                    match = BlacklistMatch(
                        match_type=MatchType.TERM,
                        matched_value=term,
                        source_file="terms_blacklist",
                        context=self._build_term_context_with_source(
                            term, packet, context_snippet, source_label
                        ),
                        criticality=CriticalityLevel.WARNING,
                        timestamp=packet.timestamp,
                    )

                    breakdown = self._scoring.calculate_score(
                        match=match,
                        packet_info=packet,
                        context=None,
                    )

                    human_ctx = self._human_context.get_term_context(
                        term=term,
                        context_snippet=context_snippet,
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
                        f"Suspicious term detected (term={term}, "
                        f"source={source_label}, "
                        f"score={breakdown.total_score}, "
                        f"criticality={breakdown.criticality.value})"
                    )

        return anomalies

    def _build_term_context_snippet(self, term: str, payload: str) -> str:
        """Extract context snippet around a matched term.

        Args:
            term: The matched term
            payload: Full payload string

        Returns:
            Snippet of ~50 chars around the term
        """
        try:
            idx = payload.lower().find(term.lower())
            if idx == -1:
                return payload[:50]

            start = max(0, idx - 20)
            end = min(len(payload), idx + len(term) + 20)
            snippet = payload[start:end]

            if start > 0:
                snippet = "..." + snippet
            if end < len(payload):
                snippet = snippet + "..."

            return snippet
        except Exception:
            return payload[:50] if payload else ""

    def _build_term_context(self, term: str, packet: PacketInfo, snippet: str) -> str:
        """Build human-readable context for a term match.

        Args:
            term: The matched term
            packet: The packet containing the match
            snippet: Context snippet around the term

        Returns:
            Context string describing the match
        """
        return (
            f"Term '{term}' in payload - "
            f"{packet.ip_src} -> {packet.ip_dst} ({packet.protocol}) - "
            f"Context: {snippet}"
        )

    def _build_term_context_with_source(
        self, term: str, packet: PacketInfo, snippet: str, source: str
    ) -> str:
        """Build human-readable context for a term match with source info.

        Args:
            term: The matched term
            packet: The packet containing the match
            snippet: Context snippet around the term
            source: Where the term was found (payload, DNS query, HTTP Host)

        Returns:
            Context string describing the match
        """
        return (
            f"Term '{term}' in {source} - "
            f"{packet.ip_src} -> {packet.ip_dst} ({packet.protocol}) - "
            f"Context: {snippet}"
        )

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
